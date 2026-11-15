// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package app

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.happydns.org/happyDeliver/internal/api"
	"git.happydns.org/happyDeliver/internal/checker"
	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/lmtp"
	"git.happydns.org/happyDeliver/internal/storage"
	"git.happydns.org/happyDeliver/pkg/analyzer"
	"git.happydns.org/happyDeliver/web"
)

// RunServer starts the API server and LMTP server
func RunServer(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.Use(securityHeaders)
	var trustedProxies []string
	for _, proxy := range strings.Split(cfg.TrustedProxies, ",") {
		if proxy = strings.TrimSpace(proxy); proxy != "" {
			trustedProxies = append(trustedProxies, proxy)
		}
	}
	if err := router.SetTrustedProxies(trustedProxies); err != nil {
		return err
	}
	if err := configureAdmin(cfg, router, trustedProxies); err != nil {
		return err
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.Type, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer store.Close()

	log.Printf("Connected to %s database", cfg.Database.Type)

	// Start cleanup service for old reports
	ctx := context.Background()
	cleanupSvc := NewCleanupService(store, func() time.Duration { return cfg.Effective().ReportRetention })
	cleanupSvc.Start(ctx)
	defer cleanupSvc.Stop()

	// Start LMTP server in background
	go func() {
		if err := lmtp.StartServer(cfg.Email.LMTPAddr, store, cfg); err != nil {
			log.Fatalf("Failed to start LMTP server: %v", err)
		}
	}()

	// Create analyzer adapter for API
	analyzerAdapter := analyzer.NewAPIAdapter(cfg)

	// Create API handler
	handler := api.NewAPIHandler(store, cfg, analyzerAdapter)

	apiGroup := router.Group("/api")
	apiGroup.Use(publicRateLimit(func() uint { return cfg.Effective().RateLimit }))

	// Network checks for /tools/ get a stricter per-IP limit.
	checker.Register(apiGroup.Group("/tools", toolsRateLimit()))

	// Register API routes
	api.RegisterHandlers(apiGroup, handler)
	web.DeclareRoutes(cfg, router)

	// Start API server
	log.Printf("Starting API server on %s", cfg.Bind)
	log.Printf("Test email domain: %s", cfg.Email.Domain)

	if err := router.Run(cfg.Bind); err != nil {
		return err
	}

	return nil
}
