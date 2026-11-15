package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Settings are the values operators may safely change without restarting the listeners.
// MaxReportRetention is the longest time reports and raw emails are kept.
const MaxReportRetention = 10 * 24 * time.Hour

type Settings struct {
	RateLimit       uint          `json:"rate_limit"`
	RBLs            []string      `json:"rbls"`
	LogoURL         string        `json:"logo_url"`
	ReportRetention time.Duration `json:"report_retention"`
	DNSTimeout      time.Duration `json:"dns_timeout"`
	HTTPTimeout     time.Duration `json:"http_timeout"`
	CheckAllIPs     bool          `json:"check_all_ips"`
}

type SettingsStore struct {
	mu      sync.RWMutex
	path    string
	current Settings
}

func OpenSettings(path string, defaults *Config) (*SettingsStore, error) {
	s := &SettingsStore{path: path, current: Settings{
		RateLimit: defaults.RateLimit, RBLs: slices.Clone(defaults.Analysis.RBLs),
		LogoURL: defaults.CustomLogoURL, ReportRetention: defaults.ReportRetention,
		DNSTimeout: defaults.Analysis.DNSTimeout, HTTPTimeout: defaults.Analysis.HTTPTimeout,
		CheckAllIPs: defaults.Analysis.CheckAllIPs,
	}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.current); err != nil {
		return nil, fmt.Errorf("read admin settings: %w", err)
	}
	if err := s.current.Validate(); err != nil {
		return nil, fmt.Errorf("invalid saved admin settings: %w", err)
	}
	return s, nil
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func (s Settings) Validate() error {
	switch {
	case s.RateLimit > 1000:
		return fmt.Errorf("das API-Limit muss zwischen 0 und 1000 liegen")
	case s.ReportRetention <= 0 || s.ReportRetention > MaxReportRetention:
		return fmt.Errorf("die Aufbewahrungsdauer muss größer als 0 und höchstens 240h (10 Tage) sein")
	case s.DNSTimeout < time.Second || s.DNSTimeout > 30*time.Second:
		return fmt.Errorf("der DNS-Timeout muss zwischen 1s und 30s liegen")
	case s.HTTPTimeout < time.Second || s.HTTPTimeout > 60*time.Second:
		return fmt.Errorf("der HTTP-Timeout muss zwischen 1s und 60s liegen")
	case len(s.RBLs) > 20:
		return fmt.Errorf("es sind höchstens 20 DNS-Sperrlisten möglich")
	}

	for _, zone := range s.RBLs {
		labels := strings.Split(zone, ".")
		if len(zone) > 253 || len(labels) < 2 || net.ParseIP(zone) != nil {
			return fmt.Errorf("ungültige DNS-Sperrliste %q", zone)
		}
		for _, label := range labels {
			if !dnsLabel.MatchString(label) {
				return fmt.Errorf("ungültige DNS-Sperrliste %q", zone)
			}
		}
	}

	if s.LogoURL != "" {
		u, err := url.Parse(s.LogoURL)
		if err != nil || len(s.LogoURL) > 2048 || strings.ContainsAny(s.LogoURL, "\\ \r\n\t") ||
			!((u.Scheme == "https" && u.Hostname() != "" && u.User == nil) ||
				(u.Scheme == "" && u.Host == "" && strings.HasPrefix(s.LogoURL, "/img/"))) {
			return fmt.Errorf("das Logo braucht eine HTTPS-URL oder einen lokalen Pfad unter /img/")
		}
	}
	return nil
}

func (s *SettingsStore) Current() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value := s.current
	value.RBLs = slices.Clone(value.RBLs)
	return value
}

// Save publishes a new snapshot only after the settings file has been written.
func (s *SettingsStore) Save(value Settings, confirmRetention bool) error {
	if err := value.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value.ReportRetention > 0 &&
		(s.current.ReportRetention == 0 || value.ReportRetention < s.current.ReportRetention) &&
		!confirmRetention {
		return fmt.Errorf("bitte bestätige, dass ältere Berichte gelöscht werden dürfen")
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(value); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	value.RBLs = slices.Clone(value.RBLs)
	s.current = value
	return nil
}

// Effective supplies a consistent snapshot for a public request or an analysis.
func (c *Config) Effective() *Config {
	if c.Settings == nil {
		return c
	}
	s := c.Settings.Current()
	out := *c
	out.RateLimit = s.RateLimit
	out.CustomLogoURL = s.LogoURL
	out.ReportRetention = s.ReportRetention
	out.Analysis = AnalysisConfig{DNSTimeout: s.DNSTimeout, HTTPTimeout: s.HTTPTimeout,
		RBLs: s.RBLs, CheckAllIPs: s.CheckAllIPs}
	return &out
}
