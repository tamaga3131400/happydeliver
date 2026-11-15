package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"git.happydns.org/happyDeliver/internal/config"
)

func TestAdminSettings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const origin = "http://127.0.0.1:4179"
	const password = "isolated-test-only-password-39"
	folder := t.TempDir()
	passwordFile := filepath.Join(folder, "password")
	settingsFile := filepath.Join(folder, "settings.json")
	if err := os.WriteFile(passwordFile, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Admin = config.AdminConfig{PasswordFile: passwordFile, SettingsFile: settingsFile, Origin: origin}
	router := gin.New()
	if err := configureAdmin(cfg, router, nil); err != nil {
		t.Fatal(err)
	}

	request := func(method, host, requestOrigin, credential string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, host+"/admin", strings.NewReader(form.Encode()))
		req.RemoteAddr = "127.0.0.1:5000"
		if credential != "" {
			req.SetBasicAuth("admin", credential)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", requestOrigin)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res
	}
	expect := func(res *httptest.ResponseRecorder, status int) {
		t.Helper()
		if res.Code != status {
			t.Fatalf("got %d, want %d", res.Code, status)
		}
	}

	expect(request("GET", origin, "", "", nil), http.StatusUnauthorized)
	expect(request("GET", origin, "", "wrong-password", nil), http.StatusUnauthorized)
	expect(request("GET", "http://wrong.example", "", password, nil), http.StatusForbidden)
	page := request("GET", origin, "", password, nil)
	expect(page, http.StatusOK)
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("admin page can be cached")
	}
	token := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(token) != 2 {
		t.Fatal("no form token")
	}
	form := url.Values{
		"rate": {"9"}, "retention": {"120h"}, "dns_timeout": {"4s"}, "http_timeout": {"9s"},
		"logo": {"/img/zenmail-plane.svg"}, "rbls": {"ZEN.SPAMHAUS.ORG.\nzen.spamhaus.org"},
	}
	expect(request("POST", origin, origin, password, form), http.StatusForbidden)
	form.Set("csrf", token[1])
	expect(request("POST", origin, "https://elsewhere.example", password, form), http.StatusForbidden)
	expect(request("POST", origin, origin, password, form), http.StatusBadRequest)
	form.Set("confirm_retention", "on")
	form.Set("logo", "javascript:alert(1)")
	expect(request("POST", origin, origin, password, form), http.StatusBadRequest)
	if cfg.Effective().RateLimit != 1 {
		t.Fatal("invalid form changed live settings")
	}
	form.Set("logo", "/img/zenmail-plane.svg")
	for _, retention := range []string{"0", "241h"} {
		form.Set("retention", retention)
		expect(request("POST", origin, origin, password, form), http.StatusBadRequest)
	}
	form.Set("retention", "120h")
	expect(request("POST", origin, origin, password, form), http.StatusSeeOther)
	effective := cfg.Effective()
	if effective.RateLimit != 9 || effective.ReportRetention != 120*time.Hour ||
		len(effective.Analysis.RBLs) != 1 || effective.Analysis.RBLs[0] != "zen.spamhaus.org" {
		t.Fatalf("incorrect saved state: %+v", effective)
	}
	reopened, err := config.OpenSettings(settingsFile, config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current().LogoURL != "/img/zenmail-plane.svg" || reopened.Current().RateLimit != 9 {
		t.Fatal("state did not survive reopening")
	}
	form.Set("rbls", "")
	expect(request("POST", origin, origin, password, form), http.StatusSeeOther)
	if len(cfg.Effective().Analysis.RBLs) != 0 {
		t.Fatal("explicit empty blacklist list not saved")
	}
}

func TestAdminDisabled(t *testing.T) {
	router := gin.New()
	if err := configureAdmin(config.DefaultConfig(), router, nil); err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	router.ServeHTTP(res, httptest.NewRequest("GET", "/admin", nil))
	if res.Code != http.StatusNotFound || res.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("disabled admin route is accessible")
	}
}

func TestPublicRateLimitReadsNewLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	var limit uint = 1
	router.GET("/status", publicRateLimit(func() uint { return limit }), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	codes := []int{200, 200, 429}
	request := func() int {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/status", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		router.ServeHTTP(resp, req)
		return resp.Code
	}
	for _, want := range codes {
		if got := request(); got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	}
	limit = 3
	if got := request(); got != 200 {
		t.Fatalf("new limit did not apply: %d", got)
	}
}
