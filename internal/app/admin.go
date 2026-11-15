package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/pkg/analyzer"
)

//go:embed admin.html
var adminHTML string

var adminPage = template.Must(template.New("admin").Parse(adminHTML))

type admin struct {
	host                     string
	proxies                  []netip.Prefix
	username, password, csrf [sha256.Size]byte
	csrfToken                string
	origin                   string
	allowLocalHTTP           bool
	settings                 *config.SettingsStore
	failures                 requestWindow
}

func configureAdmin(cfg *config.Config, router *gin.Engine, proxyAddresses []string) error {
	settingsPath := cfg.Admin.SettingsFile
	if settingsPath != "" {
		defaults := *cfg
		if len(defaults.Analysis.RBLs) == 0 {
			defaults.Analysis.RBLs = analyzer.DefaultRBLs
		}
		settings, err := config.OpenSettings(settingsPath, &defaults)
		if err != nil {
			return err
		}
		cfg.Settings = settings
	}

	passwordFile := cfg.Admin.PasswordFile
	if passwordFile == "" {
		router.Any("/admin", func(c *gin.Context) { c.Status(http.StatusNotFound) })
		router.Any("/admin/*path", func(c *gin.Context) { c.Status(http.StatusNotFound) })
		return nil
	}
	if cfg.Settings == nil {
		return errors.New("admin requires HAPPYDELIVER_ADMIN_SETTINGS_FILE on persistent storage")
	}

	origin := cfg.Admin.Origin
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || u.User != nil || origin != u.Scheme+"://"+u.Host {
		return errors.New("invalid HAPPYDELIVER_ADMIN_ORIGIN (use scheme and host only)")
	}
	local := u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if u.Scheme != "https" && !local {
		return errors.New("HAPPYDELIVER_ADMIN_ORIGIN must use HTTPS outside loopback")
	}
	raw, err := os.ReadFile(passwordFile)
	if err != nil {
		return fmt.Errorf("read admin password: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if len(password) < 24 || strings.ContainsAny(password, "\r\n") {
		return errors.New("admin password must be at least 24 bytes on one line")
	}
	username := cfg.Admin.User
	if username == "" {
		username = "admin"
	}
	if strings.ContainsAny(username, ":\r\n") {
		return errors.New("invalid admin username")
	}

	proxies := make([]netip.Prefix, 0, len(proxyAddresses))
	for _, address := range proxyAddresses {
		if ip, err := netip.ParseAddr(address); err == nil {
			proxies = append(proxies, netip.PrefixFrom(ip, ip.BitLen()))
		} else if prefix, err := netip.ParsePrefix(address); err == nil {
			proxies = append(proxies, prefix)
		}
	}

	token := rand.Text()
	h := &admin{
		host: u.Host, proxies: proxies,
		username: sha256.Sum256([]byte(username)), password: sha256.Sum256([]byte(password)),
		csrf: sha256.Sum256([]byte(token)), csrfToken: token, origin: origin,
		allowLocalHTTP: local, settings: cfg.Settings,
	}
	cfg.AdminEnabled = true
	router.GET("/admin", h.authorize, h.show)
	router.POST("/admin", h.authorize, h.save)
	return nil
}

func matches(value string, expected [sha256.Size]byte) int {
	digest := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(digest[:], expected[:])
}

func (a *admin) authorize(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")

	remote, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
	peer, _ := netip.ParseAddr(remote)
	secure := c.Request.TLS != nil
	if !secure && c.Request.Header.Get("X-Forwarded-Proto") == "https" {
		secure = slices.ContainsFunc(a.proxies, func(prefix netip.Prefix) bool {
			return prefix.Contains(peer.Unmap())
		})
	}
	if !strings.EqualFold(c.Request.Host, a.host) ||
		(!secure && !(a.allowLocalHTTP && peer.IsLoopback())) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	user, password, ok := c.Request.BasicAuth()
	if ok && (matches(user, a.username)&matches(password, a.password)) == 1 {
		return
	}
	if !a.failures.allow(c.ClientIP(), time.Minute, 12) {
		c.Header("Retry-After", "60")
		c.AbortWithStatus(http.StatusTooManyRequests)
		return
	}
	c.Header("WWW-Authenticate", `Basic realm="Deliver Zenmail Admin", charset="UTF-8"`)
	c.AbortWithStatus(http.StatusUnauthorized)
}

func (a *admin) render(c *gin.Context, status int, value config.Settings, message string, saved bool) {
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")
	err := adminPage.Execute(c.Writer, struct {
		config.Settings
		Zones, Token, Error string
		Saved               bool
	}{value, strings.Join(value.RBLs, "\n"), a.csrfToken, message, saved})
	if err != nil {
		_ = c.Error(err)
	}
}

func (a *admin) show(c *gin.Context) {
	a.render(c, http.StatusOK, a.settings.Current(), "", c.Query("saved") == "1")
}

func (a *admin) save(c *gin.Context) {
	if c.Request.Header.Get("Origin") != a.origin {
		c.Status(http.StatusForbidden)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	if err := c.Request.ParseForm(); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	form := c.Request.PostForm
	if matches(form.Get("csrf"), a.csrf) != 1 {
		c.Status(http.StatusForbidden)
		return
	}
	limit, limitErr := strconv.ParseUint(form.Get("rate"), 10, 16)
	retention, retentionErr := time.ParseDuration(form.Get("retention"))
	dns, dnsErr := time.ParseDuration(form.Get("dns_timeout"))
	httpTimeout, httpErr := time.ParseDuration(form.Get("http_timeout"))
	if limitErr != nil || retentionErr != nil || dnsErr != nil || httpErr != nil {
		a.render(c, http.StatusBadRequest, a.settings.Current(), "Bitte gib ein ganzzahliges Limit und Zeitangaben wie 5s oder 240h ein.", false)
		return
	}
	value := config.Settings{
		RateLimit: uint(limit), LogoURL: strings.TrimSpace(form.Get("logo")), RBLs: []string{},
		ReportRetention: retention, DNSTimeout: dns, HTTPTimeout: httpTimeout, CheckAllIPs: form.Has("all_ips"),
	}
	for _, raw := range strings.FieldsFunc(form.Get("rbls"), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		zone := strings.TrimSuffix(strings.ToLower(raw), ".")
		if !slices.Contains(value.RBLs, zone) {
			value.RBLs = append(value.RBLs, zone)
		}
	}
	if err := a.settings.Save(value, form.Has("confirm_retention")); err != nil {
		var fileError *os.PathError
		if errors.As(err, &fileError) {
			_ = c.Error(err)
			a.render(c, http.StatusInternalServerError, value, "Speichern fehlgeschlagen. Prüfe die Schreibrechte des Datenverzeichnisses.", false)
		} else {
			a.render(c, http.StatusBadRequest, value, err.Error(), false)
		}
		return
	}
	c.Redirect(http.StatusSeeOther, "/admin?saved=1")
}
