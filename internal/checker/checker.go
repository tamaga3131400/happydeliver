// Package checker implements the network checks offered under /tools/.
// Every outgoing connection is restricted to public addresses and a small
// set of ports, so the checks cannot be used to reach internal services.
package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
)

// Text holds an English and a German string.
type Text [2]string

func T(en, de string) Text { return Text{en, de} }

type Row struct {
	Label  Text   `json:"label"`
	Value  string `json:"value,omitempty"`
	Note   *Text  `json:"note,omitempty"`   // localized value, shown when there is no plain value
	Status string `json:"status,omitempty"` // ok, warn, bad
}

type Section struct {
	Title Text  `json:"title"`
	Rows  []Row `json:"rows"`
}

type Result struct {
	Sections []Section `json:"sections"`
}

type userError struct{ msg Text }

func (e *userError) Error() string { return e.msg[0] }

func fail(en, de string) error { return &userError{T(en, de)} }

var errBlocked = errors.New("target address is not public or port is not allowed")

type check func(ctx context.Context, q url.Values) (*Result, error)

var checks = map[string]check{
	"dns-lookup":      dnsLookup,
	"ssl-lookup":      sslLookup,
	"ip-lookup":       ipLookup,
	"whois-lookup":    whoisLookup,
	"http-headers":    httpHeaders,
	"redirect-check":  redirectCheck,
	"meta-tags":       metaTags,
	"dns-propagation": propagation,
	"dnssec":          dnssecCheck,
	"mail-ports":      mailPortCheck,
	"email-check":     emailCheck,
	"subdomains":      subdomainSearch,
	"uptime":          uptimeCheck,
	"ip-location":     geoLookup,
	"mac-lookup":      macLookup,
}

var running = make(chan struct{}, 8)

// Register adds the check endpoints to the given router group.
func Register(group *gin.RouterGroup) {
	group.GET("/:tool", handle)
}

func handle(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	run, ok := checks[c.Param("tool")]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"message": T("Unknown check.", "Unbekannte Prüfung.")})
		return
	}
	select {
	case running <- struct{}{}:
		defer func() { <-running }()
	default:
		c.Header("Retry-After", "5")
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": T(
			"Too many checks are running. Please try again in a few seconds.",
			"Gerade laufen zu viele Prüfungen. Bitte versuche es in ein paar Sekunden erneut.")})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	result, err := run(ctx, c.Request.URL.Query())
	if err != nil {
		var ue *userError
		switch {
		case errors.As(err, &ue):
			c.JSON(http.StatusBadRequest, gin.H{"message": ue.msg})
		case errors.Is(err, errBlocked):
			c.JSON(http.StatusBadRequest, gin.H{"message": T(
				"The target resolves to a non-public address or uses a port that is not allowed.",
				"Das Ziel zeigt auf eine nicht öffentliche Adresse oder nutzt einen nicht erlaubten Port.")})
		case errors.Is(err, context.DeadlineExceeded):
			c.JSON(http.StatusGatewayTimeout, gin.H{"message": T("The check timed out.", "Die Prüfung hat zu lange gedauert.")})
		default:
			c.JSON(http.StatusBadGateway, gin.H{"message": T("The check failed: "+err.Error(), "Die Prüfung ist fehlgeschlagen: "+err.Error())})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

// Address and name validation

var specialPrefixes = func() []netip.Prefix {
	var list []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fec0::/10",
	} {
		list = append(list, netip.MustParsePrefix(p))
	}
	return list
}()

// isPublic reports whether the address is a globally routable unicast address.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() {
		return false
	}
	return !slices.ContainsFunc(specialPrefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// idnaProfile converts international names but, unlike idna.Lookup, allows
// underscores so that names such as _dmarc.example.com can be checked.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))

var blockedSuffixes = []string{
	"localhost", "local", "internal", "intranet", "lan", "home", "corp", "private",
	"home.arpa", "test", "invalid", "example", "onion", "arpa",
}

// normalizeDomain accepts a domain or URL and returns the ASCII domain name.
func normalizeDomain(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err == nil {
			value = u.Hostname()
		}
	}
	value = strings.TrimSuffix(strings.ToLower(strings.SplitN(value, "/", 2)[0]), ".")
	if value == "" {
		return "", fail("Please enter a domain.", "Bitte gib eine Domain ein.")
	}
	ascii, err := idnaProfile.ToASCII(value)
	if err != nil || len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return "", fail("Please enter a valid public domain such as example.com.", "Bitte gib eine gültige öffentliche Domain wie example.com ein.")
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") ||
			strings.ContainsFunc(label, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_')
			}) {
			return "", fail("Please enter a valid public domain such as example.com.", "Bitte gib eine gültige öffentliche Domain wie example.com ein.")
		}
	}
	tld := labels[len(labels)-1]
	if _, err := strconv.Atoi(tld); err == nil {
		return "", fail("Please enter a domain, not an IP address.", "Bitte gib eine Domain ein, keine IP-Adresse.")
	}
	for _, suffix := range blockedSuffixes {
		if ascii == suffix || strings.HasSuffix(ascii, "."+suffix) {
			return "", fail("Only public domains can be checked.", "Es können nur öffentliche Domains geprüft werden.")
		}
	}
	return ascii, nil
}

// normalizeURL accepts a URL or bare host and returns a validated http(s) URL.
func normalizeURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fail("Please enter a URL.", "Bitte gib eine URL ein.")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, fail("Please enter a valid http or https URL.", "Bitte gib eine gültige http- oder https-URL ein.")
	}
	if port := u.Port(); port != "" && !slices.Contains(webPorts, port) {
		return nil, fail("Only the ports 80, 443, 8080 and 8443 are allowed.", "Erlaubt sind nur die Ports 80, 443, 8080 und 8443.")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if !isPublic(addr) {
			return nil, errBlocked
		}
	} else {
		domain, err := normalizeDomain(host)
		if err != nil {
			return nil, err
		}
		if u.Port() != "" {
			u.Host = net.JoinHostPort(domain, u.Port())
		} else {
			u.Host = domain
		}
	}
	u.Fragment = ""
	return u, nil
}

// Safe connections

var webPorts = []string{"80", "443", "8080", "8443"}

// dialer returns a dialer that only connects to public addresses on the given ports.
// The check runs after DNS resolution, so rebinding to internal addresses is blocked too.
func dialer(ports []string) *net.Dialer {
	return &net.Dialer{
		Timeout: 8 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !isPublic(ap.Addr()) || !slices.Contains(ports, strconv.Itoa(int(ap.Port()))) {
				return errBlocked
			}
			return nil
		},
	}
}

const userAgent = "DeliverZenmail-Checker/1.0 (+https://deliver.zenmail.eu/tools/)"

func httpClient(ports []string, followHTTPS int) *http.Client {
	d := dialer(ports)
	return &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialContext(d),
			ForceAttemptHTTP2:      true,
			TLSHandshakeTimeout:    6 * time.Second,
			ResponseHeaderTimeout:  8 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > followHTTPS || req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func get(ctx context.Context, client *http.Client, target string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil && errors.Is(err, errBlocked) {
		return nil, errBlocked
	}
	return resp, err
}

var resolver = &net.Resolver{PreferGo: true}

func row(en, de, value string, status ...string) Row {
	r := Row{Label: T(en, de), Value: value}
	if len(status) > 0 {
		r.Status = status[0]
	}
	return r
}

// noteRow is a row whose value is a localized text.
func noteRow(en, de, noteEn, noteDe string, status ...string) Row {
	r := row(en, de, "", status...)
	r.Note = &Text{noteEn, noteDe}
	return r
}

func days(t time.Time) int {
	return int(time.Until(t).Hours() / 24)
}

func date(t time.Time) string {
	return fmt.Sprintf("%s (%s)", t.UTC().Format("2006-01-02"), relative(t))
}

func relative(t time.Time) string {
	d := days(t)
	switch {
	case d > 0:
		return fmt.Sprintf("in %d d", d)
	case d < 0:
		return fmt.Sprintf("%d d ago", -d)
	default:
		return "today"
	}
}
