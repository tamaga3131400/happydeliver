package web

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"

	"git.happydns.org/happyDeliver/internal/config"
)

var (
	inlineScript      = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	indexScriptHashes []string
)

// scriptHashes returns CSP hashes for the inline scripts of a page, so that
// exactly these scripts may run without allowing inline scripts in general.
func scriptHashes(page string) []string {
	var hashes []string
	for _, m := range inlineScript.FindAllStringSubmatch(page, -1) {
		sum := sha256.Sum256([]byte(m[1]))
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return hashes
}

// indexCSP is the Content-Security-Policy for the web interface.
func indexCSP(cfg *config.Config) string {
	connect := "'self'"
	if cfg.SurveyURL.Host != "" {
		connect += " " + cfg.SurveyURL.Scheme + "://" + cfg.SurveyURL.Host
	}
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' " + strings.Join(indexScriptHashes, " "),
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"font-src 'self' data:",
		"connect-src " + connect,
		"frame-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}
