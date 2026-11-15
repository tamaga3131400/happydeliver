package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Subdomains are taken from public Certificate Transparency logs: every
// publicly trusted certificate lists the names it is valid for.

// ctClient allows more time: crt.sh is slow for domains with many certificates.
var ctClient = func() *http.Client {
	c := httpClient([]string{"443"}, 3)
	c.Timeout = 18 * time.Second
	c.Transport.(*http.Transport).ResponseHeaderTimeout = 16 * time.Second
	return c
}()

func crtsh(ctx context.Context, domain string) ([]string, bool) {
	resp, err := get(ctx, ctClient, "https://crt.sh/?q="+url.QueryEscape("%."+domain)+"&output=json&exclude=expired", "application/json")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&entries) != nil {
		return nil, false
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.Split(e.NameValue, "\n")...)
	}
	return names, true
}

func ctNames(ctx context.Context, domain string) ([]string, string, error) {
	// crt.sh is often briefly overloaded, so it gets a second try.
	for attempt := 0; attempt < 2; attempt++ {
		if names, ok := crtsh(ctx, domain); ok {
			return names, "crt.sh", nil
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(time.Second):
		}
	}

	resp, err := get(ctx, ctClient, "https://api.certspotter.com/v1/issuances?domain="+url.QueryEscape(domain)+"&include_subdomains=true&expand=dns_names", "application/json")
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fail("The certificate log services are busy right now. Please try again in a minute.",
			"Die Zertifikats-Suchdienste sind gerade ausgelastet. Bitte versuche es in einer Minute erneut.")
	}
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&issuances); err != nil {
		return nil, "", err
	}
	var names []string
	for _, i := range issuances {
		names = append(names, i.DNSNames...)
	}
	return names, "Cert Spotter", nil
}

func subdomainSearch(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}
	raw, source, err := ctNames(ctx, domain)
	if err != nil {
		return nil, err
	}
	wildcards := 0
	var names []string
	for _, n := range raw {
		n = strings.ToLower(strings.TrimSpace(n))
		if strings.HasPrefix(n, "*.") {
			wildcards++
			n = n[2:]
		}
		if n == domain || strings.HasSuffix(n, "."+domain) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	total := len(names)
	shown := names
	if len(shown) > 500 {
		shown = shown[:500]
	}
	summary := Section{Title: T("Summary", "Zusammenfassung"), Rows: []Row{
		row("Names found", "Gefundene Namen", fmt.Sprint(total)),
		row("Wildcard certificates", "Wildcard-Zertifikate", fmt.Sprint(wildcards)),
		row("Source", "Quelle", source+" (Certificate Transparency)"),
	}}
	if total > len(shown) {
		summary.Rows = append(summary.Rows, noteRow("Shown", "Angezeigt", "first 500", "die ersten 500"))
	}
	list := Section{Title: T("Names from certificates", "Namen aus Zertifikaten")}
	if len(shown) == 0 {
		list.Rows = []Row{noteRow("Result", "Ergebnis", "no names in current certificates", "keine Namen in aktuellen Zertifikaten")}
	} else {
		list.Rows = []Row{row("Names", "Namen", strings.Join(shown, "\n"))}
	}
	note := Section{Title: T("Note", "Hinweis"), Rows: []Row{noteRow("Scope", "Umfang",
		"Only names that appear in public certificates are found; internal names without certificates stay hidden.",
		"Gefunden werden nur Namen aus öffentlichen Zertifikaten; interne Namen ohne Zertifikat bleiben verborgen.")}}
	return &Result{Sections: []Section{summary, list, note}}, nil
}
