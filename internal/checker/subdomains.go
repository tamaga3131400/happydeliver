package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Subdomains are taken from public Certificate Transparency logs: every
// publicly trusted certificate lists the names it is valid for.

var ctClient = httpClient([]string{"443"}, 3)

type ctProvider struct {
	name   string
	lookup func(context.Context, string) ([]string, error)
}

func crtsh(ctx context.Context, domain string) ([]string, error) {
	resp, err := get(ctx, ctClient, "https://crt.sh/?q="+url.QueryEscape("%."+domain)+"&output=json&exclude=expired", "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh: HTTP %d", resp.StatusCode)
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&entries); err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, strings.Split(e.NameValue, "\n")...)
	}
	return names, nil
}

func ctNames(ctx context.Context, domain string, providers []ctProvider) ([]string, string, error) {
	// Give each provider its own deadline, leaving time for the second one
	// even if the first is completely unavailable.
	for _, provider := range providers {
		attempt, cancel := context.WithTimeout(ctx, 7*time.Second)
		names, err := provider.lookup(attempt, domain)
		cancel()
		if err == nil {
			return names, provider.name, nil
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
	return nil, "", &checkUnavailable{T(
		"The certificate log services are unavailable. Please try again shortly.",
		"Die Zertifikats-Suchdienste sind gerade nicht erreichbar. Bitte versuche es gleich erneut.")}
}

var certificateProviders = []ctProvider{
	{name: "Cert Spotter", lookup: certSpotter},
	{name: "crt.sh", lookup: crtsh},
}

func certSpotter(ctx context.Context, domain string) ([]string, error) {
	resp, err := get(ctx, ctClient, "https://api.certspotter.com/v1/issuances?domain="+url.QueryEscape(domain)+"&include_subdomains=true&expand=dns_names", "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Cert Spotter: HTTP %d", resp.StatusCode)
	}
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&issuances); err != nil {
		return nil, err
	}
	var names []string
	for _, i := range issuances {
		names = append(names, i.DNSNames...)
	}
	return names, nil
}

func subdomainSearch(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}
	raw, source, err := ctNames(ctx, domain, certificateProviders)
	if err != nil {
		return nil, err
	}
	wildcardNames := map[string]bool{}
	var names []string
	for _, n := range raw {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		wildcard := strings.HasPrefix(n, "*.")
		name := strings.TrimPrefix(n, "*.")
		if name != domain && !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if wildcard {
			wildcardNames[n] = true
		}
		names = append(names, n)
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
		row("Wildcard certificates", "Wildcard-Zertifikate", fmt.Sprint(len(wildcardNames))),
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
	sections := []Section{summary, list}
	if q.Get("mode") == "CT + DNS" && len(shown) > 0 {
		sections = append(sections, verifyCertificateNames(ctx, shown))
	}
	note := Section{Title: T("Note", "Hinweis"), Rows: []Row{noteRow("Scope", "Umfang",
		"Search covers public certificates for the entered name and its descendants. Use the parent domain for sibling names. Wildcards are certificate patterns.",
		"Die Suche zeigt öffentliche Zertifikate für den eingegebenen Namen und darunter. Gib für benachbarte Namen die übergeordnete Domain ein. Wildcards sind Zertifikatsmuster.")}}
	return &Result{Sections: append(sections, note)}, nil
}

func verifyCertificateNames(ctx context.Context, names []string) Section {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	section := Section{Title: T("DNS sample", "DNS-Stichprobe"), Rows: []Row{
		noteRow("Scope", "Umfang", "Checks up to the first 12 concrete names for public A/AAAA addresses.",
			"Prüft bis zu zwölf konkrete Namen auf öffentliche A- oder AAAA-Adressen."),
	}}
	var concrete []string
	for _, name := range names {
		if !strings.HasPrefix(name, "*.") {
			host, err := normalizeDomain(name)
			if err == nil && host == name {
				concrete = append(concrete, name)
			}
		}
		if len(concrete) == 12 {
			break
		}
	}
	rows := make([]Row, len(concrete))
	var wg sync.WaitGroup
	for i, name := range concrete {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var dnsErr *dnsUnavailable
			ips, err := lookupIPs(ctx, name)
			switch {
			case errors.As(err, &dnsErr):
				rows[i] = dnsMissing(name, name)
			case slices.ContainsFunc(ips, isPublic):
				rows[i] = noteRow(name, name, "public address found", "öffentliche Adresse gefunden", "ok")
			default:
				rows[i] = noteRow(name, name, "no public A/AAAA address", "keine öffentliche A- oder AAAA-Adresse")
			}
		}()
	}
	wg.Wait()
	section.Rows = append(section.Rows, rows...)
	return section
}
