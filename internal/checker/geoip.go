package checker

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

type geoRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

func name(names map[string]string, lang string) string {
	if v := names[lang]; v != "" {
		return v
	}
	return names["en"]
}

// publicAddresses accepts an IP address or a domain and returns up to four public addresses.
func publicAddresses(ctx context.Context, input string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(strings.TrimSpace(input)); err == nil {
		if !isPublic(addr) {
			return nil, fail("Only public IP addresses can be checked.", "Es können nur öffentliche IP-Adressen geprüft werden.")
		}
		return []netip.Addr{addr.Unmap()}, nil
	}
	domain, err := normalizeDomain(input)
	if err != nil {
		return nil, fail("Please enter an IP address or domain.", "Bitte gib eine IP-Adresse oder Domain ein.")
	}
	ips, err := lookupIPs(ctx, domain)
	if err != nil {
		return nil, fail("The domain has no A or AAAA record.", "Die Domain hat keinen A- oder AAAA-Eintrag.")
	}
	var out []netip.Addr
	for _, ip := range ips {
		if ip = ip.Unmap(); isPublic(ip) && !slices.Contains(out, ip) && len(out) < 4 {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fail("The domain has no public address.", "Die Domain hat keine öffentliche Adresse.")
	}
	return out, nil
}

func geoLookup(ctx context.Context, q url.Values) (*Result, error) {
	db := geoDB.Load()
	if db == nil {
		return nil, fail("The location database is being loaded. Please try again in a few minutes.",
			"Die Standortdatenbank wird gerade geladen. Bitte versuche es in ein paar Minuten erneut.")
	}
	addrs, err := publicAddresses(ctx, q.Get("q"))
	if err != nil {
		return nil, err
	}
	result := &Result{}
	for _, addr := range addrs {
		var rec geoRecord
		section := Section{Title: T(addr.String(), addr.String())}
		if err := db.Lookup(addr).Decode(&rec); err != nil || rec.Country.ISOCode == "" {
			section.Rows = []Row{noteRow("Location", "Standort", "unknown", "unbekannt")}
			result.Sections = append(result.Sections, section)
			continue
		}
		pair := func(en, de string, names map[string]string) {
			if v := name(names, "en"); v != "" {
				section.Rows = append(section.Rows, Row{Label: T(en, de), Note: &Text{v, name(names, "de")}})
			}
		}
		pair("Country", "Land", rec.Country.Names)
		section.Rows[len(section.Rows)-1].Value = rec.Country.ISOCode
		if len(rec.Subdivisions) > 0 {
			pair("Region", "Region", rec.Subdivisions[0].Names)
		}
		pair("City", "Stadt", rec.City.Names)
		pair("Continent", "Kontinent", rec.Continent.Names)
		if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
			section.Rows = append(section.Rows, row("Coordinates (approx.)", "Koordinaten (ungefähr)",
				fmt.Sprintf("%.4f, %.4f", rec.Location.Latitude, rec.Location.Longitude)))
		}
		result.Sections = append(result.Sections, section)
	}
	result.Sections = append(result.Sections, Section{Title: T("Source", "Quelle"), Rows: []Row{
		row("Database", "Datenbank", "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0"),
		noteRow("Accuracy", "Genauigkeit", "Country is reliable; city is often only the provider's location.",
			"Das Land stimmt meist; die Stadt ist oft nur der Standort des Providers."),
	}})
	return result, nil
}
