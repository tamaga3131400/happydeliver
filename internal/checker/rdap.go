package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// RDAP is the structured successor of WHOIS. The responsible server is
// taken from the IANA bootstrap registry.

type bootstrap struct {
	Services [][][]string `json:"services"`
}

var (
	bootstrapMu    sync.Mutex
	bootstrapCache = map[string]*bootstrap{}
	bootstrapTime  = map[string]time.Time{}
)

var rdapClient = httpClient([]string{"443"}, 3)

func loadBootstrap(ctx context.Context, kind string) (*bootstrap, error) {
	bootstrapMu.Lock()
	defer bootstrapMu.Unlock()
	if b, ok := bootstrapCache[kind]; ok && time.Since(bootstrapTime[kind]) < 24*time.Hour {
		return b, nil
	}
	resp, err := get(ctx, rdapClient, "https://data.iana.org/rdap/"+kind+".json", "application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var b bootstrap
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&b); err != nil {
		return nil, err
	}
	bootstrapCache[kind], bootstrapTime[kind] = &b, time.Now()
	return &b, nil
}

func rdapBase(b *bootstrap, match func(key string) int) string {
	best, base := 0, ""
	for _, service := range b.Services {
		if len(service) < 2 {
			continue
		}
		for _, key := range service[0] {
			if score := match(key); score > best {
				for _, u := range service[1] {
					if strings.HasPrefix(u, "https://") {
						best, base = score, u
						break
					}
				}
			}
		}
	}
	return base
}

type rdapEntity struct {
	Roles      []string `json:"roles"`
	Handle     string   `json:"handle"`
	VcardArray []any    `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

type rdapObject struct {
	LdhName      string   `json:"ldhName"`
	Handle       string   `json:"handle"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Country      string   `json:"country"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	Status       []string `json:"status"`
	Events       []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	Entities []rdapEntity `json:"entities"`
}

func vcard(e rdapEntity, field string) string {
	if len(e.VcardArray) < 2 {
		return ""
	}
	props, _ := e.VcardArray[1].([]any)
	for _, p := range props {
		prop, _ := p.([]any)
		if len(prop) >= 4 && prop[0] == field {
			if s, ok := prop[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

func findEntity(entities []rdapEntity, role string) *rdapEntity {
	for i := range entities {
		if slices.Contains(entities[i].Roles, role) {
			return &entities[i]
		}
		if found := findEntity(entities[i].Entities, role); found != nil {
			return found
		}
	}
	return nil
}

func eventRows(obj *rdapObject, rows []Row) []Row {
	labels := map[string]Text{
		"registration": T("Registered", "Registriert"),
		"expiration":   T("Expires", "Läuft ab"),
		"last changed": T("Last changed", "Zuletzt geändert"),
	}
	for _, action := range []string{"registration", "expiration", "last changed"} {
		for _, e := range obj.Events {
			if e.Action != action {
				continue
			}
			t, err := time.Parse(time.RFC3339, e.Date)
			if err != nil {
				continue
			}
			r := Row{Label: labels[action], Value: date(t)}
			if action == "expiration" {
				switch d := days(t); {
				case d < 0:
					r.Status = "bad"
				case d < 30:
					r.Status = "warn"
				default:
					r.Status = "ok"
				}
			}
			rows = append(rows, r)
			break
		}
	}
	return rows
}

func whoisLookup(ctx context.Context, q url.Values) (*Result, error) {
	input := strings.TrimSpace(q.Get("q"))
	var target string
	isIP := false
	if addr, err := netip.ParseAddr(input); err == nil {
		if !isPublic(addr) {
			return nil, fail("Only public IP addresses can be checked.", "Es können nur öffentliche IP-Adressen geprüft werden.")
		}
		kind := "ipv4"
		if addr.Unmap().Is6() {
			kind = "ipv6"
		}
		b, err := loadBootstrap(ctx, kind)
		if err != nil {
			return nil, err
		}
		base := rdapBase(b, func(key string) int {
			if p, err := netip.ParsePrefix(key); err == nil && p.Contains(addr.Unmap()) {
				return p.Bits() + 1
			}
			return 0
		})
		if base == "" {
			return nil, fail("No RDAP server is known for this address.", "Für diese Adresse ist kein RDAP-Server bekannt.")
		}
		target, isIP = strings.TrimSuffix(base, "/")+"/ip/"+addr.Unmap().String(), true
	} else {
		domain, err := normalizeDomain(input)
		if err != nil {
			return nil, err
		}
		registration, ok := registrationDomain(domain)
		if !ok {
			return nil, fail("Enter a registrable domain such as example.com.", "Gib eine registrierbare Domain wie example.com ein.")
		}
		domain = registration
		b, err := loadBootstrap(ctx, "dns")
		if err != nil {
			return nil, err
		}
		base := rdapBase(b, func(key string) int {
			if domain == key || strings.HasSuffix(domain, "."+key) {
				return strings.Count(key, ".") + 1
			}
			return 0
		})
		if base == "" {
			return whoisFallback(ctx, domain)
		}
		target = strings.TrimSuffix(base, "/") + "/domain/" + domain
	}

	resp, err := get(ctx, rdapClient, target, "application/rdap+json, application/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fail("No registration found for the requested domain or network.", "Für die angefragte Domain oder das Netzwerk wurde keine Registrierung gefunden.")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("RDAP server answered %s", resp.Status)
	}
	var obj rdapObject
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid RDAP answer: %w", err)
	}

	section := Section{Title: T("Registration", "Registrierung")}
	if isIP {
		section.Rows = append(section.Rows,
			row("Network name", "Netzname", obj.Name),
			row("Range", "Bereich", strings.TrimSpace(obj.StartAddress+" – "+obj.EndAddress)),
			row("Handle", "Kennung", obj.Handle),
			row("Type", "Art", obj.Type),
			row("Country", "Land", obj.Country))
		if e := findEntity(obj.Entities, "registrant"); e != nil {
			section.Rows = append(section.Rows, row("Organisation", "Organisation", vcard(*e, "fn")))
		}
	} else {
		section.Rows = append(section.Rows, row("Domain", "Domain", strings.ToLower(obj.LdhName)))
		if e := findEntity(obj.Entities, "registrar"); e != nil {
			name := vcard(*e, "fn")
			for _, id := range e.PublicIDs {
				if strings.Contains(strings.ToLower(id.Type), "iana") {
					name += " (IANA " + id.Identifier + ")"
				}
			}
			section.Rows = append(section.Rows, row("Registrar", "Registrar", name))
		}
		if e := findEntity(obj.Entities, "registrant"); e != nil {
			if org := vcard(*e, "org"); org != "" {
				section.Rows = append(section.Rows, row("Registrant", "Inhaber", org))
			} else if fn := vcard(*e, "fn"); fn != "" {
				section.Rows = append(section.Rows, row("Registrant", "Inhaber", fn))
			}
		}
	}
	section.Rows = eventRows(&obj, section.Rows)
	if len(obj.Status) > 0 {
		section.Rows = append(section.Rows, row("Status", "Status", strings.Join(obj.Status, ", ")))
	}
	if !isIP {
		var ns []string
		for _, n := range obj.Nameservers {
			ns = append(ns, strings.ToLower(n.LdhName))
		}
		section.Rows = append(section.Rows, row("Name servers", "Nameserver", strings.Join(ns, ", ")))
		if obj.SecureDNS != nil {
			if obj.SecureDNS.DelegationSigned {
				section.Rows = append(section.Rows, noteRow("DNSSEC", "DNSSEC", "signed", "signiert", "ok"))
			} else {
				section.Rows = append(section.Rows, noteRow("DNSSEC", "DNSSEC", "not signed", "nicht signiert"))
			}
		}
	}
	if e := findEntity(obj.Entities, "abuse"); e != nil {
		section.Rows = append(section.Rows, row("Abuse contact", "Missbrauchskontakt", vcard(*e, "email")))
	}

	// Drop empty rows (many registries redact personal data).
	section.Rows = slices.DeleteFunc(section.Rows, func(r Row) bool { return r.Value == "" && r.Note == nil })
	source := Section{Title: T("Source", "Quelle"), Rows: []Row{row("RDAP", "RDAP", target)}}
	return &Result{Sections: []Section{section, source}}, nil
}

// RDAP registries know the registered name, not hosts under that name.
// Ignore private suffix rules (for example github.io hosts): those names
// are administered below the actual registered domain.
func registrationDomain(domain string) (string, bool) {
	icannSuffix := domain
	for strings.Contains(icannSuffix, ".") {
		suffix, icann := publicsuffix.PublicSuffix(icannSuffix)
		if icann {
			icannSuffix = suffix
			break
		}
		_, icannSuffix, _ = strings.Cut(suffix, ".")
	}
	prefix, ok := strings.CutSuffix(domain, "."+icannSuffix)
	if !ok || prefix == "" {
		return "", false
	}
	label := prefix[strings.LastIndex(prefix, ".")+1:]
	return label + "." + icannSuffix, true
}
