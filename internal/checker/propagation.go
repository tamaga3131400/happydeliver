package checker

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

type publicResolver struct {
	name string
	addr netip.Addr
}

var publicResolvers = []publicResolver{
	{"Google", netip.MustParseAddr("8.8.8.8")},
	{"Cloudflare", netip.MustParseAddr("1.1.1.1")},
	{"Quad9", netip.MustParseAddr("9.9.9.9")},
	{"OpenDNS", netip.MustParseAddr("208.67.222.222")},
	{"AdGuard", netip.MustParseAddr("94.140.14.14")},
	{"Control D", netip.MustParseAddr("76.76.2.0")},
}

var recordTypes = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "MX": dnsmessage.TypeMX,
	"TXT": dnsmessage.TypeTXT, "NS": dnsmessage.TypeNS, "CNAME": dnsmessage.TypeCNAME,
}

type propagationAnswer struct {
	label  Text
	values []string
	err    string
	auth   bool
}

// authoritativeServers returns up to three public addresses of the domain's name servers.
func authoritativeServers(ctx context.Context, domain string) []publicResolver {
	zone := domain
	for strings.Count(zone, ".") >= 1 {
		ns, _ := resolver.LookupNS(ctx, zone)
		if len(ns) > 0 {
			var out []publicResolver
			for _, n := range ns {
				host := strings.TrimSuffix(n.Host, ".")
				addrs, _ := lookupIPs(ctx, host)
				for _, a := range addrs {
					if a.Is4() && isPublic(a) {
						out = append(out, publicResolver{host, a})
						break
					}
				}
				if len(out) == 3 {
					break
				}
			}
			return out
		}
		_, zone, _ = strings.Cut(zone, ".")
	}
	return nil
}

func propagation(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}
	typeName := strings.ToUpper(q.Get("type"))
	if typeName == "" {
		typeName = "A"
	}
	qtype, ok := recordTypes[typeName]
	if !ok {
		return nil, fail("Unsupported record type.", "Nicht unterstützter Eintragstyp.")
	}

	targets := slices.Clone(publicResolvers)
	auth := authoritativeServers(ctx, domain)
	answers := make([]propagationAnswer, len(targets)+len(auth))
	var wg sync.WaitGroup
	query := func(i int, r publicResolver, isAuth bool) {
		defer wg.Done()
		label := T(fmt.Sprintf("%s (%s)", r.name, r.addr), fmt.Sprintf("%s (%s)", r.name, r.addr))
		if isAuth {
			label = T(r.name+" (authoritative)", r.name+" (autoritativ)")
		}
		reply, took, err := ask(ctx, dnsAsk{server: r.addr, name: domain, qtype: qtype, recursive: !isAuth})
		a := propagationAnswer{label: label, auth: isAuth}
		switch {
		case err != nil:
			a.err = err.Error()
		case reply.RCode == dnsmessage.RCodeNameError:
			a.err = "NXDOMAIN"
		case reply.RCode != dnsmessage.RCodeSuccess:
			a.err = reply.RCode.String()
		default:
			a.values = recordText(reply, qtype)
			slices.Sort(a.values)
			ms := fmt.Sprintf(" · %d ms", took.Milliseconds())
			a.label = T(a.label[0]+ms, a.label[1]+ms)
		}
		answers[i] = a
	}
	for i, r := range targets {
		wg.Add(1)
		go query(i, r, false)
	}
	for i, r := range auth {
		wg.Add(1)
		go query(len(targets)+i, r, true)
	}
	wg.Wait()

	// Reference: the authoritative answer, otherwise the most common one.
	counts := map[string]int{}
	reference := ""
	for _, a := range answers {
		if a.err != "" {
			continue
		}
		key := strings.Join(a.values, "\n")
		if a.auth && reference == "" {
			reference = key
		}
		counts[key]++
	}
	if reference == "" {
		best := 0
		for key, n := range counts {
			if n > best {
				best, reference = n, key
			}
		}
	}

	section := Section{Title: T(typeName+" records for "+domain, typeName+"-Einträge für "+domain)}
	same := 0
	for _, a := range answers {
		r := Row{Label: a.label}
		switch {
		case a.err != "":
			r.Value, r.Status = a.err, "bad"
		case len(a.values) == 0:
			r.Note, r.Status = &Text{"no record", "kein Eintrag"}, statusFor(reference == "")
		default:
			r.Value, r.Status = strings.Join(a.values, "\n"), statusFor(strings.Join(a.values, "\n") == reference)
		}
		if r.Status == "ok" {
			same++
		}
		section.Rows = append(section.Rows, r)
	}
	summary := Section{Title: T("Summary", "Zusammenfassung")}
	total := len(answers)
	if same == total {
		summary.Rows = append(summary.Rows, noteRow("Status", "Status", fmt.Sprintf("all %d servers give the same answer", total),
			fmt.Sprintf("alle %d Server liefern dieselbe Antwort", total), "ok"))
	} else {
		summary.Rows = append(summary.Rows, noteRow("Status", "Status",
			fmt.Sprintf("%d of %d servers differ – a change may still be propagating (TTL)", total-same, total),
			fmt.Sprintf("%d von %d Servern weichen ab – eine Änderung ist evtl. noch nicht überall angekommen (TTL)", total-same, total), "warn"))
	}
	return &Result{Sections: []Section{summary, section}}, nil
}

func statusFor(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}
