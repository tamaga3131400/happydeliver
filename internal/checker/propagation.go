package checker

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

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
	nx     bool
}

// authoritativeServers returns up to three public addresses of the domain's name servers.
func authoritativeServers(ctx context.Context, domain string) []publicResolver {
	zone, err := dnsZone(ctx, domain, publicDNS)
	if err != nil {
		return nil
	}
	reply, err := publicDNS(ctx, zone, dnsmessage.TypeNS)
	if err != nil {
		return nil
	}
	var out []publicResolver
	for _, host := range recordText(reply, dnsmessage.TypeNS) {
		addrs, _ := lookupIPs(ctx, host)
		for _, a := range addrs {
			if isPublic(a) {
				out = append(out, publicResolver{host, a})
				break
			}
		}
		if len(out) == 3 || ctx.Err() != nil {
			break
		}
	}
	return out
}

// A recursive SOA response can carry the enclosing zone in the authority section.
func dnsZone(ctx context.Context, domain string, lookup func(context.Context, string, dnsmessage.Type) (*dnsmessage.Message, error)) (string, error) {
	for name := domain; strings.Contains(name, "."); {
		reply, err := lookup(ctx, name, dnsmessage.TypeSOA)
		if err != nil {
			return "", err
		}
		for _, section := range [][]dnsmessage.Resource{reply.Answers, reply.Authorities} {
			for _, resource := range section {
				owner := strings.ToLower(strings.TrimSuffix(resource.Header.Name.String(), "."))
				if resource.Header.Type == dnsmessage.TypeSOA && (owner == domain || strings.HasSuffix(domain, "."+owner)) {
					return owner, nil
				}
			}
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return "", fail("The enclosing DNS zone could not be determined.", "Die zuständige DNS-Zone konnte nicht ermittelt werden.")
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
	authCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var auth []publicResolver
	var authWG sync.WaitGroup
	authWG.Add(1)
	go func() {
		defer authWG.Done()
		auth = authoritativeServers(authCtx, domain)
	}()
	answers := make([]propagationAnswer, len(targets), len(targets)+3)
	var wg sync.WaitGroup
	query := func(i int, r publicResolver, isAuth bool) {
		defer wg.Done()
		label := T(fmt.Sprintf("%s (%s)", r.name, r.addr), fmt.Sprintf("%s (%s)", r.name, r.addr))
		if isAuth {
			label = T(r.name+" (authoritative)", r.name+" (autoritativ)")
		}
		lookup := dnsAsk{server: r.addr, name: domain, qtype: qtype, recursive: !isAuth}
		var reply *dnsmessage.Message
		var took time.Duration
		var err error
		if isAuth {
			reply, took, err = ask(ctx, lookup)
		} else {
			reply, took, err = askPublic(ctx, lookup)
		}
		a := propagationAnswer{label: label, auth: isAuth}
		switch {
		case err != nil:
			a.err = "no response"
		case reply.RCode == dnsmessage.RCodeNameError:
			a.nx = true
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
	wg.Wait()
	authWG.Wait()
	answers = answers[:len(targets)+len(auth)]
	for i, r := range auth {
		wg.Add(1)
		go query(len(targets)+i, r, true)
	}
	wg.Wait()

	section, summary := summarizePropagation(domain, typeName, answers)
	if len(auth) == 0 {
		summary.Rows = append(summary.Rows, noteRow("Authoritative name servers", "Autoritative Nameserver",
			"No authoritative name servers could be checked.", "Die autoritativen Nameserver konnten nicht geprüft werden.", "warn"))
	}
	return &Result{Sections: []Section{summary, section}}, nil
}

func answerKey(a propagationAnswer) string {
	if a.nx {
		return "NXDOMAIN"
	}
	return "records:" + strings.Join(a.values, "\n")
}

func summarizePropagation(domain, typeName string, answers []propagationAnswer) (Section, Section) {
	counts := map[string]int{}
	reference := ""
	responded := 0
	for _, a := range answers {
		if a.err == "" {
			key := answerKey(a)
			if a.auth && reference == "" {
				reference = key
			}
			counts[key]++
			responded++
		}
	}
	if reference == "" {
		best := 0
		for _, a := range answers {
			if a.err == "" && counts[answerKey(a)] > best {
				reference = answerKey(a)
				best = counts[reference]
			}
		}
	}

	section := Section{Title: T(typeName+" records for "+domain, typeName+"-Einträge für "+domain)}
	same := 0
	for _, a := range answers {
		r := Row{Label: a.label}
		switch {
		case a.err == "no response":
			r.Note, r.Status = &Text{"no response", "keine Antwort"}, "warn"
		case a.err != "":
			r.Value, r.Status = a.err, "warn"
		case a.nx:
			r.Note, r.Status = &Text{"name does not exist (NXDOMAIN)", "Name existiert nicht (NXDOMAIN)"}, statusFor(answerKey(a) == reference)
		case len(a.values) == 0:
			r.Note, r.Status = &Text{"no record of this type", "kein Eintrag dieses Typs"}, statusFor(answerKey(a) == reference)
		default:
			r.Value, r.Status = strings.Join(a.values, "\n"), statusFor(answerKey(a) == reference)
		}
		if r.Status == "ok" {
			same++
		}
		section.Rows = append(section.Rows, r)
	}
	summary := Section{Title: T("Summary", "Zusammenfassung")}
	switch {
	case responded == 0:
		summary.Rows = append(summary.Rows, noteRow("Status", "Status",
			"No DNS server returned a usable answer.", "Kein DNS-Server hat eine auswertbare Antwort geliefert.", "bad"))
	case same != responded:
		summary.Rows = append(summary.Rows, noteRow("Status", "Status",
			fmt.Sprintf("%d of %d usable answers differ.", responded-same, responded),
			fmt.Sprintf("%d von %d auswertbaren Antworten weichen ab.", responded-same, responded), "warn"))
	default:
		summary.Rows = append(summary.Rows, noteRow("Status", "Status",
			fmt.Sprintf("%d servers returned the same answer.", responded),
			fmt.Sprintf("%d Server liefern dieselbe Antwort.", responded), statusFor(responded == len(answers) && responded > 1)))
	}
	if unavailable := len(answers) - responded; unavailable > 0 {
		summary.Rows = append(summary.Rows, noteRow("Unavailable", "Nicht auswertbar",
			fmt.Sprintf("%d of %d servers", unavailable, len(answers)),
			fmt.Sprintf("%d von %d Servern", unavailable, len(answers)), "warn"))
	}
	return section, summary
}

func statusFor(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}
