package checker

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

func lookupTXT(ctx context.Context, name string) []string {
	records, _ := resolver.LookupTXT(ctx, name)
	return records
}

func withPrefix(records []string, prefix string) []string {
	var out []string
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), strings.ToLower(prefix)) {
			out = append(out, r)
		}
	}
	return out
}

func dmarcPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "p") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

func dnsLookup(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}

	type response struct {
		name   string
		kind   string
		qtype  dnsmessage.Type
		values []string
		rcode  dnsmessage.RCode
		err    error
	}
	lookups := []response{
		{name: domain, kind: "A", qtype: dnsmessage.TypeA},
		{name: domain, kind: "AAAA", qtype: dnsmessage.TypeAAAA},
		{name: domain, kind: "CNAME", qtype: dnsmessage.TypeCNAME},
		{name: domain, kind: "MX", qtype: dnsmessage.TypeMX},
		{name: domain, kind: "NS", qtype: dnsmessage.TypeNS},
		{name: domain, kind: "TXT", qtype: dnsmessage.TypeTXT},
		{name: "_dmarc." + domain, qtype: dnsmessage.TypeTXT},
		{name: "_mta-sts." + domain, qtype: dnsmessage.TypeTXT},
		{name: "_smtp._tls." + domain, qtype: dnsmessage.TypeTXT},
		{name: "default._bimi." + domain, qtype: dnsmessage.TypeTXT},
	}
	var wg sync.WaitGroup
	for i := range lookups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lookup := &lookups[i]
			reply, err := publicDNS(ctx, lookup.name, lookup.qtype)
			lookup.err = err
			if err == nil {
				lookup.rcode = reply.RCode
				lookup.values = recordText(reply, lookup.qtype)
				slices.Sort(lookup.values)
			}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	records := Section{Title: T("DNS records", "DNS-Einträge")}
	warnings := Section{Title: T("Unanswered queries", "Nicht beantwortete Abfragen")}
	var failure error
	found, missing := 0, 0
	for _, lookup := range lookups[:6] {
		switch {
		case lookup.err != nil:
			failure = lookup.err
			warnings.Rows = append(warnings.Rows, dnsMissing(lookup.kind, lookup.kind))
		case lookup.rcode == dnsmessage.RCodeNameError:
			missing++
		default:
			for _, value := range lookup.values {
				found++
				records.Rows = append(records.Rows, row(lookup.kind, lookup.kind, value))
			}
		}
	}
	if found == 0 {
		switch {
		case failure != nil:
			return nil, failure
		case missing == 6:
			return nil, fail("This DNS name does not exist.", "Dieser DNS-Name existiert nicht.")
		default:
			records.Rows = append(records.Rows, noteRow("Result", "Ergebnis",
				"The name exists, but none of the queried record types is present.",
				"Der Name existiert, hat aber keinen Eintrag der abgefragten Typen."))
		}
	}
	txt, dmarc := lookups[5], withPrefix(lookups[6].values, "v=DMARC1")
	mail := Section{Title: T("Email authentication", "E-Mail-Authentifizierung")}
	spf := withPrefix(txt.values, "v=spf1")
	switch {
	case txt.err != nil:
		mail.Rows = append(mail.Rows, dnsMissing("SPF", "SPF"))
	case len(spf) == 0:
		mail.Rows = append(mail.Rows, noteRow("SPF", "SPF", "missing", "fehlt", "bad"))
	case len(spf) == 1:
		mail.Rows = append(mail.Rows, row("SPF", "SPF", spf[0], "ok"))
	default:
		mail.Rows = append(mail.Rows, row("SPF (multiple records, invalid)", "SPF (mehrere Einträge, ungültig)", strings.Join(spf, "\n"), "bad"))
	}
	switch {
	case lookups[6].err != nil:
		mail.Rows = append(mail.Rows, dnsMissing("DMARC", "DMARC"))
	case len(dmarc) == 0:
		mail.Rows = append(mail.Rows, noteRow("DMARC", "DMARC", "missing", "fehlt", "bad"))
	case len(dmarc) > 1:
		mail.Rows = append(mail.Rows, row("DMARC (multiple records, invalid)", "DMARC (mehrere Einträge, ungültig)", strings.Join(dmarc, "\n"), "bad"))
	default:
		status := "ok"
		if p := dmarcPolicy(dmarc[0]); p != "quarantine" && p != "reject" {
			status = "warn"
		}
		mail.Rows = append(mail.Rows, row("DMARC", "DMARC", dmarc[0], status))
	}
	optional := func(en, de string, index int, prefix string) {
		lookup := lookups[index]
		values := withPrefix(lookup.values, prefix)
		switch {
		case lookup.err != nil:
			mail.Rows = append(mail.Rows, dnsMissing(en, de))
		case len(values) > 0:
			mail.Rows = append(mail.Rows, row(en, de, strings.Join(values, "\n"), "ok"))
		default:
			mail.Rows = append(mail.Rows, noteRow(en, de, "not set", "nicht gesetzt"))
		}
	}
	optional("MTA-STS", "MTA-STS", 7, "v=STSv1")
	optional("TLS reporting", "TLS-Berichte", 8, "v=TLSRPTv1")
	optional("BIMI", "BIMI", 9, "v=BIMI1")
	if lookups[3].err == nil && len(lookups[3].values) == 0 {
		mail.Rows = append(mail.Rows, noteRow("MX", "MX", "no mail server", "kein Mailserver", "warn"))
	}

	sections := []Section{records}
	if len(warnings.Rows) > 0 {
		sections = append(sections, warnings)
	}
	return &Result{Sections: append(sections, mail)}, nil
}

func dnsMissing(en, de string) Row {
	return noteRow(en, de, "DNS query could not be completed", "DNS-Abfrage konnte nicht abgeschlossen werden", "warn")
}
