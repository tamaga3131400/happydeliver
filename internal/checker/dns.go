package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
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

	var (
		wg                       sync.WaitGroup
		ips                      []netip.Addr
		cname                    string
		mx                       []*net.MX
		ns                       []*net.NS
		txt, dmarc, sts, rpt, bm []string
		ipErr                    error
	)
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() { ips, ipErr = lookupIPs(ctx, domain) })
	run(func() { cname, _ = resolver.LookupCNAME(ctx, domain) })
	run(func() { mx, _ = resolver.LookupMX(ctx, domain) })
	run(func() { ns, _ = resolver.LookupNS(ctx, domain) })
	run(func() { txt = lookupTXT(ctx, domain) })
	run(func() { dmarc = withPrefix(lookupTXT(ctx, "_dmarc."+domain), "v=DMARC1") })
	run(func() { sts = withPrefix(lookupTXT(ctx, "_mta-sts."+domain), "v=STSv1") })
	run(func() { rpt = withPrefix(lookupTXT(ctx, "_smtp._tls."+domain), "v=TLSRPTv1") })
	run(func() { bm = withPrefix(lookupTXT(ctx, "default._bimi."+domain), "v=BIMI1") })
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	records := Section{Title: T("DNS records", "DNS-Einträge")}
	for _, ip := range ips {
		kind := "A"
		if ip.Is6() {
			kind = "AAAA"
		}
		records.Rows = append(records.Rows, Row{Label: T(kind, kind), Value: ip.String()})
	}
	if cname = strings.TrimSuffix(cname, "."); cname != "" && cname != domain {
		records.Rows = append(records.Rows, Row{Label: T("CNAME", "CNAME"), Value: cname})
	}
	for _, m := range mx {
		records.Rows = append(records.Rows, Row{Label: T("MX", "MX"), Value: fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, "."))})
	}
	for _, n := range ns {
		records.Rows = append(records.Rows, Row{Label: T("NS", "NS"), Value: strings.TrimSuffix(n.Host, ".")})
	}
	slices.Sort(txt)
	for _, t := range txt {
		records.Rows = append(records.Rows, Row{Label: T("TXT", "TXT"), Value: t})
	}
	if len(records.Rows) == 0 {
		var dnsErr *net.DNSError
		if errors.As(ipErr, &dnsErr) && dnsErr.IsNotFound {
			return nil, fail("The domain does not exist or has no DNS records.", "Die Domain existiert nicht oder hat keine DNS-Einträge.")
		}
		return nil, fail("No DNS records found.", "Keine DNS-Einträge gefunden.")
	}

	mail := Section{Title: T("Email authentication", "E-Mail-Authentifizierung")}
	spf := withPrefix(txt, "v=spf1")
	switch len(spf) {
	case 0:
		mail.Rows = append(mail.Rows, noteRow("SPF", "SPF", "missing", "fehlt", "bad"))
	case 1:
		mail.Rows = append(mail.Rows, row("SPF", "SPF", spf[0], "ok"))
	default:
		mail.Rows = append(mail.Rows, row("SPF (multiple records, invalid)", "SPF (mehrere Einträge, ungültig)", strings.Join(spf, "\n"), "bad"))
	}
	switch {
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
	optional := func(en, de string, values []string) {
		if len(values) > 0 {
			mail.Rows = append(mail.Rows, row(en, de, strings.Join(values, "\n"), "ok"))
		} else {
			mail.Rows = append(mail.Rows, noteRow(en, de, "not set", "nicht gesetzt"))
		}
	}
	optional("MTA-STS", "MTA-STS", sts)
	optional("TLS reporting", "TLS-Berichte", rpt)
	optional("BIMI", "BIMI", bm)
	if len(mx) == 0 {
		mail.Rows = append(mail.Rows, noteRow("MX", "MX", "no mail server", "kein Mailserver", "warn"))
	}

	return &Result{Sections: []Section{records, mail}}, nil
}
