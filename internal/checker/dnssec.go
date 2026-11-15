package checker

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

var dnssecAlgorithms = map[byte]string{
	5: "RSA/SHA-1", 7: "RSASHA1-NSEC3", 8: "RSA/SHA-256", 10: "RSA/SHA-512",
	13: "ECDSA P-256/SHA-256", 14: "ECDSA P-384/SHA-384", 15: "Ed25519", 16: "Ed448",
}

func algorithmName(alg byte) string {
	if name, ok := dnssecAlgorithms[alg]; ok {
		return fmt.Sprintf("%s (%d)", name, alg)
	}
	return fmt.Sprintf("%d", alg)
}

func dnssecCheck(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}
	validator := publicResolvers[1].addr // Cloudflare validates DNSSEC

	ds, _, dsErr := ask(ctx, dnsAsk{server: validator, name: domain, qtype: typeDS, recursive: true, dnssec: true, noCheck: true})
	keys, _, keyErr := ask(ctx, dnsAsk{server: validator, name: domain, qtype: typeDNSKEY, recursive: true, dnssec: true, noCheck: true})
	if dsErr != nil && keyErr != nil {
		return nil, dsErr
	}

	setup := Section{Title: T("Setup", "Einrichtung")}
	dsCount := 0
	if dsErr == nil {
		dsCount = countType(ds, typeDS)
	}
	var algs []string
	if dsCount > 0 {
		for _, d := range unknownData(ds, typeDS) {
			if len(d) >= 4 {
				algs = append(algs, algorithmName(d[2]))
			}
		}
		setup.Rows = append(setup.Rows, row("DS record at the registry", "DS-Eintrag bei der Registry", fmt.Sprintf("%d", dsCount), "ok"))
	} else {
		setup.Rows = append(setup.Rows, noteRow("DS record at the registry", "DS-Eintrag bei der Registry", "none – the domain is not signed", "keiner – die Domain ist nicht signiert", "warn"))
	}
	ksk, zsk := 0, 0
	if keyErr == nil {
		for _, d := range unknownData(keys, typeDNSKEY) {
			if len(d) < 4 {
				continue
			}
			if binary.BigEndian.Uint16(d[:2])&1 == 1 {
				ksk++
			} else {
				zsk++
			}
			algs = append(algs, algorithmName(d[3]))
		}
	}
	if ksk+zsk > 0 {
		setup.Rows = append(setup.Rows, row("DNSKEY", "DNSKEY", fmt.Sprintf("%d KSK, %d ZSK", ksk, zsk), "ok"))
	} else {
		status := ""
		if dsCount > 0 {
			status = "bad"
		}
		setup.Rows = append(setup.Rows, noteRow("DNSKEY", "DNSKEY", "none", "keiner", status))
	}
	if len(algs) > 0 {
		slices.Sort(algs)
		setup.Rows = append(setup.Rows, row("Algorithm", "Algorithmus", strings.Join(slices.Compact(algs), ", ")))
	}

	validation := Section{Title: T("Validation", "Validierung")}
	type outcome struct {
		label  Text
		status string
		note   Text
	}
	results := make([]outcome, 3)
	var wg sync.WaitGroup
	for i, r := range publicResolvers[:3] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := outcome{label: T(r.name, r.name)}
			reply, _, err := ask(ctx, dnsAsk{server: r.addr, name: domain, qtype: dnsmessage.TypeSOA, recursive: true, dnssec: true})
			switch {
			case err != nil:
				o.status, o.note = "warn", Text{"no answer: " + err.Error(), "keine Antwort: " + err.Error()}
			case reply.RCode == dnsmessage.RCodeServerFailure:
				// SERVFAIL that disappears with CD set means the signatures are broken.
				retry, _, err := ask(ctx, dnsAsk{server: r.addr, name: domain, qtype: dnsmessage.TypeSOA, recursive: true, dnssec: true, noCheck: true})
				if err == nil && retry.RCode == dnsmessage.RCodeSuccess {
					o.status, o.note = "bad", Text{"validation fails (bogus) – the domain is unreachable for validating resolvers", "Validierung schlägt fehl (bogus) – die Domain ist für validierende Resolver nicht erreichbar"}
				} else {
					o.status, o.note = "bad", Text{"server failure", "Serverfehler"}
				}
			case reply.AuthenticData:
				o.status, o.note = "ok", Text{"signed and valid", "signiert und gültig"}
			default:
				o.note = Text{"answer not validated (unsigned)", "Antwort nicht validiert (unsigniert)"}
			}
			results[i] = o
		}()
	}
	wg.Wait()
	valid, bogus := 0, 0
	for _, o := range results {
		note := o.note
		validation.Rows = append(validation.Rows, Row{Label: o.label, Note: &note, Status: o.status})
		switch o.status {
		case "ok":
			valid++
		case "bad":
			bogus++
		}
	}

	summary := Section{Title: T("Result", "Ergebnis")}
	switch {
	case bogus > 0:
		summary.Rows = append(summary.Rows, noteRow("DNSSEC", "DNSSEC", "broken – fix the keys or remove the DS record at the registrar",
			"fehlerhaft – Schlüssel reparieren oder den DS-Eintrag beim Registrar entfernen", "bad"))
	case valid > 0:
		summary.Rows = append(summary.Rows, noteRow("DNSSEC", "DNSSEC", "active and valid", "aktiv und gültig", "ok"))
	case dsCount == 0:
		summary.Rows = append(summary.Rows, noteRow("DNSSEC", "DNSSEC", "not enabled – recommended to protect DNS answers against forgery",
			"nicht aktiviert – empfohlen, um DNS-Antworten gegen Fälschung zu schützen", "warn"))
	default:
		summary.Rows = append(summary.Rows, noteRow("DNSSEC", "DNSSEC", "unclear – see details", "unklar – siehe Details", "warn"))
	}
	return &Result{Sections: []Section{summary, setup, validation}}, nil
}
