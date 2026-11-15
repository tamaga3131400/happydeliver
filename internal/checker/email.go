package checker

import (
	"context"
	"net/mail"
	"net/url"
	"slices"
	"strings"
)

var roleAccounts = []string{"admin", "administrator", "info", "office", "support", "sales", "contact", "kontakt",
	"service", "billing", "abuse", "postmaster", "hostmaster", "webmaster", "noreply", "no-reply", "mail", "team", "hello", "help"}

var popularProviders = []string{"gmail.com", "googlemail.com", "yahoo.com", "yahoo.de", "outlook.com", "outlook.de", "hotmail.com",
	"hotmail.de", "live.com", "live.de", "icloud.com", "me.com", "aol.com", "gmx.de", "gmx.net", "gmx.at", "gmx.ch", "web.de",
	"t-online.de", "freenet.de", "posteo.de", "mailbox.org", "protonmail.com", "proton.me", "yandex.com", "mail.ru", "zoho.com"}

// levenshtein returns the edit distance between two short strings.
func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// typoSuggestion proposes a popular provider for a likely misspelled domain.
func typoSuggestion(domain string) string {
	if slices.Contains(popularProviders, domain) {
		return ""
	}
	best, bestDist := "", 3
	for _, p := range popularProviders {
		if d := levenshtein(domain, p); d < bestDist {
			best, bestDist = p, d
		}
	}
	return best
}

func emailCheck(ctx context.Context, q url.Values) (*Result, error) {
	input := strings.TrimSpace(q.Get("q"))
	parsed, err := mail.ParseAddress(input)
	if err != nil || parsed.Address != input && !strings.Contains(input, "<") {
		return nil, fail("Please enter a valid email address such as name@example.com.", "Bitte gib eine gültige E-Mail-Adresse wie name@example.com ein.")
	}
	at := strings.LastIndex(parsed.Address, "@")
	local, rawDomain := parsed.Address[:at], parsed.Address[at+1:]
	domain, err := normalizeDomain(rawDomain)
	if err != nil {
		return nil, err
	}

	address := Section{Title: T("Address", "Adresse"), Rows: []Row{
		row("Address", "Adresse", local+"@"+domain),
	}}
	if len(local) > 64 {
		address.Rows = append(address.Rows, noteRow("Local part", "Lokaler Teil", "longer than 64 characters", "länger als 64 Zeichen", "bad"))
	} else {
		address.Rows = append(address.Rows, noteRow("Syntax", "Syntax", "valid", "gültig", "ok"))
	}
	if suggestion := typoSuggestion(domain); suggestion != "" {
		address.Rows = append(address.Rows, noteRow("Possible typo", "Möglicher Tippfehler", "did you mean "+local+"@"+suggestion+"?",
			"meintest du "+local+"@"+suggestion+"?", "warn"))
	}
	base := strings.ToLower(strings.SplitN(local, "+", 2)[0])
	if slices.Contains(roleAccounts, base) {
		address.Rows = append(address.Rows, noteRow("Type", "Art", "role address (team mailbox, not a person)",
			"Rollenadresse (Team-Postfach, keine Person)"))
	}
	if strings.Contains(local, "+") {
		address.Rows = append(address.Rows, noteRow("Sub-address", "Unteradresse", "uses +tag; mail goes to "+base+"@"+domain,
			"nutzt +Tag; Mails landen bei "+base+"@"+domain))
	}

	provider := Section{Title: T("Provider", "Anbieter")}
	if set := disposableDomains.Load(); set == nil {
		provider.Rows = append(provider.Rows, noteRow("Disposable", "Wegwerf-Adresse", "list is being loaded", "Liste wird geladen"))
	} else if (*set)[domain] {
		provider.Rows = append(provider.Rows, noteRow("Disposable", "Wegwerf-Adresse", "yes – a temporary mailbox", "ja – ein temporäres Postfach", "bad"))
	} else {
		provider.Rows = append(provider.Rows, noteRow("Disposable", "Wegwerf-Adresse", "no", "nein", "ok"))
	}
	if set := freemailDomains.Load(); set != nil {
		if (*set)[domain] {
			provider.Rows = append(provider.Rows, noteRow("Free mail provider", "Freemail-Anbieter", "yes", "ja"))
		} else {
			provider.Rows = append(provider.Rows, noteRow("Free mail provider", "Freemail-Anbieter", "no – likely an own domain", "nein – wahrscheinlich eigene Domain"))
		}
	}

	dns := Section{Title: T("Mail delivery", "Zustellung")}
	mx, _ := resolver.LookupMX(ctx, domain)
	switch {
	case len(mx) == 1 && (mx[0].Host == "." || mx[0].Host == ""):
		dns.Rows = append(dns.Rows, noteRow("MX", "MX", "null MX – this domain accepts no mail", "Null-MX – diese Domain nimmt keine Mails an", "bad"))
	case len(mx) > 0:
		var hosts []string
		for _, m := range mx {
			hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
		}
		dns.Rows = append(dns.Rows, row("MX", "MX", strings.Join(hosts, ", "), "ok"))
	default:
		if ips, _ := lookupIPs(ctx, domain); len(ips) > 0 {
			dns.Rows = append(dns.Rows, noteRow("MX", "MX", "none – delivery falls back to the A record", "keiner – Zustellung nur über den A-Eintrag", "warn"))
		} else {
			dns.Rows = append(dns.Rows, noteRow("MX", "MX", "none – mail to this address cannot be delivered", "keiner – Mails an diese Adresse sind nicht zustellbar", "bad"))
		}
	}
	txt := lookupTXT(ctx, domain)
	if len(withPrefix(txt, "v=spf1")) > 0 {
		dns.Rows = append(dns.Rows, noteRow("SPF", "SPF", "present", "vorhanden", "ok"))
	} else {
		dns.Rows = append(dns.Rows, noteRow("SPF", "SPF", "missing – mails from this domain are easier to forge", "fehlt – Mails dieser Domain sind leichter zu fälschen", "warn"))
	}
	if len(withPrefix(lookupTXT(ctx, "_dmarc."+domain), "v=DMARC1")) > 0 {
		dns.Rows = append(dns.Rows, noteRow("DMARC", "DMARC", "present", "vorhanden", "ok"))
	} else {
		dns.Rows = append(dns.Rows, noteRow("DMARC", "DMARC", "missing", "fehlt", "warn"))
	}
	note := Section{Title: T("Note", "Hinweis"), Rows: []Row{noteRow("Mailbox", "Postfach",
		"Whether the mailbox itself exists is not tested; probing mail servers for that is unreliable and often treated as abuse.",
		"Ob das Postfach selbst existiert, wird nicht geprüft; solche Abfragen sind unzuverlässig und gelten oft als Missbrauch.")}}
	return &Result{Sections: []Section{address, provider, dns, note}}, nil
}
