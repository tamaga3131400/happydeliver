package checker

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"time"
)

// Classic WHOIS on port 43 is used for top-level domains without RDAP (for example .de and .eu).

func whoisQuery(ctx context.Context, server, query string) (string, error) {
	conn, err := dialContext(dialer([]string{"43"}))(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 8*time.Second {
		deadline = time.Now().Add(8 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil && len(body) == 0 {
		return "", err
	}
	return string(body), nil
}

// whoisServer asks IANA which WHOIS server is responsible for the top-level domain.
func whoisServer(ctx context.Context, tld string) (string, error) {
	answer, err := whoisQuery(ctx, "whois.iana.org", tld)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(answer))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && (strings.EqualFold(strings.TrimSpace(key), "whois") || strings.EqualFold(strings.TrimSpace(key), "refer")) {
			if server := strings.TrimSpace(value); server != "" {
				return server, nil
			}
		}
	}
	return "", nil
}

// cleanWhois drops comment and legal boilerplate lines and keeps the data.
func cleanWhois(raw string) string {
	var lines []string
	blank := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ">>>") {
			continue
		}
		if trimmed == "" {
			if !blank && len(lines) > 0 {
				lines = append(lines, "")
			}
			blank = true
			continue
		}
		blank = false
		lines = append(lines, strings.TrimRight(line, " \t"))
	}
	text := strings.TrimSpace(strings.Join(lines, "\n"))
	if len(text) > 6000 {
		text = text[:6000] + "\n…"
	}
	return text
}

func whoisFallback(ctx context.Context, domain string) (*Result, error) {
	labels := strings.Split(domain, ".")
	server, err := whoisServer(ctx, labels[len(labels)-1])
	if err != nil || server == "" {
		return nil, fail("No registration service is known for this top-level domain.",
			"Für diese Top-Level-Domain ist kein Registrierungsdienst bekannt.")
	}
	query := domain
	if server == "whois.denic.de" {
		query = "-T dn,ace " + domain
	}
	answer, err := whoisQuery(ctx, server, query)
	if err != nil {
		return nil, err
	}
	text := cleanWhois(answer)
	if text == "" {
		return nil, fail("The registry returned no data.", "Die Registry hat keine Daten geliefert.")
	}
	return &Result{Sections: []Section{
		{Title: T("Registration (WHOIS)", "Registrierung (WHOIS)"), Rows: []Row{row("WHOIS", "WHOIS", text)}},
		{Title: T("Source", "Quelle"), Rows: []Row{
			row("WHOIS server", "WHOIS-Server", server),
			noteRow("Note", "Hinweis", "This registry offers no RDAP; personal data is usually withheld.",
				"Diese Registry bietet kein RDAP an; persönliche Daten werden meist nicht herausgegeben."),
		}},
	}}, nil
}
