package checker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var mailPorts = []string{"25", "465", "587", "143", "993", "110", "995"}

type mailPort struct {
	port     string
	name     string
	implicit bool // TLS from the first byte
	proto    string
}

var mailServices = []mailPort{
	{"25", "SMTP", false, "smtp"},
	{"465", "SMTPS (submission)", true, "smtp"},
	{"587", "Submission", false, "smtp"},
	{"143", "IMAP", false, "imap"},
	{"993", "IMAPS", true, "imap"},
	{"110", "POP3", false, "pop3"},
	{"995", "POP3S", true, "pop3"},
}

// certificateStatus verifies the peer certificate for the given name.
func certificateStatus(state tls.ConnectionState, name string) (Text, string) {
	if len(state.PeerCertificates) == 0 {
		return T("no certificate", "kein Zertifikat"), "bad"
	}
	leaf := state.PeerCertificates[0]
	pool := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Intermediates: pool}); err != nil {
		return T("certificate invalid: "+err.Error(), "Zertifikat ungültig: "+err.Error()), "bad"
	}
	if d := days(leaf.NotAfter); d < 14 {
		return T(fmt.Sprintf("certificate expires in %d days", d), fmt.Sprintf("Zertifikat läuft in %d Tagen ab", d)), "warn"
	}
	until := leaf.NotAfter.UTC().Format("2006-01-02")
	return T("certificate valid until "+until, "Zertifikat gültig bis "+until), "ok"
}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

// smtpReply reads a possibly multi-line SMTP reply.
func smtpReply(r *bufio.Reader) []string {
	var lines []string
	for {
		line := readLine(r)
		if line == "" {
			return lines
		}
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

// probe connects to one mail port and reports banner and TLS state.
func probe(ctx context.Context, host string, addr netip.Addr, svc mailPort) Row {
	label := T(svc.port+" "+svc.name, svc.port+" "+svc.name)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := dialContext(dialer(mailPorts))(ctx, "tcp", net.JoinHostPort(addr.String(), svc.port))
	if err != nil {
		status := ""
		if svc.port == "25" {
			status = "bad" // a mail server must accept connections on port 25
		}
		return Row{Label: label, Note: &Text{"closed or filtered", "geschlossen oder gefiltert"}, Status: status}
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	config := &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}

	var banner string
	var tlsConn *tls.Conn
	if svc.implicit {
		tlsConn = tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return Row{Label: label, Value: err.Error(), Note: &Text{"TLS failed", "TLS fehlgeschlagen"}, Status: "bad"}
		}
		banner = readLine(bufio.NewReader(tlsConn))
	} else {
		r := bufio.NewReader(conn)
		w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		ok := false
		switch svc.proto {
		case "smtp":
			lines := smtpReply(r)
			if len(lines) > 0 {
				banner = lines[0]
			}
			if strings.HasPrefix(banner, "421") {
				return Row{Label: label, Value: banner, Note: &Text{"server busy – try again later", "Server ausgelastet – später erneut prüfen"}, Status: "warn"}
			}
			w("EHLO deliver.zenmail.eu")
			caps := smtpReply(r)
			if slices.ContainsFunc(caps, func(l string) bool { return strings.Contains(strings.ToUpper(l), "STARTTLS") }) {
				w("STARTTLS")
				reply := smtpReply(r)
				ok = len(reply) > 0 && strings.HasPrefix(reply[0], "220")
			}
		case "imap":
			banner = readLine(r)
			w("a1 STARTTLS")
			for i := 0; i < 5; i++ {
				line := readLine(r)
				if strings.HasPrefix(line, "a1 ") {
					ok = strings.HasPrefix(strings.ToUpper(line), "A1 OK")
					break
				}
			}
		case "pop3":
			banner = readLine(r)
			w("STLS")
			ok = strings.HasPrefix(readLine(r), "+OK")
		}
		if !ok {
			return Row{Label: label, Value: banner, Note: &Text{"no STARTTLS – passwords and mails would travel unencrypted",
				"kein STARTTLS – Passwörter und Mails würden unverschlüsselt übertragen"}, Status: "bad"}
		}
		tlsConn = tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return Row{Label: label, Value: err.Error(), Note: &Text{"STARTTLS failed", "STARTTLS fehlgeschlagen"}, Status: "bad"}
		}
	}

	state := tlsConn.ConnectionState()
	cert, status := certificateStatus(state, host)
	version := tls.VersionName(state.Version)
	if state.Version < tls.VersionTLS12 && status == "ok" {
		status = "warn"
	}
	mode := "STARTTLS"
	if svc.implicit {
		mode = "TLS"
	}
	value := fmt.Sprintf("%s · %s", mode, version)
	if banner != "" {
		if len(banner) > 100 {
			banner = banner[:100] + "…"
		}
		value = banner + "\n" + value
	}
	return Row{Label: label, Value: value, Note: &cert, Status: status}
}

func mailPortCheck(ctx context.Context, q url.Values) (*Result, error) {
	domain, err := normalizeDomain(q.Get("q"))
	if err != nil {
		return nil, err
	}
	hosts := []string{}
	reply, err := publicDNS(ctx, domain, dnsmessage.TypeMX)
	if err != nil {
		return nil, err
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		return nil, fail("This DNS name does not exist.", "Dieser DNS-Name existiert nicht.")
	}
	var mx []*dnsmessage.MXResource
	for _, answer := range reply.Answers {
		if record, ok := answer.Body.(*dnsmessage.MXResource); ok {
			mx = append(mx, record)
		}
	}
	slices.SortFunc(mx, func(a, b *dnsmessage.MXResource) int { return int(a.Pref) - int(b.Pref) })
	for _, m := range mx {
		h := strings.TrimSuffix(m.MX.String(), ".")
		if h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
		if len(hosts) == 3 {
			break
		}
	}
	intro := Section{Title: T("Mail servers", "Mailserver")}
	if len(mx) == 1 && mx[0].MX.String() == "." {
		intro.Rows = []Row{noteRow("MX", "MX", "This domain explicitly does not accept email (null MX).", "Diese Domain nimmt laut Null-MX-Eintrag keine E-Mails an.")}
		return &Result{Sections: []Section{intro}}, nil
	}
	if len(hosts) == 0 {
		hosts = []string{domain}
		intro.Rows = append(intro.Rows, noteRow("MX", "MX", "no MX record – checking the host itself", "kein MX-Eintrag – geprüft wird der Host selbst", "warn"))
	} else {
		intro.Rows = append(intro.Rows, row("MX", "MX", strings.Join(hosts, ", ")))
	}

	result := &Result{Sections: []Section{intro}}
	sections := make([]Section, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sections[i] = checkMailHost(ctx, host)
		}()
	}
	wg.Wait()
	result.Sections = append(result.Sections, sections...)
	result.Sections = append(result.Sections, Section{Title: T("Note", "Hinweis"), Rows: []Row{
		noteRow("Scope", "Umfang", "Only standard mail ports are checked; closed ports are fine for services you do not offer.",
			"Geprüft werden nur die üblichen Mail-Ports; geschlossene Ports sind in Ordnung, wenn du den Dienst nicht anbietest."),
	}})
	return result, nil
}

func checkMailHost(ctx context.Context, host string) Section {
	section := Section{Title: T(host, host)}
	addrs, err := lookupIPs(ctx, host)
	var dnsErr *dnsUnavailable
	if errors.As(err, &dnsErr) {
		section.Rows = []Row{dnsMissing("Address", "Adresse")}
		return section
	}
	var addr netip.Addr
	// Prefer IPv4 when both families are available.
	for _, candidate := range addrs {
		if isPublic(candidate) && (!addr.IsValid() || candidate.Is4()) {
			addr = candidate
			if addr.Is4() {
				break
			}
		}
	}
	if !addr.IsValid() {
		section.Rows = []Row{noteRow("Address", "Adresse", "no public A or AAAA address", "keine öffentliche A- oder AAAA-Adresse", "warn")}
		return section
	}
	section.Title = T(host+" ("+addr.String()+")", host+" ("+addr.String()+")")
	section.Rows = make([]Row, len(mailServices))
	var wg sync.WaitGroup
	for j, svc := range mailServices {
		if svc.proto != "smtp" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				section.Rows[j] = probe(ctx, host, addr, svc)
			}()
		}
	}
	// SMTP servers often limit parallel connections per IP.
	for j, svc := range mailServices {
		if svc.proto == "smtp" {
			section.Rows[j] = probe(ctx, host, addr, svc)
		}
	}
	wg.Wait()
	return section
}
