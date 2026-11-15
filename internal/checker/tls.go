package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

var tlsPorts = []string{"443", "465", "993", "995", "8443"}

func keyDescription(cert *x509.Certificate) string {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bit", key.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + key.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func sslLookup(ctx context.Context, q url.Values) (*Result, error) {
	raw := strings.TrimSpace(q.Get("q"))
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Host
		}
	}
	host, port := raw, q.Get("port")
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	}
	if port == "" {
		port = "443"
	}
	if !slices.Contains(tlsPorts, port) {
		return nil, fail("Allowed ports: 443, 465, 993, 995 and 8443.", "Erlaubte Ports: 443, 465, 993, 995 und 8443.")
	}
	serverName := ""
	if addr, err := netip.ParseAddr(host); err == nil {
		if !isPublic(addr) {
			return nil, errBlocked
		}
	} else {
		domain, err := normalizeDomain(host)
		if err != nil {
			return nil, err
		}
		host, serverName = domain, domain
	}

	conn, err := dialContext(dialer(tlsPorts))(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		if strings.Contains(err.Error(), errBlocked.Error()) {
			return nil, errBlocked
		}
		return nil, err
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // verified below, so invalid certificates can still be shown
		MinVersion:         tls.VersionTLS10,
	})
	if err := client.HandshakeContext(ctx); err != nil {
		return nil, fail("TLS handshake failed: "+err.Error(), "TLS-Handshake fehlgeschlagen: "+err.Error())
	}
	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fail("The server sent no certificate.", "Der Server hat kein Zertifikat gesendet.")
	}
	leaf := state.PeerCertificates[0]

	connection := Section{Title: T("Connection", "Verbindung")}
	connection.Rows = append(connection.Rows, row("Server", "Server", conn.RemoteAddr().String()))
	version := tls.VersionName(state.Version)
	versionStatus := "ok"
	if state.Version < tls.VersionTLS12 {
		versionStatus = "bad"
	}
	connection.Rows = append(connection.Rows,
		row("Protocol", "Protokoll", version, versionStatus),
		row("Cipher suite", "Verschlüsselung", tls.CipherSuiteName(state.CipherSuite)))
	if state.NegotiatedProtocol != "" {
		connection.Rows = append(connection.Rows, row("ALPN", "ALPN", state.NegotiatedProtocol))
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{Intermediates: intermediates}
	if serverName != "" {
		opts.DNSName = serverName
	}
	trust := noteRow("Trusted", "Vertrauenswürdig", "yes, valid for this name", "ja, gültig für diesen Namen", "ok")
	if _, err := leaf.Verify(opts); err != nil {
		trust = row("Trusted", "Vertrauenswürdig", err.Error(), "bad")
	}

	expiry := "ok"
	switch d := days(leaf.NotAfter); {
	case d < 0:
		expiry = "bad"
	case d < 14:
		expiry = "warn"
	}
	names := leaf.DNSNames
	more := ""
	if len(names) > 25 {
		more = fmt.Sprintf(" … (+%d)", len(names)-25)
		names = names[:25]
	}
	certificate := Section{Title: T("Certificate", "Zertifikat"), Rows: []Row{
		trust,
		row("Subject", "Inhaber", leaf.Subject.CommonName),
		row("Names (SAN)", "Namen (SAN)", strings.Join(names, ", ")+more),
		row("Issuer", "Aussteller", leaf.Issuer.String()),
		row("Valid from", "Gültig ab", date(leaf.NotBefore)),
		row("Valid until", "Gültig bis", date(leaf.NotAfter), expiry),
		row("Key", "Schlüssel", keyDescription(leaf)),
		row("Signature", "Signatur", leaf.SignatureAlgorithm.String()),
		row("Serial number", "Seriennummer", strings.ToUpper(leaf.SerialNumber.Text(16))),
	}}

	chain := Section{Title: T("Certificate chain", "Zertifikatskette")}
	for i, cert := range state.PeerCertificates {
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}
		chain.Rows = append(chain.Rows, row(fmt.Sprintf("#%d", i+1), fmt.Sprintf("#%d", i+1),
			fmt.Sprintf("%s ← %s (%s)", name, cert.Issuer.CommonName, cert.NotAfter.UTC().Format("2006-01-02"))))
	}

	return &Result{Sections: []Section{certificate, connection, chain}}, nil
}
