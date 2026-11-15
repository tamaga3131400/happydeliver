package checker

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestIsPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.5.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fd00::1": false, "fe80::1": false, "::ffff:127.0.0.1": false, "64:ff9b::a00:1": false,
		"2002:a00:1::": false, "224.0.0.1": false, "198.18.0.1": false,
	} {
		if got := isPublic(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublic(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.": "example.com", "https://www.example.com/path": "www.example.com",
		"müller.de": "xn--mller-kva.de", "_dmarc.example.com": "_dmarc.example.com",
	} {
		if got, err := normalizeDomain(input); err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "localhost", "happydeliver", "db.internal", "printer.local", "1.2.3.4", "a..b", "-a.com", "x.home.arpa"} {
		if _, err := normalizeDomain(input); err == nil {
			t.Errorf("normalizeDomain(%q) accepted", input)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	u, err := normalizeURL("example.com/a#frag")
	if err != nil || u.String() != "https://example.com/a" {
		t.Fatalf("got %v, %v", u, err)
	}
	for _, input := range []string{"ftp://example.com", "http://127.0.0.1/", "http://[::1]/", "http://10.0.0.1/",
		"http://example.com:22/", "http://user:pw@example.com/", "http://169.254.169.254/latest/meta-data"} {
		if _, err := normalizeURL(input); err == nil {
			t.Errorf("normalizeURL(%q) accepted", input)
		}
	}
}

func TestDialerBlocksPrivateTargets(t *testing.T) {
	d := dialer(webPorts)
	for _, address := range []string{"127.0.0.1:80", "[::1]:443", "10.0.0.1:443", "1.1.1.1:22"} {
		_, err := d.DialContext(context.Background(), "tcp", address)
		if err == nil || !strings.Contains(err.Error(), errBlocked.Error()) {
			t.Errorf("dial %s: %v", address, err)
		}
	}
}

func TestChecksRejectBadInput(t *testing.T) {
	for name, input := range map[string]string{
		"dns-lookup": "localhost", "ssl-lookup": "127.0.0.1", "ip-lookup": "192.168.0.1",
		"whois-lookup": "10.0.0.1", "http-headers": "http://127.0.0.1", "redirect-check": "http://[::1]",
		"meta-tags": "http://172.17.0.1",
	} {
		_, err := checks[name](context.Background(), url.Values{"q": {input}})
		var ue *userError
		if err == nil || !(errors.As(err, &ue) || errors.Is(err, errBlocked)) {
			t.Errorf("%s(%q) = %v", name, input, err)
		}
	}
}

func TestCymruName(t *testing.T) {
	if got := cymruName(netip.MustParseAddr("1.2.3.4")); got != "4.3.2.1.origin.asn.cymru.com" {
		t.Error(got)
	}
	if got := cymruName(netip.MustParseAddr("2001:db8::1")); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, "8.b.d.0.1.0.0.2.origin6.asn.cymru.com") {
		t.Error(got)
	}
}

func TestParsePage(t *testing.T) {
	p := parsePage(strings.NewReader(`<html lang="de"><head><meta charset="utf-8"><title> A  page </title>
<meta name="description" content="D"><meta property="og:image" content="/x.png"><link rel="canonical" href="https://e.com/"></head><body><title>no</title>`))
	if p.lang != "de" || strings.TrimSpace(p.title) != "A  page" || len(p.meta) != 2 || len(p.links) != 1 || p.charset != "utf-8" {
		t.Errorf("%+v", p)
	}
}

func TestExtServerPattern(t *testing.T) {
	var got []string
	for _, m := range extServer.FindAllStringSubmatch("host(51.158.139.25) host(2001:db8::53) 9.9.9.9", -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != "51.158.139.25,2001:db8::53,9.9.9.9" {
		t.Error(got)
	}
}

func TestTypoSuggestion(t *testing.T) {
	for in, want := range map[string]string{"gmial.com": "gmail.com", "gmx.dee": "gmx.de", "web.de": "", "example.org": "", "outlok.com": "outlook.com"} {
		if got := typoSuggestion(in); got != want {
			t.Errorf("typoSuggestion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMacTable(t *testing.T) {
	path := t.TempDir() + "/manuf"
	data := "# comment\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.\nFC:FB:FB\tCisco\tCisco Systems, Inc\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	table, err := loadManuf(path)
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"00-00-0c-12-34-56": "Cisco Systems, Inc", "001B.C500.0123": "Converging Systems Inc.", "fcfbfb": "Cisco Systems, Inc", "00:1B:C5:F0:00:00": ""} {
		v, ok := macValue(in)
		if !ok {
			t.Fatalf("macValue(%q) failed", in)
		}
		if got, _ := table.lookup(v); got != want {
			t.Errorf("lookup(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"xyz", "00:11", "00:11:22:33:44:55:66"} {
		if _, ok := macValue(bad); ok {
			t.Errorf("macValue(%q) accepted", bad)
		}
	}
}

func TestEmailCheckRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "foo", "a@b", "a@localhost", "a b@example.com"} {
		if _, err := emailCheck(context.Background(), url.Values{"q": {in}}); err == nil {
			t.Errorf("emailCheck(%q) accepted", in)
		}
	}
}
