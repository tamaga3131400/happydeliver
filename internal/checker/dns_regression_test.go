package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsFixture func(*http.Request) (*http.Response, error)

func (f dnsFixture) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func useDNSFixture(t *testing.T, fixture dnsFixture) {
	t.Helper()
	originalServers := *toolsDNSServers
	*toolsDNSServers = "fixture"
	t.Cleanup(func() { *toolsDNSServers = originalServers })
	for _, provider := range publicResolvers[:2] {
		addr := provider.addr
		original := dohResolvers[addr]
		dohResolvers[addr] = dohResolver{url: "https://dns.example.com/dns-query", client: &http.Client{Transport: fixture}}
		t.Cleanup(func() { dohResolvers[addr] = original })
	}
}

func TestDNSLookupThroughHTTPSFallback(t *testing.T) {
	useDNSFixture(t, func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, fmt.Errorf("unexpected DNS request: %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		var question dnsmessage.Message
		if err := question.Unpack(body); err != nil {
			return nil, err
		}
		q := question.Questions[0]
		answer := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: question.ID, Response: true},
			Questions: question.Questions,
		}
		name := q.Name.String()
		switch {
		case strings.Contains(name, "offline"):
			return nil, context.DeadlineExceeded
		case strings.Contains(name, "missing"):
			answer.RCode = dnsmessage.RCodeNameError
		case name == "web.example.com." && q.Type == dnsmessage.TypeA:
			answer.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
			}}
		case name == "alias.example.com." && q.Type == dnsmessage.TypeCNAME:
			answer.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("web.example.com.")},
			}}
		case name == "_dmarc.example.com." && q.Type == dnsmessage.TypeTXT:
			answer.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60},
				Body:   &dnsmessage.TXTResource{TXT: []string{"v=DMARC1; p=none"}},
			}}
		}
		wire, err := answer.Pack()
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/dns-message"}},
			Body:       io.NopCloser(bytes.NewReader(wire)),
		}, nil
	})
	router := gin.New()
	Register(router.Group("/tools"))
	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{
		{"web.example.com", 200, "192.0.2.1"},
		{"alias.example.com", 200, "web.example.com"},
		{"_dmarc.example.com", 200, "v=DMARC1; p=none"},
		{"empty.example.com", 200, "none of the queried record types"},
		{"missing.example.com", 400, "This DNS name does not exist"},
		{"offline.example.com", 502, "The DNS resolvers could not answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest("GET", "/tools/dns-lookup?q="+tc.name, nil))
			if recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), tc.want) {
				t.Fatalf("HTTP %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPropagationDoesNotTreatTimeoutAsDifference(t *testing.T) {
	_, allDown := summarizePropagation("example.com", "A", []propagationAnswer{{err: "no response"}, {err: "server failure"}})
	if allDown.Rows[0].Status != "bad" || !strings.Contains(allDown.Rows[0].Note[0], "No DNS server") {
		t.Fatal(allDown)
	}
	rows, partial := summarizePropagation("example.com", "A", []propagationAnswer{
		{auth: true, nx: true}, {nx: true}, {err: "no response"},
	})
	if rows.Rows[0].Status != "ok" || rows.Rows[2].Status != "warn" || partial.Rows[0].Status != "warn" {
		t.Fatalf("rows=%+v summary=%+v", rows, partial)
	}
}

func TestSubdomainFinderUsesSecondProvider(t *testing.T) {
	first := ctProvider{"first", func(ctx context.Context, domain string) ([]string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("provider without deadline")
		}
		return nil, errors.New("upstream unavailable")
	}}
	second := ctProvider{"second", func(ctx context.Context, domain string) ([]string, error) {
		return []string{"www." + domain}, nil
	}}
	names, source, err := ctNames(context.Background(), "example.com", []ctProvider{first, second})
	if err != nil || source != "second" || len(names) != 1 || names[0] != "www.example.com" {
		t.Fatalf("%v %s %v", names, source, err)
	}
}

func TestRDAPRegistryDomain(t *testing.T) {
	for host, expected := range map[string]string{
		"deliver.zenmail.eu": "zenmail.eu",
		"www.example.co.uk":  "example.co.uk",
		"project.github.io":  "github.io",
		"zenmail.eu":         "zenmail.eu",
	} {
		if got, ok := registrationDomain(host); !ok || got != expected {
			t.Errorf("%s: got %q, want %q", host, got, expected)
		}
	}
}
