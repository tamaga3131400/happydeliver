package checker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dohResolver struct {
	url    string
	client *http.Client
}

func newDoH(host, path, ip string) dohResolver {
	// Bootstrap with the provider's published address so a DNS outage cannot
	// prevent the DNS-over-HTTPS connection. TLS still verifies the hostname.
	dial := dialer([]string{"443"})
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
		},
		ForceAttemptHTTP2: true,
	}
	return dohResolver{
		url: "https://" + host + path,
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

var dohResolvers = map[netip.Addr]dohResolver{
	netip.MustParseAddr("8.8.8.8"):        newDoH("dns.google", "/dns-query", "8.8.8.8"),
	netip.MustParseAddr("1.1.1.1"):        newDoH("cloudflare-dns.com", "/dns-query", "1.1.1.1"),
	netip.MustParseAddr("9.9.9.9"):        newDoH("dns.quad9.net", "/dns-query", "9.9.9.9"),
	netip.MustParseAddr("208.67.222.222"): newDoH("doh.opendns.com", "/dns-query", "146.112.41.2"),
	netip.MustParseAddr("94.140.14.14"):   newDoH("dns.adguard-dns.com", "/dns-query", "94.140.14.14"),
	netip.MustParseAddr("76.76.2.0"):      newDoH("freedns.controld.com", "/p0", "76.76.2.11"),
}

func (r dohResolver) ask(ctx context.Context, q dnsAsk) (*dnsmessage.Message, error) {
	msg, err := dnsRequest(q, 0)
	if err != nil {
		return nil, err
	}
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediaType != "application/dns-message" {
		return nil, fmt.Errorf("unexpected DNS-over-HTTPS response: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(body) > 65535 {
		return nil, fmt.Errorf("DNS response too large")
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	if !matchesDNSReply(&reply, msg) || reply.Truncated {
		return nil, fmt.Errorf("unexpected DNS answer")
	}
	return &reply, nil
}

// Recursive checks prefer HTTPS, which works on networks where port 53 is
// filtered. An authoritative check stays on the authoritative server.
func askPublic(ctx context.Context, q dnsAsk) (*dnsmessage.Message, time.Duration, error) {
	start := time.Now()
	if doh, ok := dohResolvers[q.server]; ok {
		if reply, err := doh.ask(ctx, q); err == nil {
			return reply, time.Since(start), nil
		}
	}
	attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	reply, _, err := ask(attempt, q)
	return reply, time.Since(start), err
}
