package checker

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// lookupIPs resolves A and AAAA records directly over DNS. Unlike the system
// resolver it ignores /etc/hosts, where the container maps its own hostname
// (for example deliver.zenmail.eu) to an internal address.
func lookupIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		addrs []netip.Addr
		errs  []error
	)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found, err := query(ctx, host, qtype)
			mu.Lock()
			defer mu.Unlock()
			addrs = append(addrs, found...)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}
	wg.Wait()
	if len(addrs) == 0 {
		if len(errs) > 0 {
			return nil, errs[0]
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

var toolsDNSServers = flag.String("tools-dns-servers", "", "Comma-separated DNS resolver IPs for public tools")

var extServer = regexp.MustCompile(`(?:host\()?([0-9A-Fa-f:.]+)\)?`)

// nameservers returns explicitly configured resolvers or Docker's external
// DNS servers. The embedded Docker DNS can answer for its own container name,
// so public tools must not use it as an Internet DNS resolver.
func nameservers() []netip.Addr {
	if configured := strings.FieldsFunc(*toolsDNSServers, func(r rune) bool {
		return r == ',' || r == ' '
	}); len(configured) > 0 {
		var servers []netip.Addr
		for _, name := range configured {
			if addr, err := netip.ParseAddr(name); err == nil {
				servers = append(servers, addr)
			}
		}
		return servers
	}
	var servers, upstream []netip.Addr
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if list, ok := strings.CutPrefix(line, "# ExtServers:"); ok {
				for _, m := range extServer.FindAllStringSubmatch(strings.Trim(strings.TrimSpace(list), "[]"), -1) {
					if addr, err := netip.ParseAddr(m[1]); err == nil {
						upstream = append(upstream, addr)
					}
				}
			} else if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
				if addr, err := netip.ParseAddr(fields[1]); err == nil && addr.String() != "127.0.0.11" {
					servers = append(servers, addr)
				}
			}
		}
	}
	if len(upstream) > 0 {
		return upstream
	}
	return servers
}

type dnsUnavailable struct{ cause error }

func (e *dnsUnavailable) Error() string { return "DNS lookup unavailable: " + e.cause.Error() }
func (e *dnsUnavailable) Unwrap() error { return e.cause }

func publicDNS(ctx context.Context, name string, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	q := dnsAsk{name: name, qtype: qtype, recursive: true}
	var lastErr error
	for i, server := range nameservers() {
		if i == 2 {
			break
		}
		q.server = server
		attempt, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		reply, _, err := ask(attempt, q)
		cancel()
		if reply, err = usableDNS(reply, err); err == nil {
			return reply, nil
		}
		lastErr = err
	}
	for _, server := range publicResolvers[:2] {
		q.server = server.addr
		reply, err := dohResolvers[q.server].ask(ctx, q)
		if reply, err = usableDNS(reply, err); err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return nil, &dnsUnavailable{cause: lastErr}
}

func usableDNS(reply *dnsmessage.Message, err error) (*dnsmessage.Message, error) {
	if err != nil {
		return nil, err
	}
	switch reply.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
		return reply, nil
	default:
		return nil, fmt.Errorf("resolver answered %s", reply.RCode)
	}
}

func query(ctx context.Context, name string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	reply, err := publicDNS(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, value := range recordText(reply, qtype) {
		if addr, err := netip.ParseAddr(value); err == nil {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// dialContext resolves the host without /etc/hosts and connects only to public addresses.
func dialContext(d *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return d.DialContext(ctx, network, address)
		}
		addrs, err := lookupIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		lastErr := errBlocked
		for _, addr := range addrs {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
