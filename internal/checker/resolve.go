package checker

import (
	"bufio"
	"context"
	"errors"
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
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
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
			found, err := query(ctx, name, qtype)
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

var extServer = regexp.MustCompile(`(?:host\()?([0-9A-Fa-f:.]+)\)?`)

// nameservers returns the DNS servers to ask. Docker's embedded DNS (127.0.0.11)
// also answers container hostnames with internal addresses, so the upstream
// servers Docker notes in the "ExtServers" comment are preferred.
func nameservers() []string {
	var servers, upstream []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if list, ok := strings.CutPrefix(line, "# ExtServers:"); ok {
				for _, m := range extServer.FindAllStringSubmatch(strings.Trim(strings.TrimSpace(list), "[]"), -1) {
					if addr, err := netip.ParseAddr(m[1]); err == nil {
						upstream = append(upstream, net.JoinHostPort(addr.String(), "53"))
					}
				}
			} else if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" {
				servers = append(servers, net.JoinHostPort(fields[1], "53"))
			}
		}
	}
	if len(upstream) > 0 {
		return upstream
	}
	if len(servers) == 0 {
		servers = []string{"127.0.0.1:53"}
	}
	return servers
}

func query(ctx context.Context, name dnsmessage.Name, qtype dnsmessage.Type) ([]netip.Addr, error) {
	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packet, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, server := range nameservers() {
		addrs, err := exchange(ctx, server, packet, id, qtype)
		if err == nil {
			return addrs, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func exchange(ctx context.Context, server string, packet []byte, id uint16, qtype dnsmessage.Type) ([]netip.Addr, error) {
	// The resolver itself may live on a local address (Docker uses 127.0.0.11),
	// so this connection deliberately does not use the public-only dialer.
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(buf[:n]); err != nil || reply.ID != id {
			continue
		}
		if reply.RCode == dnsmessage.RCodeNameError {
			return nil, nil
		}
		if reply.RCode != dnsmessage.RCodeSuccess {
			return nil, errors.New("DNS server answered " + reply.RCode.String())
		}
		var addrs []netip.Addr
		for _, answer := range reply.Answers {
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				if qtype == dnsmessage.TypeA {
					addrs = append(addrs, netip.AddrFrom4(body.A))
				}
			case *dnsmessage.AAAAResource:
				if qtype == dnsmessage.TypeAAAA {
					addrs = append(addrs, netip.AddrFrom16(body.AAAA))
				}
			}
		}
		return addrs, nil
	}
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
