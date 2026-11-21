package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// cymruName returns the Team Cymru DNS name used to look up the origin ASN of an address.
func cymruName(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := addr.As16()
	nibbles := make([]string, 0, 32)
	for i := len(b) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x", b[i]&0x0f), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(nibbles, ".") + ".origin6.asn.cymru.com"
}

func cymruFields(records []string) []string {
	if len(records) == 0 {
		return nil
	}
	fields := strings.Split(records[0], "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields
}

func ipLookup(ctx context.Context, q url.Values) (*Result, error) {
	input := strings.TrimSpace(q.Get("q"))
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(input); err == nil {
		addrs = []netip.Addr{addr.Unmap()}
	} else {
		domain, err := normalizeDomain(input)
		if err != nil {
			return nil, fail("Please enter an IP address or domain.", "Bitte gib eine IP-Adresse oder Domain ein.")
		}
		ips, err := lookupIPs(ctx, domain)
		if err != nil {
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
				return nil, err
			}
			return nil, fail("The domain has no A or AAAA record.", "Die Domain hat keinen A- oder AAAA-Eintrag.")
		}
		for _, ip := range ips {
			if ip = ip.Unmap(); isPublic(ip) && !slices.Contains(addrs, ip) && len(addrs) < 4 {
				addrs = append(addrs, ip)
			}
		}
	}
	if len(addrs) == 0 || !slices.ContainsFunc(addrs, isPublic) {
		return nil, fail("Only public IP addresses can be checked.", "Es können nur öffentliche IP-Adressen geprüft werden.")
	}

	result := &Result{}
	for _, addr := range addrs {
		section := Section{Title: T(addr.String(), addr.String())}
		version := "IPv4"
		if addr.Is6() {
			version = "IPv6"
		}
		section.Rows = append(section.Rows, row("Version", "Version", version))

		names, _ := resolver.LookupAddr(ctx, addr.String())
		if len(names) == 0 {
			section.Rows = append(section.Rows, noteRow("Reverse DNS (PTR)", "Reverse DNS (PTR)", "none – mail servers need one", "keiner – Mailserver brauchen einen", "warn"))
		} else {
			ptr := strings.TrimSuffix(names[0], ".")
			section.Rows = append(section.Rows, row("Reverse DNS (PTR)", "Reverse DNS (PTR)", ptr))
			forward, err := lookupIPs(ctx, ptr)
			var dnsErr *dnsUnavailable
			if errors.As(err, &dnsErr) {
				section.Rows = append(section.Rows, dnsMissing("Forward-confirmed (FCrDNS)", "Vorwärts bestätigt (FCrDNS)"))
			} else if slices.ContainsFunc(forward, func(ip netip.Addr) bool { return ip.Unmap() == addr }) {
				section.Rows = append(section.Rows, noteRow("Forward-confirmed (FCrDNS)", "Vorwärts bestätigt (FCrDNS)", "yes", "ja", "ok"))
			} else {
				section.Rows = append(section.Rows, noteRow("Forward-confirmed (FCrDNS)", "Vorwärts bestätigt (FCrDNS)", "no – PTR name does not point back", "nein – der PTR-Name zeigt nicht zurück", "warn"))
			}
		}

		origin := cymruFields(lookupTXT(ctx, cymruName(addr)))
		if len(origin) >= 5 {
			asn := strings.Fields(origin[0])[0]
			section.Rows = append(section.Rows,
				row("Network (prefix)", "Netz (Präfix)", origin[1]),
				row("ASN", "ASN", "AS"+asn),
				row("Country", "Land", origin[2]),
				row("Registry", "Registry", strings.ToUpper(origin[3])),
				row("Allocated", "Vergeben", origin[4]))
			if as := cymruFields(lookupTXT(ctx, "AS"+asn+".asn.cymru.com")); len(as) >= 5 {
				section.Rows = append(section.Rows, row("Network operator", "Netzbetreiber", as[4]))
			}
		}
		result.Sections = append(result.Sections, section)
	}
	return result, nil
}
