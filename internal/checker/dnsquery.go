package checker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Extra record types that dnsmessage does not name.
const (
	typeDS     dnsmessage.Type = 43
	typeRRSIG  dnsmessage.Type = 46
	typeDNSKEY dnsmessage.Type = 48
)

type dnsAsk struct {
	server    netip.Addr
	name      string
	qtype     dnsmessage.Type
	recursive bool // RD flag
	dnssec    bool // DO flag
	noCheck   bool // CD flag: ask a validating resolver to skip validation
}

func dnsRequest(q dnsAsk, id uint16) (dnsmessage.Message, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(q.name, ".") + ".")
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, q.dnssec); err != nil {
		return dnsmessage.Message{}, err
	}
	return dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, RecursionDesired: q.recursive, CheckingDisabled: q.noCheck},
		Questions:   []dnsmessage.Question{{Name: name, Type: q.qtype, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}},
	}, nil
}

func matchesDNSReply(reply *dnsmessage.Message, request dnsmessage.Message) bool {
	return reply.Response && reply.ID == request.ID && len(reply.Questions) == 1 &&
		strings.EqualFold(reply.Questions[0].Name.String(), request.Questions[0].Name.String()) &&
		reply.Questions[0].Type == request.Questions[0].Type && reply.Questions[0].Class == dnsmessage.ClassINET
}

// ask sends one DNS query over UDP and retries over TCP if the answer is truncated.
func ask(ctx context.Context, q dnsAsk) (*dnsmessage.Message, time.Duration, error) {
	msg, err := dnsRequest(q, uint16(time.Now().UnixNano()))
	if err != nil {
		return nil, 0, err
	}
	packet, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	server := net.JoinHostPort(q.server.String(), "53")
	start := time.Now()
	reply, err := askOver(ctx, "udp", server, packet, msg)
	if err == nil && reply.Truncated {
		reply, err = askOver(ctx, "tcp", server, packet, msg)
	}
	return reply, time.Since(start), err
}

func askOver(ctx context.Context, network, server string, packet []byte, request dnsmessage.Message) (*dnsmessage.Message, error) {
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if network == "tcp" {
		framed := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(framed, uint16(len(packet)))
		copy(framed[2:], packet)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		buf := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(buf); err != nil {
			return nil, err
		}
		if !matchesDNSReply(&reply, request) {
			return nil, errors.New("unexpected DNS answer")
		}
		return &reply, nil
	}

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
		if reply.Unpack(buf[:n]) == nil && matchesDNSReply(&reply, request) {
			return &reply, nil
		}
	}
}

// recordText renders the answers of the requested type as sorted text values.
func recordText(msg *dnsmessage.Message, qtype dnsmessage.Type) []string {
	var out []string
	for _, a := range msg.Answers {
		if a.Header.Type != qtype {
			continue
		}
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A).String())
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA).String())
		case *dnsmessage.MXResource:
			out = append(out, fmt.Sprintf("%d %s", b.Pref, strings.TrimSuffix(b.MX.String(), ".")))
		case *dnsmessage.NSResource:
			out = append(out, strings.TrimSuffix(b.NS.String(), "."))
		case *dnsmessage.CNAMEResource:
			out = append(out, strings.TrimSuffix(b.CNAME.String(), "."))
		case *dnsmessage.TXTResource:
			out = append(out, strings.Join(b.TXT, ""))
		case *dnsmessage.UnknownResource:
			out = append(out, fmt.Sprintf("%x", b.Data))
		}
	}
	return out
}

// countType counts answer records of a type (also for types dnsmessage does not parse).
func countType(msg *dnsmessage.Message, t dnsmessage.Type) int {
	n := 0
	for _, a := range msg.Answers {
		if a.Header.Type == t {
			n++
		}
	}
	return n
}

func unknownData(msg *dnsmessage.Message, t dnsmessage.Type) [][]byte {
	var out [][]byte
	for _, a := range msg.Answers {
		if b, ok := a.Body.(*dnsmessage.UnknownResource); ok && a.Header.Type == t {
			out = append(out, b.Data)
		}
	}
	return out
}
