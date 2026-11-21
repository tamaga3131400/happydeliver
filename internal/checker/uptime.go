package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
)

func uptimeCheck(ctx context.Context, q url.Values) (*Result, error) {
	target, err := normalizeURL(q.Get("q"))
	if err != nil {
		return nil, err
	}
	var start, connected, tlsStart, tlsDone, firstByte time.Time
	trace := &httptrace.ClientTrace{
		ConnectDone:          func(string, string, error) { connected = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	start = time.Now()
	resp, err := webClient.Do(req)
	if err != nil {
		var dnsErr *dnsUnavailable
		var noAddress *net.DNSError
		if errors.As(err, &dnsErr) || errors.As(err, &noAddress) || errors.Is(err, errBlocked) {
			return nil, err
		}
		down := Section{Title: T("Result", "Ergebnis"), Rows: []Row{
			noteRow("Status", "Status", "not reachable", "nicht erreichbar", "bad"),
			row("Error", "Fehler", err.Error()),
		}}
		return &Result{Sections: []Section{down}}, nil
	}
	resp.Body.Close()
	total := time.Since(start)

	ms := func(d time.Duration) string { return fmt.Sprintf("%d ms", d.Milliseconds()) }
	timing := Section{Title: T("Timing", "Zeiten")}
	if !connected.IsZero() {
		timing.Rows = append(timing.Rows, row("DNS and connection", "DNS und Verbindung", ms(connected.Sub(start))))
	}
	if !tlsDone.IsZero() && !tlsStart.IsZero() {
		timing.Rows = append(timing.Rows, row("TLS handshake", "TLS-Handshake", ms(tlsDone.Sub(tlsStart))))
	}
	if !firstByte.IsZero() {
		ttfb := firstByte.Sub(start)
		status := "ok"
		if ttfb > 1500*time.Millisecond {
			status = "warn"
		}
		timing.Rows = append(timing.Rows, row("First byte (TTFB)", "Erstes Byte (TTFB)", ms(ttfb), status))
	}
	timing.Rows = append(timing.Rows, row("Total", "Gesamt", ms(total)))

	result := Section{Title: T("Result", "Ergebnis"), Rows: []Row{row("URL", "URL", target.String())}}
	switch {
	case resp.StatusCode < 400:
		result.Rows = append(result.Rows, noteRow("Status", "Status", "reachable ("+resp.Status+")", "erreichbar ("+resp.Status+")", "ok"))
	case resp.StatusCode < 500:
		result.Rows = append(result.Rows, noteRow("Status", "Status", "reachable, but "+resp.Status, "erreichbar, aber "+resp.Status, "warn"))
	default:
		result.Rows = append(result.Rows, noteRow("Status", "Status", "server error ("+resp.Status+")", "Serverfehler ("+resp.Status+")", "bad"))
	}
	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Rows = append(result.Rows, row("Redirects to", "Leitet weiter zu", loc))
	}
	return &Result{Sections: []Section{result, timing}}, nil
}
