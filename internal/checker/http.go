package checker

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var webClient = httpClient(webPorts, 0)

// follow requests the URL and follows up to max redirects, validating every hop.
func follow(ctx context.Context, start *url.URL, max int) ([]Row, *http.Response, error) {
	var hops []Row
	seen := map[string]bool{}
	current := start
	for i := 0; ; i++ {
		begin := time.Now()
		resp, err := get(ctx, webClient, current.String(), "text/html,application/xhtml+xml,*/*;q=0.8")
		if err != nil {
			return hops, nil, err
		}
		took := time.Since(begin).Round(time.Millisecond)
		location := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			hops = append(hops, Row{Label: T(fmt.Sprintf("%d. %d", i+1, resp.StatusCode), fmt.Sprintf("%d. %d", i+1, resp.StatusCode)),
				Value: fmt.Sprintf("%s (%s)", current, took), Status: statusOf(resp.StatusCode)})
			return hops, resp, nil
		}
		resp.Body.Close()
		next, err := current.Parse(location)
		if err != nil {
			return hops, nil, fail("Invalid redirect target: "+location, "Ungültiges Weiterleitungsziel: "+location)
		}
		hops = append(hops, Row{Label: T(fmt.Sprintf("%d. %d", i+1, resp.StatusCode), fmt.Sprintf("%d. %d", i+1, resp.StatusCode)),
			Value: fmt.Sprintf("%s → %s (%s)", current, next, took)})
		seen[current.String()] = true
		if seen[next.String()] {
			return hops, nil, fail("Redirect loop detected.", "Weiterleitungsschleife erkannt.")
		}
		if i+1 >= max {
			return hops, nil, fail(fmt.Sprintf("More than %d redirects.", max), fmt.Sprintf("Mehr als %d Weiterleitungen.", max))
		}
		if current, err = normalizeURL(next.String()); err != nil {
			return hops, nil, err
		}
	}
}

func statusOf(code int) string {
	switch {
	case code < 300:
		return "ok"
	case code < 400:
		return ""
	case code < 500:
		return "warn"
	default:
		return "bad"
	}
}

func httpHeaders(ctx context.Context, q url.Values) (*Result, error) {
	target, err := normalizeURL(q.Get("q"))
	if err != nil {
		return nil, err
	}
	resp, err := get(ctx, webClient, target.String(), "")
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	response := Section{Title: T("Response", "Antwort"), Rows: []Row{
		row("URL", "URL", target.String()),
		row("Status", "Status", resp.Status, statusOf(resp.StatusCode)),
		row("Protocol", "Protokoll", resp.Proto),
	}}
	headers := Section{Title: T("Headers", "Header")}
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		headers.Rows = append(headers.Rows, Row{Label: T(name, name), Value: strings.Join(resp.Header.Values(name), "\n")})
	}

	h := resp.Header
	security := Section{Title: T("Security headers", "Sicherheits-Header")}
	present := func(en, de, name string, good func(string) bool) {
		value := h.Get(name)
		switch {
		case value == "":
			security.Rows = append(security.Rows, noteRow(en, de, "missing", "fehlt", "warn"))
		case good == nil || good(value):
			security.Rows = append(security.Rows, row(en, de, value, "ok"))
		default:
			security.Rows = append(security.Rows, row(en, de, value, "warn"))
		}
	}
	if target.Scheme == "https" {
		present("Strict-Transport-Security (HSTS)", "Strict-Transport-Security (HSTS)", "Strict-Transport-Security", nil)
	}
	present("Content-Security-Policy", "Content-Security-Policy", "Content-Security-Policy", nil)
	present("X-Content-Type-Options", "X-Content-Type-Options", "X-Content-Type-Options", func(v string) bool { return strings.EqualFold(v, "nosniff") })
	if strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors") {
		security.Rows = append(security.Rows, noteRow("Clickjacking protection", "Schutz vor Clickjacking", "via CSP frame-ancestors", "über CSP frame-ancestors", "ok"))
	} else {
		present("Clickjacking protection (X-Frame-Options)", "Schutz vor Clickjacking (X-Frame-Options)", "X-Frame-Options", nil)
	}
	present("Referrer-Policy", "Referrer-Policy", "Referrer-Policy", nil)
	present("Permissions-Policy", "Permissions-Policy", "Permissions-Policy", nil)
	for _, name := range []string{"Server", "X-Powered-By"} {
		if v := h.Get(name); strings.ContainsAny(v, "0123456789") {
			security.Rows = append(security.Rows, row(name+" reveals a version", name+" verrät eine Version", v, "warn"))
		}
	}
	return &Result{Sections: []Section{response, security, headers}}, nil
}

func redirectCheck(ctx context.Context, q url.Values) (*Result, error) {
	start, err := normalizeURL(q.Get("q"))
	if err != nil {
		return nil, err
	}
	hops, resp, err := follow(ctx, start, 10)
	if err != nil {
		if len(hops) == 0 {
			return nil, err
		}
		hops = append(hops, row("Stopped", "Abgebrochen", err.Error(), "bad"))
		return &Result{Sections: []Section{{Title: T("Redirect chain", "Weiterleitungskette"), Rows: hops}}}, nil
	}
	resp.Body.Close()
	chain := Section{Title: T("Redirect chain", "Weiterleitungskette"), Rows: hops}
	summary := Section{Title: T("Summary", "Zusammenfassung"), Rows: []Row{
		row("Final URL", "Ziel-URL", resp.Request.URL.String(), statusOf(resp.StatusCode)),
		row("Redirects", "Weiterleitungen", fmt.Sprint(len(hops)-1)),
	}}
	if len(hops) > 3 {
		summary.Rows = append(summary.Rows, noteRow("Hint", "Hinweis", "long chains slow down page loads", "lange Ketten verlangsamen das Laden", "warn"))
	}
	if start.Scheme == "http" && resp.Request.URL.Scheme != "https" {
		summary.Rows = append(summary.Rows, noteRow("HTTPS", "HTTPS", "no redirect to HTTPS", "keine Weiterleitung auf HTTPS", "warn"))
	}
	return &Result{Sections: []Section{summary, chain}}, nil
}

type page struct {
	title, lang, charset string
	meta                 [][2]string // name or property, content
	links                [][2]string // rel, href
}

func parsePage(r io.Reader) page {
	var p page
	z := html.NewTokenizer(r)
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return p
		case html.TextToken:
			if inTitle {
				p.title += string(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "title" {
				inTitle = false
			} else if string(name) == "head" {
				return p
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			switch string(name) {
			case "html":
				p.lang = attrs["lang"]
			case "title":
				inTitle = p.title == ""
			case "meta":
				if attrs["charset"] != "" {
					p.charset = attrs["charset"]
				}
				key := attrs["property"]
				if key == "" {
					key = attrs["name"]
				}
				if key != "" {
					p.meta = append(p.meta, [2]string{strings.ToLower(key), attrs["content"]})
				}
			case "link":
				if attrs["rel"] != "" && attrs["href"] != "" {
					p.links = append(p.links, [2]string{strings.ToLower(attrs["rel"]), attrs["href"]})
				}
			case "body":
				return p
			}
		}
	}
}

func lengthStatus(n, min, max int) string {
	if n >= min && n <= max {
		return "ok"
	}
	return "warn"
}

func metaTags(ctx context.Context, q url.Values) (*Result, error) {
	start, err := normalizeURL(q.Get("q"))
	if err != nil {
		return nil, err
	}
	_, resp, err := follow(ctx, start, 5)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fail("The page answered with "+resp.Status+".", "Die Seite antwortete mit "+resp.Status+".")
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/html" && mt != "application/xhtml+xml" {
		return nil, fail("The URL does not return an HTML page.", "Die URL liefert keine HTML-Seite.")
	}
	p := parsePage(io.LimitReader(resp.Body, 1<<20))
	get := func(key string) string {
		for _, m := range p.meta {
			if m[0] == key {
				return m[1]
			}
		}
		return ""
	}
	link := func(rel string) string {
		for _, l := range p.links {
			if slices.Contains(strings.Fields(l[0]), rel) {
				return l[1]
			}
		}
		return ""
	}

	title := strings.Join(strings.Fields(p.title), " ")
	description := get("description")
	basics := Section{Title: T("Basics", "Grundlagen"), Rows: []Row{row("URL", "URL", resp.Request.URL.String())}}
	if title == "" {
		basics.Rows = append(basics.Rows, noteRow("Title", "Titel", "missing", "fehlt", "bad"))
	} else {
		basics.Rows = append(basics.Rows, row(fmt.Sprintf("Title (%d chars, ideal 30–60)", len([]rune(title))),
			fmt.Sprintf("Titel (%d Zeichen, ideal 30–60)", len([]rune(title))), title, lengthStatus(len([]rune(title)), 30, 60)))
	}
	if description == "" {
		basics.Rows = append(basics.Rows, noteRow("Description", "Beschreibung", "missing", "fehlt", "warn"))
	} else {
		n := len([]rune(description))
		basics.Rows = append(basics.Rows, row(fmt.Sprintf("Description (%d chars, ideal 70–160)", n),
			fmt.Sprintf("Beschreibung (%d Zeichen, ideal 70–160)", n), description, lengthStatus(n, 70, 160)))
	}
	optional := func(en, de, value string, warn bool) {
		switch {
		case value != "":
			basics.Rows = append(basics.Rows, row(en, de, value, "ok"))
		case warn:
			basics.Rows = append(basics.Rows, noteRow(en, de, "missing", "fehlt", "warn"))
		}
	}
	optional("Canonical URL", "Kanonische URL", link("canonical"), true)
	optional("Language", "Sprache", p.lang, true)
	optional("Viewport", "Viewport", get("viewport"), true)
	optional("Charset", "Zeichensatz", p.charset, false)
	if robots := get("robots"); robots != "" {
		status := "ok"
		if strings.Contains(strings.ToLower(robots), "noindex") {
			status = "warn"
		}
		basics.Rows = append(basics.Rows, row("Robots", "Robots", robots, status))
	}
	optional("Theme colour", "Designfarbe", get("theme-color"), false)
	optional("Generator", "Generator", get("generator"), false)

	social := Section{Title: T("Social media (Open Graph, X/Twitter)", "Social Media (Open Graph, X/Twitter)")}
	for _, m := range p.meta {
		if strings.HasPrefix(m[0], "og:") || strings.HasPrefix(m[0], "twitter:") {
			r := Row{Label: T(m[0], m[0]), Value: m[1]}
			if m[0] == "og:image" || m[0] == "twitter:image" {
				if u, err := url.Parse(m[1]); err != nil || !u.IsAbs() {
					r.Status = "warn"
					r.Note = &Text{"relative URL – many platforms need an absolute URL", "relative URL – viele Plattformen brauchen eine vollständige URL"}
				}
			}
			social.Rows = append(social.Rows, r)
		}
	}
	for _, key := range []string{"og:title", "og:description", "og:image"} {
		if get(key) == "" {
			social.Rows = append(social.Rows, noteRow(key, key, "missing", "fehlt", "warn"))
		}
	}

	links := Section{Title: T("Icons and links", "Icons und Links")}
	for _, l := range p.links {
		if slices.ContainsFunc(strings.Fields(l[0]), func(rel string) bool {
			return slices.Contains([]string{"icon", "apple-touch-icon", "manifest", "alternate", "mask-icon"}, rel)
		}) {
			links.Rows = append(links.Rows, Row{Label: T(l[0], l[0]), Value: l[1]})
		}
	}

	sections := []Section{basics, social}
	if len(links.Rows) > 0 {
		sections = append(sections, links)
	}
	return &Result{Sections: sections}, nil
}
