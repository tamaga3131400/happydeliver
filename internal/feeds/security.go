package feeds

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The security overview lists the most relevant recent vulnerabilities per
// area. It deliberately contains no links and no exploit identifiers: it is
// meant to tell administrators what to patch, not where to find exploits.

type Text [2]string

type Item struct {
	Title           string   `json:"title"`
	Platform        string   `json:"platform,omitempty"`
	Date            string   `json:"date"`
	CVEs            []string `json:"cves,omitempty"`
	CVSS            float64  `json:"cvss,omitempty"`
	EPSS            float64  `json:"epss,omitempty"` // probability of exploitation in the next 30 days, 0..1
	Exploited       bool     `json:"exploited,omitempty"`
	Ransomware      bool     `json:"ransomware,omitempty"`
	PublicExploit   bool     `json:"public_exploit,omitempty"`
	Unauthenticated bool     `json:"unauthenticated,omitempty"`
	Action          Text     `json:"action"`
	score           float64
}

type Category struct {
	Key   string `json:"key"`
	Title Text   `json:"title"`
	Info  Text   `json:"info"`
	Items []Item `json:"items"`
}

type Overview struct {
	Updated    time.Time  `json:"updated"`
	Categories []Category `json:"categories"`
}

type Security struct {
	store    *Store
	mu       sync.RWMutex
	overview *Overview
	pending  chan struct{}
}

func NewSecurity(store *Store) *Security {
	s := &Security{store: store, pending: make(chan struct{}, 1)}
	if b, err := os.ReadFile(store.Path("security-overview.json")); err == nil {
		var o Overview
		if json.Unmarshal(b, &o) == nil {
			s.overview = &o
		}
	}
	trigger := func(string) {
		select {
		case s.pending <- struct{}{}:
		default:
		}
	}
	store.Watch("exploitdb.csv", trigger)
	store.Watch("kev.json", trigger)
	return s
}

// Current returns the latest overview or nil while it is being built.
func (s *Security) Current() *Overview {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.overview
}

// Run rebuilds the overview after feed updates and at least once a day.
func (s *Security) Run(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.pending:
			case <-ticker.C:
				if o := s.Current(); o != nil && time.Since(o.Updated) < 24*time.Hour {
					continue
				}
			}
			// Both feeds usually change together; wait briefly to build once.
			time.Sleep(30 * time.Second)
			select {
			case <-s.pending:
			default:
			}
			// A restart reports the existing files again; skip if nothing changed.
			if o := s.Current(); o != nil && time.Since(o.Updated) < 24*time.Hour && !s.feedsNewerThan(o.Updated) && o.complete() {
				continue
			}
			if err := s.build(ctx); err != nil {
				log.Printf("security overview: %v", err)
			}
		}
	}()
}

// complete reports whether every category has entries (an empty WordPress
// list usually means NVD was unreachable during the last build).
func (o *Overview) complete() bool {
	for _, c := range o.Categories {
		if c.Key == "wordpress" && len(c.Items) == 0 {
			return false
		}
	}
	return true
}

func (s *Security) feedsNewerThan(t time.Time) bool {
	for _, name := range []string{"exploitdb.csv", "kev.json"} {
		if info, err := os.Stat(s.store.Path(name)); err == nil && info.ModTime().After(t) {
			return true
		}
	}
	return false
}

type kevEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

func (s *Security) build(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	kev := map[string]kevEntry{}
	var kevList []kevEntry
	if b, err := os.ReadFile(s.store.Path("kev.json")); err == nil {
		var doc struct {
			Vulnerabilities []kevEntry `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &doc); err == nil {
			kevList = doc.Vulnerabilities
			for _, e := range kevList {
				kev[e.CVE] = e
			}
		}
	}

	f, err := os.Open(s.store.Path("exploitdb.csv"))
	if err != nil {
		return err
	}
	// Two years for mail servers, one year for everything else (filtered in assemble).
	exploits, err := parseExploitDB(f, time.Now().AddDate(-2, 0, 0))
	f.Close()
	if err != nil {
		return err
	}

	wordpress, err := fetchWordPress(ctx, time.Now())
	if err != nil {
		log.Printf("security overview: NVD: %v (retrying in 30s)", err)
		time.Sleep(30 * time.Second)
		wordpress, err = fetchWordPress(ctx, time.Now())
		if err != nil {
			log.Printf("security overview: NVD: %v", err)
		}
	}

	// Collect CVEs for EPSS.
	var cves []string
	for _, e := range exploits {
		cves = append(cves, e.cves...)
	}
	for _, w := range wordpress {
		cves = append(cves, w.CVEs...)
	}
	recentKEV := recentKEV(kevList, time.Now().AddDate(0, 0, -60))
	mailKEV := mailKEV(kevList, time.Now().AddDate(-2, 0, 0))
	for _, k := range append(recentKEV, mailKEV...) {
		cves = append(cves, k.CVE)
	}
	epss := fetchEPSS(ctx, cves)

	overview := assemble(exploits, wordpress, recentKEV, mailKEV, kev, epss)
	overview.Updated = time.Now().UTC()
	// If NVD was unavailable, keep the previous WordPress list instead of showing none.
	if len(wordpress) == 0 {
		if previous := s.Current(); previous != nil {
			for _, old := range previous.Categories {
				for i := range overview.Categories {
					if old.Key == "wordpress" && overview.Categories[i].Key == "wordpress" && len(old.Items) > 0 {
						overview.Categories[i].Items = old.Items
					}
				}
			}
		}
	}

	if b, err := json.Marshal(overview); err == nil {
		tmp := s.store.Path("security-overview.json.tmp")
		if os.WriteFile(tmp, b, 0o640) == nil {
			_ = os.Rename(tmp, s.store.Path("security-overview.json"))
		}
	}
	s.mu.Lock()
	s.overview = overview
	s.mu.Unlock()
	log.Printf("security overview: rebuilt from %d exploits, %d WordPress CVEs", len(exploits), len(wordpress))
	return nil
}

// Exploit-DB

type exploit struct {
	description, kind, platform string
	date                        time.Time
	verified                    bool
	cves                        []string
}

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func parseExploitDB(r io.Reader, since time.Time) ([]exploit, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, name := range header {
		col[name] = i
	}
	for _, name := range []string{"description", "date_published", "type", "platform", "verified", "codes"} {
		if _, ok := col[name]; !ok {
			return nil, fmt.Errorf("exploitdb.csv: column %q missing", name)
		}
	}
	var out []exploit
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) <= col["codes"] {
			continue
		}
		date, err := time.Parse("2006-01-02", rec[col["date_published"]])
		if err != nil || date.Before(since) {
			continue
		}
		out = append(out, exploit{
			description: strings.Join(strings.Fields(rec[col["description"]]), " "),
			kind:        rec[col["type"]],
			platform:    rec[col["platform"]],
			date:        date,
			verified:    rec[col["verified"]] == "1",
			cves:        cvePattern.FindAllString(rec[col["codes"]], -1),
		})
	}
	return out, nil
}

var mailPattern = regexp.MustCompile(`(?i)\b(exim|postfix|dovecot|sendmail|microsoft exchange|exchange server|zimbra|roundcube|horde|rainloop|snappymail|squirrelmail|smartermail|mdaemon|hmailserver|qmail|courier-imap|axigen|icewarp|kerio connect|mailenable|webmail|smtp|imap|pop3|mailcow|iredmail|mailman)\b`)

func isWordPress(description string) bool {
	return strings.Contains(strings.ToLower(description), "wordpress")
}

// NVD (WordPress)

type wpCVE struct {
	ID              string
	CVEs            []string
	Title           string
	CVSS            float64
	Published       time.Time
	Unauthenticated bool
	UpTo            string
}

var (
	wpSubject = regexp.MustCompile(`(?i)^The (.{1,120}?) (plugin|theme) for WordPress`)
	wpUpTo    = regexp.MustCompile(`(?i)(?:up to,? and including,?|versions? up to|before|prior to|<=)\s*v?([0-9][0-9A-Za-z.\-]*)`)
	wpFlaw    = regexp.MustCompile(`(?i)is vulnerable to ([^.]{3,90}?)(?: in all versions| in versions| via | due to|\.|$)`)
)

func fetchWordPress(ctx context.Context, now time.Time) ([]wpCVE, error) {
	client := &http.Client{Timeout: 2 * time.Minute}
	start := now.AddDate(0, 0, -90)
	var out []wpCVE
	for index := 0; ; {
		q := url.Values{
			"keywordSearch":  {"WordPress"},
			"pubStartDate":   {start.UTC().Format("2006-01-02T15:04:05.000")},
			"pubEndDate":     {now.UTC().Format("2006-01-02T15:04:05.000")},
			"resultsPerPage": {"2000"},
			"startIndex":     {strconv.Itoa(index)},
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0?"+q.Encode(), nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		var page nvdPage
		err = json.NewDecoder(io.LimitReader(resp.Body, 128<<20)).Decode(&page)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("NVD answered %s", resp.Status)
		}
		if err != nil {
			return out, err
		}
		for _, v := range page.Vulnerabilities {
			if w, ok := v.CVE.wordpress(); ok {
				out = append(out, w)
			}
		}
		index += page.ResultsPerPage
		if page.ResultsPerPage == 0 || index >= page.TotalResults {
			return out, nil
		}
		// NVD asks clients without an API key to pause between requests.
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(7 * time.Second):
		}
	}
}

type nvdPage struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]nvdMetric `json:"metrics"`
}

func (c nvdCVE) score() float64 {
	best := 0.0
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV40"} {
		for _, m := range c.Metrics[key] {
			if m.Type == "Primary" {
				return m.CVSSData.BaseScore
			}
			best = math.Max(best, m.CVSSData.BaseScore)
		}
		if best > 0 {
			return best
		}
	}
	return best
}

func (c nvdCVE) wordpress() (wpCVE, bool) {
	if c.VulnStatus == "Rejected" {
		return wpCVE{}, false
	}
	desc := ""
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
		}
	}
	subject := wpSubject.FindStringSubmatch(desc)
	if subject == nil && !strings.HasPrefix(desc, "WordPress") {
		return wpCVE{}, false
	}
	score := c.score()
	if score < 7.0 {
		return wpCVE{}, false
	}
	published, _ := time.Parse("2006-01-02T15:04:05.000", c.Published)
	w := wpCVE{ID: c.ID, CVEs: []string{c.ID}, CVSS: score, Published: published,
		Unauthenticated: strings.Contains(strings.ToLower(desc), "unauthenticated")}
	if subject != nil {
		kind := "Plugin"
		if strings.EqualFold(subject[2], "theme") {
			kind = "Theme"
		}
		w.Title = subject[1] + " (" + kind + ")"
	} else {
		w.Title = "WordPress"
	}
	if flaw := wpFlaw.FindStringSubmatch(desc); flaw != nil {
		w.Title += " – " + strings.TrimSpace(flaw[1])
	}
	if m := wpUpTo.FindStringSubmatch(desc); m != nil {
		w.UpTo = strings.TrimRight(m[1], ".")
	}
	return w, true
}

// EPSS

func fetchEPSS(ctx context.Context, cves []string) map[string]float64 {
	slices.Sort(cves)
	cves = slices.Compact(cves)
	out := map[string]float64{}
	client := &http.Client{Timeout: time.Minute}
	for i := 0; i < len(cves); i += 100 {
		batch := cves[i:min(i+100, len(cves))]
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://api.first.org/data/v1/epss?cve="+strings.Join(batch, ","), nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("security overview: EPSS: %v", err)
			return out
		}
		var doc struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&doc)
		resp.Body.Close()
		for _, d := range doc.Data {
			if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = v
			}
		}
		time.Sleep(time.Second)
	}
	return out
}

func recentKEV(list []kevEntry, since time.Time) []kevEntry {
	var out []kevEntry
	for _, e := range list {
		if d, err := time.Parse("2006-01-02", e.DateAdded); err == nil && !d.Before(since) {
			out = append(out, e)
		}
	}
	return out
}

func mailKEV(list []kevEntry, since time.Time) []kevEntry {
	var out []kevEntry
	for _, e := range recentKEV(list, since) {
		if mailPattern.MatchString(e.Vendor + " " + e.Product + " " + e.Name) {
			out = append(out, e)
		}
	}
	return out
}

// Ranking

var (
	actionExploited = Text{"Apply the vendor update immediately – this is being exploited in the wild.", "Update des Herstellers sofort einspielen – wird bereits aktiv ausgenutzt."}
	actionUpdate    = Text{"Install the vendor update or apply the vendor's workaround.", "Update des Herstellers einspielen oder dessen Schutzmaßnahme umsetzen."}
	actionNoCVE     = Text{"Check whether you use this software and update it to the latest version.", "Prüfen, ob die Software eingesetzt wird, und auf die neueste Version aktualisieren."}
)

func scoreOf(exploited, ransomware, verified, publicExploit bool, epss, cvss float64, date, now time.Time, window time.Duration) float64 {
	s := epss * 50
	if exploited {
		s += 100
	}
	if ransomware {
		s += 10
	}
	if verified {
		s += 5
	}
	if publicExploit {
		s += 15
	}
	s += cvss
	age := now.Sub(date)
	if age < window {
		s += 10 * (1 - float64(age)/float64(window))
	}
	return s
}

func assemble(exploits []exploit, wordpress []wpCVE, kevRecent, kevMail []kevEntry, kev map[string]kevEntry, epss map[string]float64) *Overview {
	now := time.Now()
	year := 365 * 24 * time.Hour
	categories := []Category{
		{Key: "exploited", Title: Text{"Actively exploited right now", "Aktuell aktiv ausgenutzt"},
			Info: Text{"Added to the CISA catalogue of exploited vulnerabilities in the last 60 days.", "In den letzten 60 Tagen in den CISA-Katalog ausgenutzter Schwachstellen aufgenommen."}},
		{Key: "mail", Title: Text{"Mail and webmail servers", "Mail- und Webmail-Server"},
			Info: Text{"Exim, Postfix, Dovecot, Exchange, Zimbra, Roundcube and similar, from the last two years.", "Exim, Postfix, Dovecot, Exchange, Zimbra, Roundcube und ähnliche aus den letzten zwei Jahren."}},
		{Key: "wordpress", Title: Text{"WordPress (CVSS 7.0 or higher)", "WordPress (CVSS ab 7.0)"},
			Info: Text{"Plugins, themes and core from the last 90 days.", "Plugins, Themes und Kern aus den letzten 90 Tagen."}},
		{Key: "webapps", Title: Text{"Web applications", "Webanwendungen"},
			Info: Text{"CMS, shops, admin panels and other web software.", "CMS, Shops, Admin-Oberflächen und andere Websoftware."}},
		{Key: "remote", Title: Text{"Network services (remote)", "Netzwerkdienste (aus der Ferne)"},
			Info: Text{"Attackable over the network without local access.", "Über das Netzwerk angreifbar, ohne lokalen Zugang."}},
		{Key: "local", Title: Text{"Privilege escalation (local)", "Rechteausweitung (lokal)"},
			Info: Text{"Lets a logged-in user gain administrator rights.", "Ermöglicht angemeldeten Benutzern Administratorrechte."}},
		{Key: "hardware", Title: Text{"Routers, cameras and IoT", "Router, Kameras und IoT"},
			Info: Text{"Firmware of network and embedded devices.", "Firmware von Netzwerk- und Embedded-Geräten."}},
	}
	byKey := map[string]*Category{}
	for i := range categories {
		byKey[categories[i].Key] = &categories[i]
	}

	maxEPSS := func(cves []string) float64 {
		m := 0.0
		for _, c := range cves {
			m = math.Max(m, epss[c])
		}
		return m
	}
	kevInfo := func(cves []string) (exploited, ransomware bool) {
		for _, c := range cves {
			if e, ok := kev[c]; ok {
				exploited = true
				ransomware = ransomware || e.Ransomware == "Known"
			}
		}
		return
	}

	wpWithExploit := map[string]bool{}
	for _, e := range exploits {
		key := ""
		switch {
		case e.kind == "dos":
			continue
		case isWordPress(e.description):
			for _, c := range e.cves {
				wpWithExploit[c] = true
			}
			continue
		case mailPattern.MatchString(e.description):
			key = "mail"
		case e.platform == "hardware":
			key = "hardware"
		case e.kind == "webapps":
			key = "webapps"
		case e.kind == "remote":
			key = "remote"
		case e.kind == "local":
			key = "local"
		default:
			continue
		}
		if key != "mail" && now.Sub(e.date) > year {
			continue
		}
		exploited, ransomware := kevInfo(e.cves)
		item := Item{
			Title: e.description, Platform: platformName(e.platform), Date: e.date.Format("2006-01-02"),
			CVEs: e.cves, EPSS: maxEPSS(e.cves), Exploited: exploited, Ransomware: ransomware, PublicExploit: true,
		}
		switch {
		case exploited:
			item.Action = actionExploited
		case len(e.cves) > 0:
			item.Action = actionUpdate
		default:
			item.Action = actionNoCVE
		}
		window := year
		if key == "mail" {
			window = 2 * year
		}
		item.score = scoreOf(exploited, ransomware, e.verified, false, item.EPSS, 0, e.date, now, window)
		byKey[key].Items = append(byKey[key].Items, item)
	}

	for _, w := range wordpress {
		exploited, ransomware := kevInfo(w.CVEs)
		item := Item{
			Title: w.Title, Platform: "WordPress", Date: w.Published.Format("2006-01-02"), CVEs: w.CVEs, CVSS: w.CVSS,
			EPSS: maxEPSS(w.CVEs), Exploited: exploited, Ransomware: ransomware, PublicExploit: wpWithExploit[w.ID],
			Unauthenticated: w.Unauthenticated,
		}
		if w.UpTo != "" {
			item.Action = Text{"Update to a version newer than " + w.UpTo + " (affected up to and including " + w.UpTo + "), or deactivate it until then.",
				"Auf eine Version nach " + w.UpTo + " aktualisieren (betroffen bis einschließlich " + w.UpTo + ") oder bis dahin deaktivieren."}
		} else {
			item.Action = Text{"Update to the latest version, or deactivate it until a fix is available.",
				"Auf die neueste Version aktualisieren oder bis zu einem Update deaktivieren."}
		}
		item.score = scoreOf(exploited, ransomware, false, item.PublicExploit, item.EPSS, w.CVSS, w.Published, now, 90*24*time.Hour)
		if w.Unauthenticated {
			item.score += 8
		}
		byKey["wordpress"].Items = append(byKey["wordpress"].Items, item)
	}

	for _, k := range kevRecent {
		date, _ := time.Parse("2006-01-02", k.DateAdded)
		item := Item{
			Title: strings.TrimSpace(k.Name), Platform: strings.TrimSpace(k.Vendor + " " + k.Product), Date: k.DateAdded,
			CVEs: []string{k.CVE}, EPSS: epss[k.CVE], Exploited: true, Ransomware: k.Ransomware == "Known", Action: actionExploited,
		}
		item.score = scoreOf(false, item.Ransomware, false, false, item.EPSS, 0, date, now, 60*24*time.Hour)
		byKey["exploited"].Items = append(byKey["exploited"].Items, item)
	}

	for _, k := range kevMail {
		date, _ := time.Parse("2006-01-02", k.DateAdded)
		item := Item{
			Title: strings.TrimSpace(k.Name), Platform: strings.TrimSpace(k.Vendor + " " + k.Product), Date: k.DateAdded,
			CVEs: []string{k.CVE}, EPSS: epss[k.CVE], Exploited: true, Ransomware: k.Ransomware == "Known", Action: actionExploited,
		}
		item.score = scoreOf(true, item.Ransomware, false, false, item.EPSS, 0, date, now, 2*year)
		byKey["mail"].Items = append(byKey["mail"].Items, item)
	}

	for i := range categories {
		items := categories[i].Items
		sort.SliceStable(items, func(a, b int) bool { return items[a].score > items[b].score })
		// One entry per vulnerability: keep the best ranked item for each CVE.
		seen := map[string]bool{}
		unique := items[:0]
		for _, it := range items {
			if slices.ContainsFunc(it.CVEs, func(c string) bool { return seen[c] }) {
				continue
			}
			for _, c := range it.CVEs {
				seen[c] = true
			}
			unique = append(unique, it)
		}
		categories[i].Items = append([]Item{}, unique[:min(10, len(unique))]...) // never null in JSON
	}
	return &Overview{Categories: categories}
}

var platformNames = map[string]string{
	"php": "PHP", "windows": "Windows", "windows_x86": "Windows", "windows_x86-64": "Windows", "linux": "Linux",
	"linux_x86": "Linux", "linux_x86-64": "Linux", "hardware": "Hardware", "multiple": "Multiple", "macos": "macOS",
	"android": "Android", "ios": "iOS", "java": "Java", "python": "Python", "nodejs": "Node.js", "go": "Go", "ruby": "Ruby",
	"asp": "ASP", "aspx": "ASP.NET", "jsp": "JSP", "cgi": "CGI", "freebsd": "FreeBSD", "solaris": "Solaris",
}

func platformName(p string) string {
	if name, ok := platformNames[p]; ok {
		return name
	}
	return p
}
