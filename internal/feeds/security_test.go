package feeds

import (
	"strings"
	"testing"
	"time"
)

const csvFixture = `id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url
1,exploits/php/webapps/1.txt,"Shop Script 1.0 - SQL Injection",2026-10-01,a,webapps,php,,2026-10-01,2026-10-01,1,CVE-2026-1001,,,,,
2,exploits/linux/remote/2.py,"Exim 4.97 - Remote Code Execution",2026-09-01,a,remote,linux,25,2026-09-01,2026-09-01,0,CVE-2026-1002;OSVDB-1,,,,,
3,exploits/php/webapps/3.txt,"WordPress Plugin Forms 2.1 - Unauthenticated File Upload",2026-08-01,a,webapps,php,,2026-08-01,2026-08-01,0,CVE-2026-1003,,,,,
4,exploits/hardware/remote/4.txt,"Router X - Command Injection",2026-07-01,a,remote,hardware,,2026-07-01,2026-07-01,0,,,,,,
5,exploits/windows/dos/5.txt,"Some Server - Denial of Service",2026-10-02,a,dos,windows,,2026-10-02,2026-10-02,0,CVE-2026-1005,,,,,
6,exploits/php/webapps/6.txt,"Old App - XSS",2019-01-01,a,webapps,php,,2019-01-01,2019-01-01,0,CVE-2019-1,,,,,
7,exploits/php/webapps/7.txt,"Courier Management System 1.0 - SQLi",2026-10-03,a,webapps,php,,2026-10-03,2026-10-03,0,,,,,,
`

func TestParseAndAssemble(t *testing.T) {
	exploits, err := parseExploitDB(strings.NewReader(csvFixture), time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(exploits) != 6 {
		t.Fatalf("parse: %d, %v", len(exploits), err)
	}
	if got := exploits[1].cves; len(got) != 1 || got[0] != "CVE-2026-1002" {
		t.Fatalf("cves: %v", got)
	}
	wp := []wpCVE{
		{ID: "CVE-2026-1003", CVEs: []string{"CVE-2026-1003"}, Title: "Forms (Plugin) – Arbitrary File Upload", CVSS: 9.8, Published: time.Now(), Unauthenticated: true, UpTo: "2.1"},
		{ID: "CVE-2026-2000", CVEs: []string{"CVE-2026-2000"}, Title: "Gallery (Plugin) – XSS", CVSS: 7.2, Published: time.Now()},
	}
	kev := map[string]kevEntry{"CVE-2026-1002": {CVE: "CVE-2026-1002", Ransomware: "Known"}}
	o := assemble(exploits, wp, nil, nil, kev, map[string]float64{"CVE-2026-1001": 0.5})

	cat := map[string]Category{}
	for _, c := range o.Categories {
		cat[c.Key] = c
	}
	if items := cat["mail"].Items; len(items) != 1 || !items[0].Exploited || !items[0].Ransomware || items[0].Action != actionExploited {
		t.Errorf("mail: %+v", items)
	}
	if items := cat["webapps"].Items; len(items) != 2 || items[0].EPSS != 0.5 {
		t.Errorf("webapps (WordPress must be excluded, courier is no mail server): %+v", items)
	}
	if items := cat["hardware"].Items; len(items) != 1 || items[0].Action != actionNoCVE {
		t.Errorf("hardware: %+v", items)
	}
	if items := cat["wordpress"].Items; len(items) != 2 || items[0].Title != wp[0].Title || !items[0].PublicExploit || !strings.Contains(items[0].Action[1], "2.1") {
		t.Errorf("wordpress: %+v", items)
	}
	for _, c := range o.Categories {
		for _, it := range c.Items {
			if strings.Contains(it.Title, "Denial of Service") || strings.Contains(it.Title, "Old App") {
				t.Errorf("unexpected item %q in %s", it.Title, c.Key)
			}
		}
	}
}

func TestDeduplicateAndMailKEV(t *testing.T) {
	now := time.Now()
	dup := []exploit{
		{description: "Win - Spoof A", kind: "remote", platform: "windows", date: now.AddDate(0, -1, 0), cves: []string{"CVE-1"}},
		{description: "Win - Spoof B", kind: "remote", platform: "windows", date: now.AddDate(0, -2, 0), cves: []string{"CVE-1"}},
	}
	mail := []kevEntry{{CVE: "CVE-9", Vendor: "Synacor", Product: "Zimbra Collaboration Suite", Name: "Zimbra XSS", DateAdded: now.AddDate(0, -3, 0).Format("2006-01-02")}}
	if got := mailKEV(append(mail, kevEntry{CVE: "CVE-8", Vendor: "Acme", Product: "Shop", DateAdded: mail[0].DateAdded}), now.AddDate(-2, 0, 0)); len(got) != 1 {
		t.Fatalf("mailKEV: %+v", got)
	}
	o := assemble(dup, nil, nil, mail, map[string]kevEntry{}, nil)
	for _, c := range o.Categories {
		switch c.Key {
		case "remote":
			if len(c.Items) != 1 || c.Items[0].Title != "Win - Spoof A" {
				t.Errorf("remote: %+v", c.Items)
			}
		case "mail":
			if len(c.Items) != 1 || !c.Items[0].Exploited {
				t.Errorf("mail: %+v", c.Items)
			}
		}
	}
}

func TestEmptyCategoriesAreLists(t *testing.T) {
	o := assemble(nil, nil, nil, nil, map[string]kevEntry{}, nil)
	for _, c := range o.Categories {
		if c.Items == nil {
			t.Errorf("%s: items must be an empty list, not nil", c.Key)
		}
	}
}

func TestWordPressFromNVD(t *testing.T) {
	c := nvdCVE{ID: "CVE-2026-5", Published: "2026-11-01T10:00:00.000",
		Descriptions: []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		}{{Lang: "en", Value: "The Super Forms plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 3.4.1. This makes it possible for unauthenticated attackers to upload files."}},
		Metrics: map[string][]nvdMetric{"cvssMetricV31": {{Type: "Secondary"}}},
	}
	c.Metrics["cvssMetricV31"][0].CVSSData.BaseScore = 9.8
	w, ok := c.wordpress()
	if !ok || w.Title != "Super Forms (Plugin) – arbitrary file uploads" || w.UpTo != "3.4.1" || !w.Unauthenticated || w.CVSS != 9.8 {
		t.Fatalf("%+v %v", w, ok)
	}
	c.Metrics["cvssMetricV31"][0].CVSSData.BaseScore = 6.4
	if _, ok := c.wordpress(); ok {
		t.Error("CVSS below 7.0 must be skipped")
	}
}
