package checker

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"

	"git.happydns.org/happyDeliver/internal/feeds"
)

// Data loaded from the feed store. Each value is swapped atomically when the
// feed is updated, so checks never see a half-loaded list.
var (
	disposableDomains atomic.Pointer[map[string]bool]
	freemailDomains   atomic.Pointer[map[string]bool]
	macVendors        atomic.Pointer[macTable]
	geoDB             atomic.Pointer[maxminddb.Reader]
)

func watchFeeds(store *feeds.Store) {
	store.Watch("disposable.txt", func(path string) {
		if set, err := loadLines(path); err == nil {
			disposableDomains.Store(&set)
		}
	})
	store.Watch("freemail.json", func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var list []string
		if json.Unmarshal(b, &list) != nil {
			return
		}
		set := make(map[string]bool, len(list))
		for _, d := range list {
			set[strings.ToLower(strings.TrimSpace(d))] = true
		}
		freemailDomains.Store(&set)
	})
	store.Watch("manuf.txt", func(path string) {
		if t, err := loadManuf(path); err == nil {
			macVendors.Store(t)
		}
	})
	store.Watch("dbip-city.mmdb", func(path string) {
		db, err := maxminddb.Open(path)
		if err != nil {
			log.Printf("feeds: dbip-city.mmdb: %v", err)
			return
		}
		if old := geoDB.Swap(db); old != nil {
			// Give running lookups time to finish before unmapping the old file.
			time.AfterFunc(time.Minute, func() { _ = old.Close() })
		}
	})
}

func loadLines(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" && !strings.HasPrefix(line, "#") {
			set[line] = true
		}
	}
	return set, scanner.Err()
}

// MAC vendors (Wireshark manuf file)

type macTable struct {
	byBits map[int]map[uint64]string // prefix length in bits -> prefix -> vendor
}

func loadManuf(path string) (*macTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	t := &macTable{byBits: map[int]map[uint64]string{}}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		prefix, bits := fields[0], 24
		if p, b, ok := strings.Cut(prefix, "/"); ok {
			prefix = p
			if n, err := strconv.Atoi(b); err == nil {
				bits = n
			}
		}
		value, ok := macValue(prefix)
		if !ok {
			continue
		}
		vendor := strings.TrimSpace(fields[len(fields)-1])
		if vendor == "" {
			vendor = strings.TrimSpace(fields[1])
		}
		if t.byBits[bits] == nil {
			t.byBits[bits] = map[uint64]string{}
		}
		t.byBits[bits][value>>(48-bits)] = vendor
	}
	return t, scanner.Err()
}

// macValue parses a MAC address or prefix in common notations into a 48-bit value.
func macValue(s string) (uint64, bool) {
	var hex strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
		default:
			return 0, false
		}
	}
	h := hex.String()
	if len(h) < 6 || len(h) > 12 || len(h)%2 != 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(h+strings.Repeat("0", 12-len(h)), 16, 64)
	return v, err == nil
}

func (t *macTable) lookup(mac uint64) (string, int) {
	for _, bits := range []int{36, 28, 24} {
		if vendor, ok := t.byBits[bits][mac>>(48-bits)]; ok {
			return vendor, bits
		}
	}
	return "", 0
}
