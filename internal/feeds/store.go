// Package feeds downloads public data files (vulnerability lists, IP and MAC
// databases, email provider lists) on a schedule and keeps them on the
// persistent data volume.
package feeds

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const userAgent = "DeliverZenmail-Feeds/1.0 (+https://deliver.zenmail.eu/tools/)"

// Source describes one downloadable file.
type Source struct {
	Name     string                       // file name in the feeds directory
	URLs     func(now time.Time) []string // candidates, tried in order
	Every    time.Duration
	MaxBytes int64
	Gunzip   bool
}

// Store keeps the files in a directory and notifies watchers after updates.
type Store struct {
	dir      string
	client   *http.Client
	mu       sync.Mutex
	watchers map[string][]func(path string)
}

func NewStore(dir string) *Store {
	return &Store{
		dir:      dir,
		client:   &http.Client{Timeout: 10 * time.Minute},
		watchers: map[string][]func(string){},
	}
}

func (s *Store) Path(name string) string { return filepath.Join(s.dir, name) }

// Watch registers fn for a source; it runs whenever the file is (re)loaded.
func (s *Store) Watch(name string, fn func(path string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchers[name] = append(s.watchers[name], fn)
}

func (s *Store) notify(name string) {
	s.mu.Lock()
	fns := append([]func(string){}, s.watchers[name]...)
	s.mu.Unlock()
	for _, fn := range fns {
		fn(s.Path(name))
	}
}

// Run loads existing files, then keeps them fresh until ctx ends.
func (s *Store) Run(ctx context.Context, sources []Source) {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		log.Printf("feeds: cannot create %s: %v", s.dir, err)
		return
	}
	for _, src := range sources {
		if _, err := os.Stat(s.Path(src.Name)); err == nil {
			s.notify(src.Name)
		}
	}
	refresh := func() {
		for _, src := range sources {
			if ctx.Err() != nil {
				return
			}
			info, err := os.Stat(s.Path(src.Name))
			if err == nil && time.Since(info.ModTime()) < src.Every {
				continue
			}
			changed, err := s.download(ctx, src, info)
			if err != nil {
				log.Printf("feeds: %s: %v", src.Name, err)
				continue
			}
			if changed {
				log.Printf("feeds: updated %s", src.Name)
				s.notify(src.Name)
			}
		}
	}
	go func() {
		refresh()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}

func (s *Store) download(ctx context.Context, src Source, existing os.FileInfo) (bool, error) {
	var lastErr error
	for _, url := range src.URLs(time.Now()) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", userAgent)
		if existing != nil {
			req.Header.Set("If-Modified-Since", existing.ModTime().UTC().Format(http.TimeFormat))
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		changed, err := s.store(src, resp)
		resp.Body.Close()
		if err == nil {
			return changed, nil
		}
		lastErr = err
	}
	return false, lastErr
}

func (s *Store) store(src Source, resp *http.Response) (bool, error) {
	path := s.Path(src.Name)
	switch resp.StatusCode {
	case http.StatusNotModified:
		now := time.Now()
		return false, os.Chtimes(path, now, now)
	case http.StatusOK:
	default:
		return false, fmt.Errorf("%s answered %s", resp.Request.URL.Host, resp.Status)
	}
	var body io.Reader = resp.Body
	if src.Gunzip {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return false, err
		}
		defer gz.Close()
		body = gz
	}
	tmp, err := os.CreateTemp(s.dir, src.Name+".*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(body, src.MaxBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if n > src.MaxBytes {
		return false, fmt.Errorf("file larger than %d bytes", src.MaxBytes)
	}
	if n == 0 {
		return false, fmt.Errorf("empty file")
	}
	return true, os.Rename(tmp.Name(), path)
}

func fixed(url string) func(time.Time) []string {
	return func(time.Time) []string { return []string{url} }
}

// Sources lists all files used by Deliver Zenmail.
var Sources = []Source{
	{Name: "exploitdb.csv", URLs: fixed("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"), Every: 24 * time.Hour, MaxBytes: 64 << 20},
	{Name: "kev.json", URLs: fixed("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"), Every: 24 * time.Hour, MaxBytes: 32 << 20},
	{Name: "manuf.txt", URLs: fixed("https://www.wireshark.org/download/automated/data/manuf"), Every: 7 * 24 * time.Hour, MaxBytes: 32 << 20},
	{Name: "disposable.txt", URLs: fixed("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"), Every: 24 * time.Hour, MaxBytes: 8 << 20},
	{Name: "freemail.json", URLs: fixed("https://raw.githubusercontent.com/Kikobeats/free-email-domains/master/domains.json"), Every: 7 * 24 * time.Hour, MaxBytes: 8 << 20},
	{Name: "dbip-city.mmdb", URLs: func(now time.Time) []string {
		// DB-IP publishes the lite database monthly; fall back to last month early in a month.
		prev := now.AddDate(0, -1, 0)
		return []string{
			fmt.Sprintf("https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz", now.Format("2006-01")),
			fmt.Sprintf("https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz", prev.Format("2006-01")),
		}
	}, Every: 30 * 24 * time.Hour, MaxBytes: 512 << 20, Gunzip: true},
}
