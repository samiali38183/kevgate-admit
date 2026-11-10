// Package kev loads and refreshes the CISA Known Exploited Vulnerabilities
// catalog. The server only reads a local file; refreshing is an explicit
// operator action (kevgate-admit kev-refresh).
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultURL is the official CISA feed.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// DefaultMaxBytes caps both the local file and a downloaded feed.
const DefaultMaxBytes = 32 << 20

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)

// Catalog is an immutable set of KEV CVE IDs.
type Catalog struct {
	ids     map[string]struct{}
	Version string
}

// Len returns the number of entries.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.ids)
}

// Contains reports whether the CVE is in the catalog. Safe on a nil catalog.
func (c *Catalog) Contains(id string) bool {
	if c == nil {
		return false
	}
	_, ok := c.ids[strings.ToUpper(id)]
	return ok
}

type feed struct {
	CatalogVersion string      `json:"catalogVersion"`
	Count          *int        `json:"count"`
	Vulns          *[]feedItem `json:"vulnerabilities"`
}

type feedItem struct {
	CVEID string `json:"cveID"`
}

// Parse validates a feed document: the vulnerabilities array must exist and be
// non-empty, every cveID must be well formed, and the optional count header
// must match.
func Parse(data []byte) (*Catalog, error) {
	var f feed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	if f.Vulns == nil {
		return nil, errors.New("kev: missing vulnerabilities array")
	}
	items := *f.Vulns
	if len(items) == 0 {
		return nil, errors.New("kev: catalog has no entries")
	}
	if f.Count != nil && *f.Count != len(items) {
		return nil, fmt.Errorf("kev: count mismatch: header %d, entries %d", *f.Count, len(items))
	}
	c := &Catalog{ids: make(map[string]struct{}, len(items)), Version: f.CatalogVersion}
	for i, it := range items {
		id := strings.ToUpper(strings.TrimSpace(it.CVEID))
		if !cveRe.MatchString(id) {
			return nil, fmt.Errorf("kev: entry %d: invalid cveID", i)
		}
		c.ids[id] = struct{}{}
	}
	return c, nil
}

// RefreshOptions configures Refresh. Zero values select safe defaults.
type RefreshOptions struct {
	URL      string        // must be https
	Dest     string        // file to write atomically
	Client   *http.Client  // optional; tests inject a TLS test client
	Timeout  time.Duration // default 30s
	MaxBytes int64         // default DefaultMaxBytes
}

// Refresh downloads the feed over HTTPS, validates it and atomically replaces
// Dest. It refuses a new catalog that is less than half the size of the one
// already on disk. It returns the number of entries written.
func Refresh(ctx context.Context, o RefreshOptions) (int, error) {
	if o.URL == "" {
		o.URL = DefaultURL
	}
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return 0, errors.New("kev: refusing to fetch over a non-HTTPS URL")
	}
	if o.Dest == "" {
		return 0, errors.New("kev: destination path required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	client := &http.Client{}
	if o.Client != nil {
		c := *o.Client
		client = &c
	}
	client.Timeout = o.Timeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("kev: redirect to non-HTTPS URL refused")
		}
		if len(via) >= 5 {
			return errors.New("kev: too many redirects")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("kev: %w", err)
	}
	req.Header.Set("User-Agent", "kevgate-admit-kev-refresh")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("kev: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("kev: fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, o.MaxBytes+1))
	if err != nil {
		return 0, fmt.Errorf("kev: read: %w", err)
	}
	if int64(len(body)) > o.MaxBytes {
		return 0, fmt.Errorf("kev: feed larger than %d bytes", o.MaxBytes)
	}
	cat, err := Parse(body)
	if err != nil {
		return 0, err
	}
	if old, err := os.ReadFile(o.Dest); err == nil {
		if oc, perr := Parse(old); perr == nil && cat.Len()*2 < oc.Len() {
			return 0, fmt.Errorf("kev: new catalog has %d entries, existing has %d; refusing to shrink by more than half", cat.Len(), oc.Len())
		}
	}
	if err := writeAtomic(o.Dest, body); err != nil {
		return 0, err
	}
	return cat.Len(), nil
}

func writeAtomic(dest string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".kev-*.tmp")
	if err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("kev: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	if err := os.Rename(name, dest); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	return nil
}
