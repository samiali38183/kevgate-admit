package kev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodFeed = `{"catalogVersion":"2026.11.01","count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"x"},{"cveID":"cve-2024-3400"}]}`

func TestParse(t *testing.T) {
	c, err := Parse([]byte(goodFeed))
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 || c.Version != "2026.11.01" {
		t.Errorf("len=%d version=%q", c.Len(), c.Version)
	}
	for _, id := range []string{"CVE-2021-44228", "cve-2021-44228", "CVE-2024-3400"} {
		if !c.Contains(id) {
			t.Errorf("missing %s", id)
		}
	}
	if c.Contains("CVE-2000-0001") {
		t.Error("unexpected member")
	}
	var nilCat *Catalog
	if nilCat.Contains("CVE-2021-44228") || nilCat.Len() != 0 {
		t.Error("nil catalog must be empty")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"not json", `x`, "kev:"},
		{"missing array", `{"count":0}`, "missing vulnerabilities"},
		{"empty", `{"vulnerabilities":[]}`, "no entries"},
		{"count mismatch", `{"count":5,"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`, "count mismatch"},
		{"bad id", `{"vulnerabilities":[{"cveID":"CVE-21-1"}]}`, "invalid cveID"},
		{"missing id", `{"vulnerabilities":[{}]}`, "invalid cveID"},
		{"wrong type", `{"vulnerabilities":{"a":1}}`, "kev:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	return s
}

func TestRefresh(t *testing.T) {
	good := serve(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, goodFeed) })
	dest := filepath.Join(t.TempDir(), "kev.json")
	n, err := Refresh(context.Background(), RefreshOptions{URL: good.URL, Dest: dest, Client: good.Client()})
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != goodFeed {
		t.Error("file content differs from feed")
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestRefreshFailuresLeaveFileAlone(t *testing.T) {
	big := strings.Repeat(" ", 2048)
	tests := []struct {
		name string
		h    http.HandlerFunc
		opt  func(*RefreshOptions)
		want string
	}{
		{"http error", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }, nil, "HTTP 500"},
		{"bad schema", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"x"}]}`) }, nil, "invalid cveID"},
		{"too big", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, goodFeed+big) }, func(o *RefreshOptions) { o.MaxBytes = 1024 }, "larger than"},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		}, func(o *RefreshOptions) { o.Timeout = 50 * time.Millisecond }, "fetch"},
		{"redirect to http", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.invalid/kev.json", http.StatusFound)
		}, nil, "non-HTTPS"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := serve(t, tc.h)
			dest := filepath.Join(t.TempDir(), "kev.json")
			if err := os.WriteFile(dest, []byte(goodFeed), 0o600); err != nil {
				t.Fatal(err)
			}
			o := RefreshOptions{URL: s.URL, Dest: dest, Client: s.Client()}
			if tc.opt != nil {
				tc.opt(&o)
			}
			_, err := Refresh(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if b, _ := os.ReadFile(dest); string(b) != goodFeed {
				t.Error("existing file was modified by a failed refresh")
			}
		})
	}
}

func TestRefreshRejectsNonHTTPSAndBadOptions(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "k.json")
	for _, u := range []string{"http://example.com/k.json", "ftp://x/y", "://bad", "https://"} {
		if _, err := Refresh(context.Background(), RefreshOptions{URL: u, Dest: dest}); err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
			t.Errorf("%q: err = %v", u, err)
		}
	}
	if _, err := Refresh(context.Background(), RefreshOptions{URL: "https://example.com/x"}); err == nil || !strings.Contains(err.Error(), "destination") {
		t.Errorf("missing dest: %v", err)
	}
}

func TestRefreshRefusesLargeShrink(t *testing.T) {
	var items []string
	for i := 0; i < 10; i++ {
		items = append(items, fmt.Sprintf(`{"cveID":"CVE-2024-%04d"}`, 1000+i))
	}
	old := `{"vulnerabilities":[` + strings.Join(items, ",") + `]}`
	dest := filepath.Join(t.TempDir(), "kev.json")
	_ = os.WriteFile(dest, []byte(old), 0o600)
	s := serve(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, goodFeed) }) // 2 entries < 10/2
	_, err := Refresh(context.Background(), RefreshOptions{URL: s.URL, Dest: dest, Client: s.Client()})
	if err == nil || !strings.Contains(err.Error(), "shrink") {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshWriteError(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, goodFeed) })
	dest := filepath.Join(t.TempDir(), "missing-dir", "kev.json")
	if _, err := Refresh(context.Background(), RefreshOptions{URL: s.URL, Dest: dest, Client: s.Client()}); err == nil {
		t.Fatal("expected error for unwritable destination")
	}
}
