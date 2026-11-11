package evidence

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func report(digest string) string {
	meta := ""
	if digest != "" {
		meta = `"Metadata":{"RepoDigests":["r/x@` + digest + `"]},`
	}
	return `{"SchemaVersion":2,"CreatedAt":"2026-11-01T00:00:00Z",` + meta +
		`"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"p","CVSS":{"n":{"V3Score":7.5}}}]}]}`
}

func writeReport(t *testing.T, dir, digest, body string) {
	t.Helper()
	name, err := FileName(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileName(t *testing.T) {
	got, err := FileName(dA)
	if err != nil || got != "sha256-"+strings.Repeat("a", 64)+".json" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "sha256:abc", "../etc/passwd", dA + "/..", strings.ToUpper(dA), "latest"} {
		if _, err := FileName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDirProvider(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, dA, report(dA))
	writeReport(t, dir, dB, report(dA)) // misnamed: describes A, stored as B
	p := &DirProvider{Dir: dir}
	ctx := context.Background()

	ev, err := p.Lookup(ctx, dA)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Digest != dA || len(ev.Findings) != 1 || ev.Findings[0].CVSS != 7.5 || ev.ScannedAt.Year() != 2026 {
		t.Errorf("evidence = %+v", ev)
	}
	if _, err := p.Lookup(ctx, dB); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("misnamed report must be an error, got %v", err)
	}
	other := "sha256:" + strings.Repeat("c", 64)
	if _, err := p.Lookup(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := p.Lookup(ctx, "bogus"); err == nil {
		t.Error("malformed digest")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Lookup(cctx, dA); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestDirProviderBadReports(t *testing.T) {
	dir := t.TempDir()
	p := &DirProvider{Dir: dir, MaxBytes: 300}
	writeReport(t, dir, dA, `{not json`)
	if _, err := p.Lookup(context.Background(), dA); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("malformed: %v", err)
	}
	writeReport(t, dir, dA, report("")+strings.Repeat(" ", 400))
	if _, err := p.Lookup(context.Background(), dA); err == nil {
		t.Error("oversize report accepted")
	}
	// Directory with the report name.
	name, _ := FileName(dB)
	if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Lookup(context.Background(), dB); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("directory as report: %v", err)
	}
}

func TestDirProviderModTimeFallback(t *testing.T) {
	dir := t.TempDir()
	writeReport(t, dir, dA, `{"SchemaVersion":2}`)
	ev, err := (&DirProvider{Dir: dir}).Lookup(context.Background(), dA)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(ev.ScannedAt) > time.Minute {
		t.Errorf("ScannedAt = %v, want file mtime", ev.ScannedAt)
	}
}

type fake struct {
	name string
	ev   *Evidence
	err  error
}

func (f fake) Name() string { return f.name }
func (f fake) Lookup(context.Context, string) (*Evidence, error) {
	return f.ev, f.err
}

func TestChain(t *testing.T) {
	ev := &Evidence{Digest: dA}
	boom := errors.New("boom")
	tests := []struct {
		name    string
		chain   Chain
		wantEv  bool
		wantErr string
	}{
		{"first wins", Chain{fake{"a", ev, nil}, fake{"b", nil, boom}}, true, ""},
		{"falls through not found", Chain{fake{"a", nil, ErrNotFound}, fake{"b", ev, nil}}, true, ""},
		{"all not found", Chain{fake{"a", nil, ErrNotFound}, fake{"b", nil, ErrNotFound}}, false, "no evidence"},
		{"error then found", Chain{fake{"a", nil, boom}, fake{"b", ev, nil}}, true, ""},
		{"error then not found reports error", Chain{fake{"a", nil, boom}, fake{"b", nil, ErrNotFound}}, false, "a: boom"},
		{"empty", Chain{}, false, "no evidence"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.chain.Lookup(context.Background(), dA)
			if tc.wantEv != (got != nil) {
				t.Fatalf("evidence = %v", got)
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if n := (Chain{fake{name: "a"}, fake{name: "b"}}).Name(); n != "a+b" {
		t.Errorf("Name = %q", n)
	}
}

func TestHTTPProvider(t *testing.T) {
	var gotAuth, gotPath, gotAsset string
	respond := func(code int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotPath, gotAsset = r.Header.Get("Authorization"), r.URL.Path, r.URL.Query().Get("asset")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
	}
	ok := respond(200, `[{"cve":"cve-2021-44228","cvss":10,"epss":0.97,"kev":true,"risk":90,"asset":"x"}]`)
	defer ok.Close()
	p := &HTTPProvider{BaseURL: ok.URL + "/", Token: "tok"}
	ev, err := p.Lookup(context.Background(), dA)
	if err != nil {
		t.Fatal(err)
	}
	f := ev.Findings[0]
	if f.ID != "CVE-2021-44228" || !f.KEVHint || !f.HasEPSS || f.EPSS != 0.97 || !ev.ScannedAt.IsZero() {
		t.Errorf("finding = %+v", f)
	}
	if gotAuth != "Bearer tok" || gotPath != "/queue" || gotAsset != dA {
		t.Errorf("request: auth=%q path=%q asset=%q", gotAuth, gotPath, gotAsset)
	}

	cases := []struct {
		name    string
		code    int
		body    string
		notFnd  bool
		wantErr string
	}{
		{"empty list", 200, `[]`, true, ""},
		{"404", 404, ``, true, ""},
		{"500", 500, `x`, false, "HTTP 500"},
		{"not json", 200, `<html>`, false, "response"},
		{"missing cvss", 200, `[{"cve":"CVE-2024-0001","epss":0.1}]`, false, "missing"},
		{"bad cve", 200, `[{"cve":"a b","cvss":1,"epss":0.1}]`, false, "missing"},
		{"range", 200, `[{"cve":"CVE-2024-0001","cvss":11,"epss":0.1}]`, false, "out-of-range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := respond(tc.code, tc.body)
			defer s.Close()
			_, err := (&HTTPProvider{BaseURL: s.URL}).Lookup(context.Background(), dA)
			switch {
			case tc.notFnd && !errors.Is(err, ErrNotFound):
				t.Fatalf("err = %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestHTTPProviderEdgeCases(t *testing.T) {
	ctx := context.Background()
	if _, err := (&HTTPProvider{BaseURL: "http://x"}).Lookup(ctx, "bad"); err == nil {
		t.Error("bad digest")
	}
	for _, u := range []string{"", "ftp://x", "http://", "::"} {
		if _, err := (&HTTPProvider{BaseURL: u}).Lookup(ctx, dA); err == nil {
			t.Errorf("base %q accepted", u)
		}
	}
	// Timeout: server stalls, client context expires.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer slow.Close()
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := (&HTTPProvider{BaseURL: slow.URL}).Lookup(cctx, dA); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("timeout: %v", err)
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[` + strings.Repeat(" ", httpMaxBody+10) + `]`))
	}))
	defer big.Close()
	if _, err := (&HTTPProvider{BaseURL: big.URL}).Lookup(ctx, dA); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("big: %v", err)
	}
	many := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[` + strings.Repeat(`{"cve":"CVE-2024-0001","cvss":1,"epss":0},`, httpMaxItems) + `{"cve":"CVE-2024-0001","cvss":1,"epss":0}]`))
	}))
	defer many.Close()
	if _, err := (&HTTPProvider{BaseURL: many.URL}).Lookup(ctx, dA); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("many: %v", err)
	}
}
