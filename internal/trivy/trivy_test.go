package trivy

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseBasic(t *testing.T) {
	data, err := os.ReadFile("testdata/basic.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ArtifactName != "registry.example.com/demo/app" {
		t.Errorf("artifact = %q", rep.ArtifactName)
	}
	if want := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC); !rep.CreatedAt.Equal(want) {
		t.Errorf("created = %v", rep.CreatedAt)
	}
	if len(rep.Digests) != 2 {
		t.Errorf("digests = %v", rep.Digests)
	}
	if rep.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", rep.Skipped)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("findings = %d, want 3 (duplicate merged): %+v", len(rep.Findings), rep.Findings)
	}
	byID := map[string]float64{}
	for _, f := range rep.Findings {
		byID[f.ID] = f.CVSS
	}
	// 0001: highest V3 across sources and duplicates is 9.0.
	// 0002: only V2 present, so V2 is used. 0003: no CVSS, CRITICAL maps to 9.0.
	for id, want := range map[string]float64{"CVE-2024-0001": 9.0, "CVE-2024-0002": 5.0, "CVE-2024-0003": 9.0} {
		if byID[id] != want {
			t.Errorf("%s cvss = %v, want %v", id, byID[id], want)
		}
	}
	for _, f := range rep.Findings {
		if f.ID == "CVE-2024-0002" && (!f.HasEPSS || f.EPSS != 0.42) {
			t.Errorf("EPSS not carried: %+v", f)
		}
		if f.ID == "CVE-2024-0003" && f.HasEPSS {
			t.Errorf("unexpected EPSS: %+v", f)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"not json", `nope`, "invalid trivy report"},
		{"empty", ``, "invalid trivy report"},
		{"wrong schema", `{"SchemaVersion":1}`, "unsupported SchemaVersion"},
		{"missing schema", `{}`, "unsupported SchemaVersion"},
		{"trailing data", `{"SchemaVersion":2} {}`, "trailing data"},
		{"bad created", `{"SchemaVersion":2,"CreatedAt":"yesterday"}`, "CreatedAt"},
		{"wrong type", `{"SchemaVersion":2,"Results":"x"}`, "invalid trivy report"},
		{"cvss out of range", `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","CVSS":{"a":{"V3Score":11}}}]}]}`, "cvss"},
		{"cvss negative", `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","CVSS":{"a":{"V2Score":-1}}}]}]}`, "cvss"},
		{"epss out of range", `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","EPSS":1.5}]}]}`, "epss"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseReaderSizeCap(t *testing.T) {
	big := `{"SchemaVersion":2,"ArtifactName":"` + strings.Repeat("a", 2000) + `"}`
	if _, err := ParseReader(strings.NewReader(big), 1000); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected size error, got %v", err)
	}
	if _, err := ParseReader(strings.NewReader(big), 0); err != nil {
		t.Fatalf("default cap should allow a small document: %v", err)
	}
	// Valid document followed by padding that crosses the cap.
	padded := `{"SchemaVersion":2}` + strings.Repeat(" ", 2000) + "x"
	if _, err := ParseReader(strings.NewReader(padded), 100); err == nil {
		t.Fatal("expected error for padded input")
	}
}

func TestClipStripsControlCharacters(t *testing.T) {
	in := `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"a\nb\u001b[31m","Severity":"high"}]}]}`
	rep, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Findings[0]
	if strings.ContainsAny(f.Package, "\n\x1b") {
		t.Errorf("control characters survived: %q", f.Package)
	}
	if f.Severity != "HIGH" {
		t.Errorf("severity = %q", f.Severity)
	}
	if got := clip(strings.Repeat("é", 100), 5); len(got) > 5 {
		t.Errorf("clip did not truncate: %q", got)
	}
}

func FuzzParse(f *testing.F) {
	seed, _ := os.ReadFile("testdata/basic.json")
	f.Add(seed)
	f.Add([]byte(`{"SchemaVersion":2}`))
	f.Add([]byte(`{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","CVSS":{"x":{"V3Score":9.8}},"EPSS":0.5}]}]}`))
	f.Add([]byte(`{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","CVSS":{"x":{"V3Score":99}}}]}]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		for _, fi := range rep.Findings {
			if fi.ID == "" || fi.ID != strings.ToUpper(fi.ID) {
				t.Fatalf("bad id %q", fi.ID)
			}
			if !(fi.CVSS >= 0 && fi.CVSS <= 10) {
				t.Fatalf("cvss out of range: %v", fi.CVSS)
			}
			if fi.HasEPSS && !(fi.EPSS >= 0 && fi.EPSS <= 1) {
				t.Fatalf("epss out of range: %v", fi.EPSS)
			}
			if strings.ContainsAny(fi.Package+fi.Installed+fi.Fixed+fi.Severity, "\n\r\x1b") {
				t.Fatalf("control characters in finding: %+v", fi)
			}
		}
	})
}
