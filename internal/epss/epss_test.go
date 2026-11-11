package epss

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	csv := "#model_version:v2025.03.14,score_date:2026-11-09T00:00:00Z\ncve,epss,percentile\nCVE-2021-44228,0.97565,0.99999\ncve-2024-0001, 0.5 ,0.8\n"
	tab, err := Parse([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if tab.Len() != 2 {
		t.Fatalf("len = %d", tab.Len())
	}
	if v, ok := tab.Lookup("CVE-2021-44228"); !ok || v != 0.97565 {
		t.Errorf("lookup = %v %v", v, ok)
	}
	if v, ok := tab.Lookup("cve-2024-0001"); !ok || v != 0.5 {
		t.Errorf("lookup lower-case = %v %v", v, ok)
	}
	if _, ok := tab.Lookup("CVE-2000-0001"); ok {
		t.Error("unexpected hit")
	}
	var nilTab *Table
	if _, ok := nilTab.Lookup("CVE-2021-44228"); ok || nilTab.Len() != 0 {
		t.Error("nil table must be empty")
	}
}

func TestParseWithoutHeader(t *testing.T) {
	tab, err := Parse([]byte("CVE-2024-0001,0.1\n"))
	if err != nil || tab.Len() != 1 {
		t.Fatalf("err=%v", err)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, in string }{
		{"empty", ""},
		{"only comments", "# nothing\n"},
		{"header only", "cve,epss,percentile\n"},
		{"bad cve", "CVE-1-1,0.5\n"},
		{"bad score", "CVE-2024-0001,abc\n"},
		{"score above 1", "CVE-2024-0001,1.5\n"},
		{"score negative", "CVE-2024-0001,-0.1\n"},
		{"score NaN", "CVE-2024-0001,NaN\n"},
		{"one column", "CVE-2024-0001\n"},
		{"bad quoting", "CVE-2024-0001,\"0.5\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.in)); err == nil {
				t.Fatal("expected error")
			} else if !strings.HasPrefix(err.Error(), "epss:") {
				t.Errorf("unprefixed error %v", err)
			}
		})
	}
}
