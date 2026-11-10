// Package trivy parses Trivy JSON image reports (schema version 2) into the
// small subset the admission policy needs.
package trivy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

// Limits that bound the work done for one report.
const (
	DefaultMaxBytes = 16 << 20
	maxFindings     = 200000
)

// ErrInvalid wraps every parse or validation failure.
var ErrInvalid = errors.New("invalid trivy report")

// Report is the parsed form of a Trivy report.
type Report struct {
	ArtifactName string
	CreatedAt    time.Time // zero when the report has no timestamp
	// Digests are the image digests the report says it describes
	// (Metadata.ImageID and Metadata.RepoDigests). Empty when absent.
	Digests  []string
	Findings []vuln.Finding
	Skipped  int // vulnerabilities dropped because the ID was malformed
}

type rawReport struct {
	SchemaVersion int      `json:"SchemaVersion"`
	CreatedAt     string   `json:"CreatedAt"`
	ArtifactName  string   `json:"ArtifactName"`
	Metadata      rawMeta  `json:"Metadata"`
	Results       []rawRes `json:"Results"`
}

type rawMeta struct {
	ImageID     string   `json:"ImageID"`
	RepoDigests []string `json:"RepoDigests"`
}

type rawRes struct {
	Target          string    `json:"Target"`
	Vulnerabilities []rawVuln `json:"Vulnerabilities"`
}

type rawVuln struct {
	ID               string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	Severity         string             `json:"Severity"`
	CVSS             map[string]rawCVSS `json:"CVSS"`
	EPSS             *float64           `json:"EPSS"`
}

type rawCVSS struct {
	V2Score float64 `json:"V2Score"`
	V3Score float64 `json:"V3Score"`
}

// severityCVSS is used when a vulnerability carries no CVSS data at all.
var severityCVSS = map[string]float64{
	"CRITICAL": 9.0,
	"HIGH":     7.5,
	"MEDIUM":   5.0,
	"LOW":      2.0,
	"UNKNOWN":  0.0,
}

// Parse decodes and validates a report held in memory.
func Parse(data []byte) (*Report, error) {
	return ParseReader(bytes.NewReader(data), int64(len(data)))
}

// ParseReader reads at most maxBytes from r; a larger input is rejected.
// Unknown fields are ignored so newer Trivy versions keep working; the fields
// the policy relies on are validated.
func ParseReader(r io.Reader, maxBytes int64) (*Report, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	dec := json.NewDecoder(lr)
	var raw rawReport
	if err := dec.Decode(&raw); err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, maxBytes)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if lr.N <= 0 {
			return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, maxBytes)
		}
		return nil, fmt.Errorf("%w: trailing data after report", ErrInvalid)
	}
	if raw.SchemaVersion != 2 {
		return nil, fmt.Errorf("%w: unsupported SchemaVersion %d (want 2)", ErrInvalid, raw.SchemaVersion)
	}
	rep := &Report{ArtifactName: clip(raw.ArtifactName, 256)}
	if raw.CreatedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, raw.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: CreatedAt: %v", ErrInvalid, err)
		}
		rep.CreatedAt = t.UTC()
	}
	rep.Digests = digestsOf(raw.Metadata)

	best := map[string]vuln.Finding{}
	total := 0
	for _, res := range raw.Results {
		for _, v := range res.Vulnerabilities {
			total++
			if total > maxFindings {
				return nil, fmt.Errorf("%w: more than %d vulnerabilities", ErrInvalid, maxFindings)
			}
			id := strings.ToUpper(strings.TrimSpace(v.ID))
			if !vuln.ValidID(id) {
				rep.Skipped++
				continue
			}
			f, err := convert(id, v)
			if err != nil {
				return nil, err
			}
			if cur, ok := best[id]; !ok || f.CVSS > cur.CVSS {
				best[id] = f
			}
		}
	}
	rep.Findings = make([]vuln.Finding, 0, len(best))
	for _, f := range best {
		rep.Findings = append(rep.Findings, f)
	}
	sort.Slice(rep.Findings, func(i, j int) bool { return rep.Findings[i].ID < rep.Findings[j].ID })
	return rep, nil
}

func convert(id string, v rawVuln) (vuln.Finding, error) {
	f := vuln.Finding{
		ID:        id,
		Package:   clip(v.PkgName, 128),
		Installed: clip(v.InstalledVersion, 64),
		Fixed:     clip(v.FixedVersion, 64),
		Severity:  strings.ToUpper(clip(v.Severity, 16)),
	}
	var v3, v2 float64
	have3, have2 := false, false
	for _, c := range v.CVSS {
		if !validScore(c.V3Score) || !validScore(c.V2Score) {
			return f, fmt.Errorf("%w: %s: cvss score out of range 0..10", ErrInvalid, id)
		}
		if c.V3Score > 0 {
			have3 = true
			v3 = math.Max(v3, c.V3Score)
		}
		if c.V2Score > 0 {
			have2 = true
			v2 = math.Max(v2, c.V2Score)
		}
	}
	switch {
	case have3:
		f.CVSS = v3
	case have2:
		f.CVSS = v2
	default:
		f.CVSS = severityCVSS[f.Severity]
	}
	if v.EPSS != nil {
		e := *v.EPSS
		if !(e >= 0 && e <= 1) {
			return f, fmt.Errorf("%w: %s: epss out of range 0..1", ErrInvalid, id)
		}
		f.EPSS, f.HasEPSS = e, true
	}
	return f, nil
}

func validScore(s float64) bool { return s >= 0 && s <= 10 }

func digestsOf(m rawMeta) []string {
	var out []string
	add := func(s string) {
		if i := strings.LastIndexByte(s, '@'); i >= 0 {
			s = s[i+1:]
		}
		if strings.HasPrefix(s, "sha256:") || strings.HasPrefix(s, "sha512:") {
			out = append(out, strings.ToLower(s))
		}
	}
	add(m.ImageID)
	for _, d := range m.RepoDigests {
		add(d)
	}
	return out
}

// clip drops control characters and truncates to n bytes. Report text ends up
// in denial messages and logs, so it must not carry newlines or escapes.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}
