package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/imageref"
	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var now = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseValid(t *testing.T) {
	p := mustParse(t, `
version: 1
mode: enforce
default:
  requireEvidence: warn
namespaces:
  prod:
    maxRisk: 40
    denyKev: true
    requireDigest: true
    requireEvidence: deny
    allowedRegistries: [GHCR.io/Org/, registry.example.com]
    assetCriticality: 7
    maxEvidenceAge: 168h
    ignoreUnfixed: true
    exceptions:
      - id: ex-1
        cve: cve-2024-0001
        justification: vendor patch ships next sprint
        expires: 2026-12-01
      - id: ex-2
        rule: requireDigest
        image: ghcr.io/org/legacy
        justification: legacy job pinned by tag until rebuild
        expires: 2026-12-01T10:00:00Z
  audit-ns:
    mode: audit
`)
	if p.Default.RequireEvidence != ActionWarn || p.Default.AssetCriticality != DefaultACR {
		t.Errorf("default = %+v", p.Default)
	}
	prod := p.Namespaces["prod"]
	if *prod.MaxRisk != 40 || !prod.DenyKEV || !prod.RequireDigest || prod.AssetCriticality != 7 ||
		prod.MaxEvidenceAge != 168*time.Hour || !prod.IgnoreUnfixed {
		t.Errorf("prod = %+v", prod)
	}
	if prod.AllowedRegistries[0] != "ghcr.io/org" {
		t.Errorf("registries = %v", prod.AllowedRegistries)
	}
	if got := prod.Exceptions[0].Expires; !got.Equal(time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("date-only expiry should run through the end of the day, got %v", got)
	}
	if prod.Exceptions[0].CVE != "CVE-2024-0001" || prod.Exceptions[1].Rule != "requireDigest" {
		t.Errorf("exceptions = %+v", prod.Exceptions)
	}
	if got := p.Namespaces["audit-ns"].RequireEvidence; got != ActionDeny {
		t.Errorf("requireEvidence default = %v, want deny", got)
	}
	if m := p.EffectiveMode(&p.Default); m != ModeEnforce {
		t.Errorf("mode = %v", m)
	}
	au := p.Namespaces["audit-ns"]
	if m := p.EffectiveMode(&au); m != ModeAudit {
		t.Errorf("mode = %v", m)
	}
	if scope, _ := p.RuleFor("prod"); scope != "prod" {
		t.Errorf("scope = %q", scope)
	}
	if scope, _ := p.RuleFor("other"); scope != "_default" {
		t.Errorf("scope = %q", scope)
	}
}

func TestParseInvalid(t *testing.T) {
	ex := func(body string) string {
		return "version: 1\ndefault:\n  exceptions:\n    - " + body + "\n"
	}
	good := "id: e1\n      justification: long enough text\n      expires: 2027-01-01\n      "
	tests := []struct{ name, in, want string }{
		{"unknown field", "version: 1\ndefault: {}\nbogus: 1\n", "bogus"},
		{"unknown rule field", "version: 1\ndefault:\n  maxRsik: 3\n", "maxRsik"},
		{"wrong version", "version: 2\ndefault: {}\n", "version must be 1"},
		{"missing version", "default: {}\n", "version must be 1"},
		{"no default", "version: 1\n", "default rule is required"},
		{"bad mode", "version: 1\nmode: loud\ndefault: {}\n", "mode must be"},
		{"bad rule mode", "version: 1\ndefault:\n  mode: x\n", "mode must be"},
		{"maxRisk high", "version: 1\ndefault:\n  maxRisk: 101\n", "maxRisk"},
		{"maxRisk negative", "version: 1\ndefault:\n  maxRisk: -1\n", "maxRisk"},
		{"bad action", "version: 1\ndefault:\n  requireEvidence: maybe\n", "requireEvidence"},
		{"acr high", "version: 1\ndefault:\n  assetCriticality: 9\n", "assetCriticality"},
		{"acr negative", "version: 1\ndefault:\n  assetCriticality: -2\n", "assetCriticality"},
		{"bad age", "version: 1\ndefault:\n  maxEvidenceAge: soon\n", "maxEvidenceAge"},
		{"negative age", "version: 1\ndefault:\n  maxEvidenceAge: -5h\n", "maxEvidenceAge"},
		{"registry scheme", "version: 1\ndefault:\n  allowedRegistries: [\"https://ghcr.io\"]\n", "allowedRegistries"},
		{"registry wildcard", "version: 1\ndefault:\n  allowedRegistries: [\"*.io\"]\n", "allowedRegistries"},
		{"empty registry", "version: 1\ndefault:\n  allowedRegistries: [\"\"]\n", "allowedRegistries"},
		{"registry traversal", "version: 1\ndefault:\n  allowedRegistries: [\"ghcr.io/org/..\"]\n", "allowedRegistries"},
		{"registry bad host", "version: 1\ndefault:\n  allowedRegistries: [\"::0\"]\n", "allowedRegistries"},
		{"registry empty component", "version: 1\ndefault:\n  allowedRegistries: [\"ghcr.io//org\"]\n", "allowedRegistries"},
		{"bad ns key", "version: 1\ndefault: {}\nnamespaces:\n  \"a*\": {}\n", "namespace key"},
		{"not yaml", "version: [", "policy:"},
		{"exc no id", ex("justification: long enough text\n      cve: CVE-2024-0001\n      expires: 2027-01-01"), "id is required"},
		{"exc short justification", ex("id: e1\n      justification: no\n      cve: CVE-2024-0001\n      expires: 2027-01-01"), "justification"},
		{"exc both", ex(good + "cve: CVE-2024-0001\n      rule: requireDigest\n      image: a/b"), "exactly one"},
		{"exc neither", ex(good), "exactly one"},
		{"exc bad cve", ex(good + "cve: nope"), "invalid cve"},
		{"exc bad rule", ex(good + "rule: maxRisk\n      image: a/b"), "cannot be waived"},
		{"exc rule without image", ex(good + "rule: requireDigest"), "needs an image"},
		{"exc image with tag", ex(good + "rule: requireDigest\n      image: a/b:1"), "without tag"},
		{"exc bad digest", ex(good + "cve: CVE-2024-0001\n      image: sha256:xyz"), "valid digest"},
		{"exc no expiry", ex("id: e1\n      justification: long enough text\n      cve: CVE-2024-0001"), "expires is required"},
		{"exc bad expiry", ex("id: e1\n      justification: long enough text\n      cve: CVE-2024-0001\n      expires: tomorrow"), "YYYY-MM-DD"},
		{"exc duplicate id", "version: 1\ndefault:\n  exceptions:\n    - " + good + "cve: CVE-2024-0001\n    - " + good + "cve: CVE-2024-0002\n", "duplicate id"},
		{"too large", "version: 1\n#" + strings.Repeat("x", MaxPolicyBytes), "too large"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

type kevSet map[string]bool

func (k kevSet) Contains(id string) bool { return k[id] }

type epssSet map[string]float64

func (e epssSet) Lookup(id string) (float64, bool) { v, ok := e[id]; return v, ok }

func img(t *testing.T, raw string, ev *evidence.Evidence, err error) ImageInput {
	t.Helper()
	r, perr := imageref.Parse(raw)
	return ImageInput{Raw: raw, Ref: r, RefErr: perr, Evidence: ev, EvidenceErr: err}
}

func evd(at time.Time, f ...vuln.Finding) *evidence.Evidence {
	return &evidence.Evidence{Digest: dA, ScannedAt: at, Findings: f}
}

func fnd(id string, cvss float64) vuln.Finding {
	return vuln.Finding{ID: id, CVSS: cvss, Package: "pkg", Installed: "1.0", Fixed: "1.1"}
}

const pinned = "ghcr.io/org/app@" + dA

func TestEvaluateRules(t *testing.T) {
	kevs := kevSet{"CVE-2021-44228": true}
	const base = "version: 1\ndefault:\n"
	tests := []struct {
		name      string
		policy    string
		image     func(*testing.T) ImageInput
		failMode  FailMode
		outcome   Outcome
		rule      string
		contains  []string
		notInMsg  []string
		warnsHave string
	}{
		{
			name:    "clean image passes",
			policy:  base + "  maxRisk: 40\n  denyKev: true\n  requireDigest: true\n",
			image:   func(t *testing.T) ImageInput { return img(t, pinned, evd(now, fnd("CVE-2024-0001", 3.1)), nil) },
			outcome: OutcomeAllow,
		},
		{
			name:   "kev finding denied",
			policy: base + "  denyKev: true\n",
			image: func(t *testing.T) ImageInput {
				return img(t, pinned, evd(now, fnd("CVE-2021-44228", 10), fnd("CVE-2024-0001", 3)), nil)
			},
			outcome:  OutcomeDeny,
			rule:     RuleDenyKEV,
			contains: []string{"[denyKev]", "CVE-2021-44228", "KEV", "1 finding(s) in the CISA KEV", "ghcr.io/org/app@sha256:aaaaaaaaaaaa", `scope "_default"`},
			notInMsg: []string{"CVE-2024-0001"},
		},
		{
			name:   "kev hint from provider",
			policy: base + "  denyKev: true\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2030-0001", 5)
				f.KEVHint = true
				return img(t, pinned, evd(now, f), nil)
			},
			outcome:  OutcomeDeny,
			rule:     RuleDenyKEV,
			contains: []string{"CVE-2030-0001"},
		},
		{
			name:   "max risk exceeded",
			policy: base + "  maxRisk: 40\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2024-0009", 9.8)
				f.EPSS, f.HasEPSS = 0.9, true
				return img(t, pinned, evd(now, f), nil)
			},
			outcome:  OutcomeDeny,
			rule:     RuleMaxRisk,
			contains: []string{"[maxRisk]", "above max risk 40.0", "risk  47.7"},
		},
		{
			name:   "max risk equal is allowed",
			policy: base + "  maxRisk: 17.8\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2024-0010", 3.1)
				f.EPSS, f.HasEPSS = 0.002, true
				return img(t, pinned, evd(now, f), nil)
			},
			outcome: OutcomeAllow,
		},
		{
			name:     "acr raises risk",
			policy:   base + "  maxRisk: 40\n  assetCriticality: 8\n",
			image:    func(t *testing.T) ImageInput { return img(t, pinned, evd(now, fnd("CVE-2024-0011", 8.8)), nil) },
			outcome:  OutcomeDeny, // (0.25 + 0.176)/1.05 = 40.6
			rule:     RuleMaxRisk,
			contains: []string{"risk  40.6"},
		},
		{
			name:     "tag only with requireDigest",
			policy:   base + "  requireDigest: true\n  denyKev: true\n",
			image:    func(t *testing.T) ImageInput { return img(t, "ghcr.io/org/app:v1", nil, nil) },
			outcome:  OutcomeDeny,
			rule:     RuleRequireDigest,
			contains: []string{"not pinned by digest"},
			notInMsg: []string{"requireEvidence"},
		},
		{
			name:     "tag only without requireDigest falls to requireEvidence",
			policy:   base + "  denyKev: true\n",
			image:    func(t *testing.T) ImageInput { return img(t, "ghcr.io/org/app:v1", nil, nil) },
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"no digest to look up"},
		},
		{
			name:     "registry not allowed",
			policy:   base + "  allowedRegistries: [registry.example.com/team]\n  requireEvidence: allow\n",
			image:    func(t *testing.T) ImageInput { return img(t, pinned, evd(now), nil) },
			outcome:  OutcomeDeny,
			rule:     RuleAllowedRegistries,
			contains: []string{"registry is not in the allowed list"},
		},
		{
			name:    "registry allowed",
			policy:  base + "  allowedRegistries: [ghcr.io/org]\n",
			image:   func(t *testing.T) ImageInput { return img(t, pinned, evd(now), nil) },
			outcome: OutcomeAllow,
		},
		{
			name:     "missing evidence deny",
			policy:   base + "  denyKev: true\n  requireEvidence: deny\n",
			image:    func(t *testing.T) ImageInput { return img(t, pinned, nil, evidence.ErrNotFound) },
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"no scan report"},
		},
		{
			name:   "missing evidence warn",
			policy: base + "  denyKev: true\n  requireEvidence: warn\n",
			image: func(t *testing.T) ImageInput {
				return img(t, pinned, nil, fmt.Errorf("wrapped: %w", evidence.ErrNotFound))
			},
			outcome:   OutcomeWarn,
			warnsHave: "no scan report",
		},
		{
			name:    "missing evidence allow",
			policy:  base + "  denyKev: true\n  requireEvidence: allow\n",
			image:   func(t *testing.T) ImageInput { return img(t, pinned, nil, evidence.ErrNotFound) },
			outcome: OutcomeAllow,
		},
		{
			name:    "no evidence checks configured means no evidence needed",
			policy:  base + "  requireEvidence: allow\n",
			image:   func(t *testing.T) ImageInput { return img(t, pinned, nil, errors.New("not consulted")) },
			outcome: OutcomeAllow,
		},
		{
			name:   "provider failure fails closed",
			policy: base + "  denyKev: true\n  requireEvidence: allow\n",
			image: func(t *testing.T) ImageInput {
				return img(t, pinned, nil, errors.New("context deadline exceeded\nsecond line"))
			},
			failMode: FailClosed,
			outcome:  OutcomeDeny,
			rule:     RuleEvidenceError,
			contains: []string{"failing closed", "deadline exceeded"},
			notInMsg: []string{"second line"},
		},
		{
			name:      "provider failure fails open",
			policy:    base + "  denyKev: true\n",
			image:     func(t *testing.T) ImageInput { return img(t, pinned, nil, errors.New("malformed report")) },
			failMode:  FailOpen,
			outcome:   OutcomeWarn,
			warnsHave: "failing open",
		},
		{
			name:   "stale evidence follows requireEvidence",
			policy: base + "  denyKev: true\n  maxEvidenceAge: 24h\n",
			image: func(t *testing.T) ImageInput {
				return img(t, pinned, evd(now.Add(-72*time.Hour), fnd("CVE-2024-0001", 1)), nil)
			},
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"stale", "3d old"},
		},
		{
			name:   "fresh evidence within age",
			policy: base + "  denyKev: true\n  maxEvidenceAge: 24h\n",
			image: func(t *testing.T) ImageInput {
				return img(t, pinned, evd(now.Add(-2*time.Hour), fnd("CVE-2024-0001", 1)), nil)
			},
			outcome: OutcomeAllow,
		},
		{
			name:    "unknown scan time skips staleness",
			policy:  base + "  denyKev: true\n  maxEvidenceAge: 1h\n",
			image:   func(t *testing.T) ImageInput { return img(t, pinned, evd(time.Time{}, fnd("CVE-2024-0001", 1)), nil) },
			outcome: OutcomeAllow,
		},
		{
			name:   "ignoreUnfixed never drops a KEV finding without a fix",
			policy: base + "  denyKev: true\n  ignoreUnfixed: true\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2021-44228", 10)
				f.Fixed = ""
				return img(t, pinned, evd(now, f), nil)
			},
			outcome:  OutcomeDeny,
			rule:     RuleDenyKEV,
			contains: []string{"CVE-2021-44228", "(no fix)"},
		},
		{
			name:   "ignoreUnfixed drops a non KEV finding without a fix",
			policy: base + "  denyKev: true\n  maxRisk: 20\n  ignoreUnfixed: true\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2024-0001", 10)
				f.Fixed = ""
				return img(t, pinned, evd(now, f), nil)
			},
			outcome: OutcomeAllow,
		},
		{
			name:   "without ignoreUnfixed a non KEV finding without a fix counts for maxRisk",
			policy: base + "  maxRisk: 20\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2024-0001", 10)
				f.Fixed = ""
				return img(t, pinned, evd(now, f), nil)
			},
			outcome: OutcomeDeny,
			rule:    RuleMaxRisk,
		},
		{
			name:   "ignoreUnfixed keeps a KEV finding without a fix for maxRisk too",
			policy: base + "  maxRisk: 20\n  ignoreUnfixed: true\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2021-44228", 3)
				f.Fixed = ""
				return img(t, pinned, evd(now, f), nil)
			},
			outcome: OutcomeDeny,
			rule:    RuleMaxRisk,
		},
		{
			name:   "ignoreUnfixed keeps a finding the report itself marks as KEV",
			policy: base + "  denyKev: true\n  ignoreUnfixed: true\n",
			image: func(t *testing.T) ImageInput {
				f := fnd("CVE-2024-0002", 5)
				f.Fixed = ""
				f.KEVHint = true
				return img(t, pinned, evd(now, f), nil)
			},
			outcome: OutcomeDeny,
			rule:    RuleDenyKEV,
		},
		{
			name:     "malformed reference",
			policy:   base + "  requireEvidence: allow\n",
			image:    func(t *testing.T) ImageInput { return img(t, "bad ref\n", nil, nil) },
			outcome:  OutcomeDeny,
			rule:     RuleImageRef,
			contains: []string{"malformed image reference"},
		},
		{
			name:     "audit mode allows but reports",
			policy:   "version: 1\nmode: audit\ndefault:\n  denyKev: true\n",
			image:    func(t *testing.T) ImageInput { return img(t, pinned, evd(now, fnd("CVE-2021-44228", 10)), nil) },
			outcome:  OutcomeAuditDeny,
			rule:     RuleDenyKEV,
			contains: []string{"audit mode"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mustParse(t, tc.policy)
			fm := tc.failMode
			if fm == "" {
				fm = FailClosed
			}
			d := p.Evaluate(Env{Namespace: "ns", Now: now, KEV: kevs, FailMode: fm}, []ImageInput{tc.image(t)})
			if d.Outcome() != tc.outcome {
				t.Fatalf("outcome = %s, want %s\n%s", d.Outcome(), tc.outcome, d.Message())
			}
			if d.PrimaryRule() != tc.rule {
				t.Errorf("rule = %q, want %q", d.PrimaryRule(), tc.rule)
			}
			if wantAllowed := tc.outcome != OutcomeDeny; d.Allowed() != wantAllowed {
				t.Errorf("Allowed() = %v", d.Allowed())
			}
			msg := d.Message()
			for _, s := range tc.contains {
				if !strings.Contains(msg, s) {
					t.Errorf("message lacks %q:\n%s", s, msg)
				}
			}
			for _, s := range tc.notInMsg {
				if strings.Contains(msg, s) {
					t.Errorf("message should not contain %q:\n%s", s, msg)
				}
			}
			if tc.warnsHave != "" && !strings.Contains(strings.Join(d.ResponseWarnings(), "|"), tc.warnsHave) {
				t.Errorf("warnings %v lack %q", d.ResponseWarnings(), tc.warnsHave)
			}
			if tc.outcome == OutcomeAuditDeny && !strings.Contains(strings.Join(d.ResponseWarnings(), "|"), "would deny [denyKev]") {
				t.Errorf("audit warnings = %v", d.ResponseWarnings())
			}
		})
	}
}

func TestEPSSLookupUsedWhenReportHasNone(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault:\n  maxRisk: 40\n")
	in := img(t, pinned, evd(now, fnd("CVE-2024-0001", 9.8)), nil)
	// Without EPSS: (0.125 + 0.196)/1.05 = 30.6 -> allowed.
	if d := p.Evaluate(Env{Now: now}, []ImageInput{in}); !d.Allowed() {
		t.Fatalf("unexpected deny: %s", d.Message())
	}
	// With EPSS 0.9 from the CSV: 47.7 -> denied.
	d := p.Evaluate(Env{Now: now, EPSS: epssSet{"CVE-2024-0001": 0.9}}, []ImageInput{in})
	if d.Allowed() || !strings.Contains(d.Message(), "47.7") {
		t.Fatalf("EPSS not applied: %s", d.Message())
	}
}

func TestExceptions(t *testing.T) {
	const pol = `
version: 1
default:
  denyKev: true
  requireDigest: true
  exceptions:
    - id: cve-ok
      cve: CVE-2021-44228
      image: ghcr.io/org/app
      justification: mitigated by WAF rule 1234
      expires: 2026-11-10
    - id: cve-expired
      cve: CVE-2021-45046
      justification: was mitigated, review overdue
      expires: 2026-11-09
    - id: tag-ok
      rule: requireDigest
      image: ghcr.io/org/legacy
      justification: legacy job pinned by tag
      expires: 2026-12-31
    - id: digest-scope
      cve: CVE-2021-34527
      image: ` + dB + `
      justification: different image only
      expires: 2026-12-31
`
	kevs := kevSet{"CVE-2021-44228": true, "CVE-2021-45046": true, "CVE-2021-34527": true}
	p := mustParse(t, pol)
	run := func(at time.Time, imgs ...ImageInput) *Decision {
		return p.Evaluate(Env{Namespace: "ns", Now: at, KEV: kevs}, imgs)
	}

	t.Run("applies through end of expiry day", func(t *testing.T) {
		d := run(time.Date(2026, 11, 10, 23, 59, 0, 0, time.UTC), img(t, pinned, evd(now, fnd("CVE-2021-44228", 10)), nil))
		if !d.Allowed() || len(d.Applied) != 1 || d.Applied[0] != "cve-ok" {
			t.Fatalf("applied = %v\n%s", d.Applied, d.Message())
		}
		if !strings.Contains(strings.Join(d.ResponseWarnings(), "|"), "exception cve-ok applied") {
			t.Errorf("no notice: %v", d.ResponseWarnings())
		}
	})
	t.Run("expired exception does not apply and is reported", func(t *testing.T) {
		d := run(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), img(t, pinned, evd(now, fnd("CVE-2021-44228", 10)), nil))
		if d.Allowed() || len(d.Expired) != 1 || d.Expired[0] != "cve-ok" {
			t.Fatalf("expired = %v allowed=%v", d.Expired, d.Allowed())
		}
	})
	t.Run("expired global cve exception", func(t *testing.T) {
		d := run(now, img(t, pinned, evd(now, fnd("CVE-2021-45046", 9)), nil))
		if d.Allowed() || len(d.Expired) != 1 || d.Expired[0] != "cve-expired" {
			t.Fatalf("expired = %v", d.Expired)
		}
	})
	t.Run("scoped to a different image", func(t *testing.T) {
		d := run(now, img(t, "ghcr.io/other/app@"+dA, evd(now, fnd("CVE-2021-44228", 10)), nil))
		if d.Allowed() {
			t.Fatal("exception for ghcr.io/org/app must not cover another repository")
		}
	})
	t.Run("digest scoped", func(t *testing.T) {
		okImg := img(t, "ghcr.io/org/app@"+dB, evd(now, fnd("CVE-2021-34527", 9)), nil)
		if d := run(now, okImg); !d.Allowed() {
			t.Fatalf("digest exception should apply: %s", d.Message())
		}
		if d := run(now, img(t, pinned, evd(now, fnd("CVE-2021-34527", 9)), nil)); d.Allowed() {
			t.Fatal("digest exception applied to another digest")
		}
	})
	t.Run("rule exception waives requireDigest only for its image", func(t *testing.T) {
		if d := run(now, img(t, "ghcr.io/org/legacy:1", nil, nil)); d.Outcome() == OutcomeDeny && d.PrimaryRule() == RuleRequireDigest {
			t.Fatalf("requireDigest should be waived: %s", d.Message())
		}
		if d := run(now, img(t, "ghcr.io/org/other:1", nil, nil)); d.PrimaryRule() != RuleRequireDigest {
			t.Fatalf("other image must still be denied: %s", d.Message())
		}
	})
}

func TestTopFindingsAndLimits(t *testing.T) {
	p := mustParse(t, "version: 1\ndefault:\n  maxRisk: 0\n")
	var fs []vuln.Finding
	for i := 0; i < 6; i++ {
		fs = append(fs, fnd(fmt.Sprintf("CVE-2024-%04d", 1000+i), float64(i+3)))
	}
	d := p.Evaluate(Env{Now: now}, []ImageInput{img(t, pinned, evd(now, fs...), nil)})
	msg := d.Message()
	if !strings.Contains(msg, "... and 3 more") || strings.Count(msg, "CVE-2024-") != 3 {
		t.Fatalf("expected top 3 + overflow line:\n%s", msg)
	}
	if !strings.Contains(msg, "CVE-2024-1005") { // highest CVSS first
		t.Errorf("highest risk finding missing:\n%s", msg)
	}

	// More than maxViolations images.
	var imgs []ImageInput
	for i := 0; i < 8; i++ {
		imgs = append(imgs, img(t, fmt.Sprintf("ghcr.io/org/app%d@%s", i, dA), evd(now, fnd("CVE-2024-0001", 9)), nil))
	}
	d = p.Evaluate(Env{Now: now}, imgs)
	if !strings.Contains(d.Message(), "... and 3 more violation(s)") {
		t.Errorf("violation overflow missing:\n%s", d.Message())
	}
	if (&Decision{}).Message() != "" {
		t.Error("empty decision must have no message")
	}
}

func TestResponseWarningsCap(t *testing.T) {
	d := &Decision{Mode: ModeEnforce}
	for i := 0; i < 15; i++ {
		d.Warnings = append(d.Warnings, strings.Repeat("w", 400))
	}
	w := d.ResponseWarnings()
	if len(w) != maxWarnings || !strings.Contains(w[len(w)-1], "more warning(s) omitted") {
		t.Fatalf("len=%d last=%q", len(w), w[len(w)-1])
	}
	if len(w[0]) > maxWarningLen+3 {
		t.Errorf("warning not truncated: %d", len(w[0]))
	}
}

func TestSortOrder(t *testing.T) {
	mk := func(id string, risk float64, kev bool, epss, cvss float64) Scored {
		return Scored{Finding: vuln.Finding{ID: id, EPSS: epss, CVSS: cvss}, KEV: kev, Risk: risk}
	}
	s := []Scored{
		mk("C", 10, false, 0, 0), mk("B", 10, false, 0.5, 0), mk("A", 10, true, 0, 0),
		mk("E", 10, false, 0.5, 5), mk("D", 10, false, 0.5, 5), mk("Z", 20, false, 0, 0),
	}
	sortScored(s)
	got := ""
	for _, x := range s {
		got += x.ID
	}
	if got != "ZADEBC" {
		t.Errorf("order = %s, want ZADEBC", got)
	}
}
