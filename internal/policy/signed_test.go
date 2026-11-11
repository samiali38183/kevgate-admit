package policy

import (
	"strings"
	"testing"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
)

func signedEv(state evidence.SigState, detail string, f ...string) *evidence.Evidence {
	ev := evd(now)
	for _, id := range f {
		ev.Findings = append(ev.Findings, fnd(id, 3))
	}
	ev.Signature, ev.SigDetail = state, detail
	return ev
}

func TestRequireSignedEvidence(t *testing.T) {
	kev := "CVE-2021-44228" // the KEV finding hidden in an unauthenticated report
	tests := []struct {
		name     string
		policy   string
		ev       *evidence.Evidence
		outcome  Outcome
		rule     string
		contains []string
		warnHave string
	}{
		{
			name:    "verified report is judged normally and passes",
			policy:  "version: 1\ndefault:\n  denyKev: true\n  requireSignedEvidence: true\n",
			ev:      signedEv(evidence.SigVerified, "", "CVE-2024-0001"),
			outcome: OutcomeAllow,
		},
		{
			name:     "verified report is still judged on content",
			policy:   "version: 1\ndefault:\n  denyKev: true\n  requireSignedEvidence: true\n",
			ev:       signedEv(evidence.SigVerified, "", kev),
			outcome:  OutcomeDeny,
			rule:     RuleDenyKEV,
			contains: []string{kev},
		},
		{
			name:     "unsigned report is denied by default",
			policy:   "version: 1\ndefault:\n  denyKev: true\n  requireSignedEvidence: true\n",
			ev:       signedEv(evidence.SigMissing, "no signature file sha256-aa.json.sig", "CVE-2024-0001"),
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"scan report is unsigned", "sha256-aa.json.sig", "signed evidence is required"},
		},
		{
			name:     "invalid signature is denied and its findings are not scored",
			policy:   "version: 1\ndefault:\n  denyKev: true\n  maxRisk: 10\n  requireSignedEvidence: true\n",
			ev:       signedEv(evidence.SigInvalid, "signature does not verify against a trusted key", "CVE-2024-0001"),
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"signature is invalid", "does not verify"},
		},
		{
			name:     "not checked (no key configured) is denied with a clear reason",
			policy:   "version: 1\ndefault:\n  denyKev: true\n  requireSignedEvidence: true\n",
			ev:       signedEv(evidence.SigNotChecked, ""),
			outcome:  OutcomeDeny,
			rule:     RuleRequireEvidence,
			contains: []string{"cannot be authenticated", "no trusted evidence key configured"},
		},
		{
			name:     "requireEvidence warn: warning, and the forged report is not used",
			policy:   "version: 1\ndefault:\n  denyKev: true\n  requireEvidence: warn\n  requireSignedEvidence: true\n",
			ev:       signedEv(evidence.SigInvalid, "signature does not verify against a trusted key", kev),
			outcome:  OutcomeWarn,
			warnHave: "signature is invalid",
		},
		{
			name:    "requireEvidence allow: admitted, the forged report is not used",
			policy:  "version: 1\ndefault:\n  denyKev: true\n  requireEvidence: allow\n  requireSignedEvidence: true\n",
			ev:      signedEv(evidence.SigMissing, "no signature file", kev),
			outcome: OutcomeAllow,
		},
		{
			name:    "without the option an unsigned report is judged as before",
			policy:  "version: 1\ndefault:\n  denyKev: true\n",
			ev:      signedEv(evidence.SigMissing, "no signature file", "CVE-2024-0001"),
			outcome: OutcomeAllow,
		},
		{
			name:     "without the option an unsigned KEV report is still denied on content",
			policy:   "version: 1\ndefault:\n  denyKev: true\n",
			ev:       signedEv(evidence.SigInvalid, "x", kev),
			outcome:  OutcomeDeny,
			rule:     RuleDenyKEV,
			contains: []string{kev},
		},
		{
			name: "a requireEvidence exception for the image waives the signature requirement",
			policy: `version: 1
default:
  denyKev: true
  requireSignedEvidence: true
  exceptions:
    - id: legacy-unsigned
      rule: requireEvidence
      image: ghcr.io/org/app
      justification: legacy image scanned before signing existed
      expires: 2027-01-01
`,
			ev:       signedEv(evidence.SigMissing, "no signature file", kev),
			outcome:  OutcomeWarn,
			warnHave: "exception legacy-unsigned applied",
		},
	}
	kevs := kevSet{kev: true}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mustParse(t, tc.policy)
			d := p.Evaluate(Env{Namespace: "ns", Now: now, KEV: kevs, FailMode: FailClosed},
				[]ImageInput{img(t, pinned, tc.ev, nil)})
			if d.Outcome() != tc.outcome {
				t.Fatalf("outcome = %s, want %s\n%s", d.Outcome(), tc.outcome, d.Message())
			}
			if d.PrimaryRule() != tc.rule {
				t.Errorf("rule = %q, want %q", d.PrimaryRule(), tc.rule)
			}
			msg := d.Message()
			for _, s := range tc.contains {
				if !strings.Contains(msg, s) {
					t.Errorf("message lacks %q:\n%s", s, msg)
				}
			}
			if tc.warnHave != "" && !strings.Contains(strings.Join(d.ResponseWarnings(), "|"), tc.warnHave) {
				t.Errorf("warnings %v lack %q", d.ResponseWarnings(), tc.warnHave)
			}
			// a forged report whose findings were not used must not leak into the message
			if tc.ev.Signature != evidence.SigVerified && tc.rule == RuleRequireEvidence && strings.Contains(msg, "CVE-2024-0001") {
				t.Errorf("unauthenticated findings appear in the message:\n%s", msg)
			}
		})
	}
}

func TestRequiresSignedEvidence(t *testing.T) {
	cases := map[string]bool{
		"version: 1\ndefault: {}\n":                                                             false,
		"version: 1\ndefault:\n  requireSignedEvidence: true\n":                                 true,
		"version: 1\ndefault: {}\nnamespaces:\n  prod:\n    requireSignedEvidence: true\n":      true,
		"version: 1\ndefault: {}\nnamespaces:\n  dev:\n    requireSignedEvidence: false\n":      false,
		"version: 1\ndefault:\n  requireSignedEvidence: false\nnamespaces:\n  a: {}\n  b: {}\n": false,
	}
	for y, want := range cases {
		if got := mustParse(t, y).RequiresSignedEvidence(); got != want {
			t.Errorf("%q: %v, want %v", y, got, want)
		}
	}
}

func TestRequireSignedEvidenceRejectsNonBool(t *testing.T) {
	if _, err := Parse([]byte("version: 1\ndefault:\n  requireSignedEvidence: sometimes\n")); err == nil {
		t.Fatal("non boolean accepted")
	}
}
