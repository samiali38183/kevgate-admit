package policy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/imageref"
	"github.com/samiali38183/kevgate-admit/internal/risk"
	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)

func validCVE(s string) bool    { return cveRe.MatchString(s) }
func validDigest(s string) bool { return evidence.ValidDigest(s) }

// KEVSet answers whether a CVE is in the CISA KEV catalog.
type KEVSet interface{ Contains(id string) bool }

// EPSSSource supplies EPSS scores for findings whose report carries none.
type EPSSSource interface {
	Lookup(id string) (float64, bool)
}

// Env is everything besides the images that evaluation depends on.
type Env struct {
	Namespace string
	Now       time.Time
	KEV       KEVSet
	EPSS      EPSSSource
	FailMode  FailMode
}

// ImageInput is one image of the workload together with its evidence lookup
// result. EvidenceErr is nil when Evidence is set, evidence.ErrNotFound (maybe
// wrapped) when the source had nothing, and any other error for a failure of
// the source itself.
type ImageInput struct {
	Raw         string
	Ref         imageref.Ref
	RefErr      error
	Evidence    *evidence.Evidence
	EvidenceErr error
}

// Scored is a finding with its KEV membership and risk score.
type Scored struct {
	vuln.Finding
	KEV  bool
	Risk float64
}

// Violation is one rule firing for one image.
type Violation struct {
	Rule     string
	Image    string
	Detail   string
	Findings []Scored // top findings only
	More     int      // findings not listed
}

// Outcome is the metric and log label of a decision.
type Outcome string

// Outcomes.
const (
	OutcomeAllow     Outcome = "allow"
	OutcomeWarn      Outcome = "warn"
	OutcomeDeny      Outcome = "deny"
	OutcomeAuditDeny Outcome = "audit_deny"
	OutcomeError     Outcome = "error"
)

// Decision is the result of evaluating a workload.
type Decision struct {
	Namespace  string
	Scope      string
	Mode       Mode
	Violations []Violation
	Warnings   []string
	Applied    []string // exception IDs that waived something
	Expired    []string // exception IDs that matched but had expired
}

// Outcome classifies the decision.
func (d *Decision) Outcome() Outcome {
	switch {
	case len(d.Violations) > 0 && d.Mode == ModeAudit:
		return OutcomeAuditDeny
	case len(d.Violations) > 0:
		return OutcomeDeny
	case len(d.Warnings) > 0:
		return OutcomeWarn
	}
	return OutcomeAllow
}

// Allowed reports whether the request may proceed.
func (d *Decision) Allowed() bool {
	return len(d.Violations) == 0 || d.Mode == ModeAudit
}

// PrimaryRule is the first rule that fired, or "" when none did.
func (d *Decision) PrimaryRule() string {
	if len(d.Violations) == 0 {
		return ""
	}
	return d.Violations[0].Rule
}

const (
	topFindings   = 3
	maxViolations = 5
	maxWarnings   = 10
	maxWarningLen = 240
)

// Evaluate checks the images of one workload against the rule for the namespace.
func (p *Policy) Evaluate(env Env, images []ImageInput) *Decision {
	scope, rule := p.RuleFor(env.Namespace)
	d := &Decision{Namespace: env.Namespace, Scope: scope, Mode: p.EffectiveMode(rule)}
	ev := evaluator{rule: rule, env: env, d: d, applied: map[string]bool{}, expired: map[string]bool{}}
	for i := range images {
		ev.image(&images[i])
	}
	sort.Strings(d.Applied)
	sort.Strings(d.Expired)
	return d
}

type evaluator struct {
	rule    *Rule
	env     Env
	d       *Decision
	applied map[string]bool
	expired map[string]bool
}

func (e *evaluator) violate(rule, image, detail string, f []Scored) {
	v := Violation{Rule: rule, Image: image, Detail: detail}
	if len(f) > topFindings {
		v.More = len(f) - topFindings
		f = f[:topFindings]
	}
	v.Findings = f
	e.d.Violations = append(e.d.Violations, v)
}

func (e *evaluator) warn(rule, image, detail string) {
	e.d.Warnings = append(e.d.Warnings, fmt.Sprintf("[%s] %s: %s", rule, image, detail))
}

// scopeMatches reports whether an exception's image scope covers the image.
func scopeMatches(ex *Exception, ref imageref.Ref) bool {
	switch {
	case ex.Image == "":
		return true
	case strings.HasPrefix(ex.Image, "sha"):
		return ref.Digest == ex.Image
	}
	return ref.Name() == ex.Image
}

// waived reports whether an unexpired exception covers the match. Expired
// exceptions that would have matched are recorded and do not waive anything.
func (e *evaluator) waived(match func(*Exception) bool) bool {
	for i := range e.rule.Exceptions {
		ex := &e.rule.Exceptions[i]
		if !match(ex) {
			continue
		}
		if !e.env.Now.Before(ex.Expires) {
			if !e.expired[ex.ID] {
				e.expired[ex.ID] = true
				e.d.Expired = append(e.d.Expired, ex.ID)
			}
			continue
		}
		if !e.applied[ex.ID] {
			e.applied[ex.ID] = true
			e.d.Applied = append(e.d.Applied, ex.ID)
			e.d.Warnings = append(e.d.Warnings, fmt.Sprintf("exception %s applied (expires %s)", ex.ID, ex.Expires.UTC().Format("2006-01-02")))
		}
		return true
	}
	return false
}

func (e *evaluator) ruleWaived(rule string, ref imageref.Ref) bool {
	return e.waived(func(x *Exception) bool { return x.Rule == rule && scopeMatches(x, ref) })
}

func (e *evaluator) image(in *ImageInput) {
	if in.RefErr != nil {
		e.violate(RuleImageRef, clipRaw(in.Raw), "malformed image reference: "+reason(in.RefErr), nil)
		return
	}
	ref := in.Ref
	name := ref.Short()

	if len(e.rule.AllowedRegistries) > 0 {
		ok := false
		for _, reg := range e.rule.AllowedRegistries {
			if ref.MatchesRegistry(reg) {
				ok = true
				break
			}
		}
		if !ok && !e.ruleWaived(RuleAllowedRegistries, ref) {
			e.violate(RuleAllowedRegistries, name, "registry is not in the allowed list", nil)
		}
	}

	digestFailed := false
	if e.rule.RequireDigest && !ref.Pinned() && !e.ruleWaived(RuleRequireDigest, ref) {
		e.violate(RuleRequireDigest, name, "image is not pinned by digest; tags are mutable", nil)
		digestFailed = true
	}
	if digestFailed || !e.rule.NeedsEvidence() {
		return
	}

	switch {
	case !ref.Pinned():
		e.missing(ref, name, "no digest to look up scan evidence for")
	case in.EvidenceErr != nil && errors.Is(in.EvidenceErr, evidence.ErrNotFound):
		e.missing(ref, name, "no scan report for this digest")
	case in.EvidenceErr != nil:
		e.sourceFailure(name, in.EvidenceErr)
	case in.Evidence == nil:
		e.missing(ref, name, "no scan report for this digest")
	default:
		e.findings(ref, name, in.Evidence)
	}
}

func (e *evaluator) missing(ref imageref.Ref, name, detail string) {
	switch e.rule.RequireEvidence {
	case ActionAllow:
	case ActionWarn:
		e.warn(RuleRequireEvidence, name, detail)
	default:
		if !e.ruleWaived(RuleRequireEvidence, ref) {
			e.violate(RuleRequireEvidence, name, detail, nil)
		}
	}
}

func (e *evaluator) sourceFailure(name string, err error) {
	detail := "evidence source failed: " + reason(err)
	if e.env.FailMode == FailOpen {
		e.warn(RuleEvidenceError, name, detail+" (failing open)")
		return
	}
	e.violate(RuleEvidenceError, name, detail+" (failing closed)", nil)
}

func (e *evaluator) findings(ref imageref.Ref, name string, ev *evidence.Evidence) {
	if e.rule.MaxEvidenceAge > 0 && !ev.ScannedAt.IsZero() {
		if age := e.env.Now.Sub(ev.ScannedAt); age > e.rule.MaxEvidenceAge {
			e.missing(ref, name, fmt.Sprintf("scan report is stale (%s old, limit %s)", roundAge(age), e.rule.MaxEvidenceAge))
			return
		}
	}
	scored := make([]Scored, 0, len(ev.Findings))
	for _, f := range ev.Findings {
		epss := f.EPSS
		if !f.HasEPSS && e.env.EPSS != nil {
			if v, ok := e.env.EPSS.Lookup(f.ID); ok {
				epss = v
			}
		}
		kev := f.KEVHint || (e.env.KEV != nil && e.env.KEV.Contains(f.ID))
		// ignoreUnfixed never applies to a KEV finding: a vulnerability exploited in
		// the wild is the last one to ignore for lack of a fix. Only an
		// explicit, expiring CVE exception can waive it.
		if e.rule.IgnoreUnfixed && f.Fixed == "" && !kev {
			continue
		}
		if e.waived(func(x *Exception) bool { return x.CVE == f.ID && scopeMatches(x, ref) }) {
			continue
		}
		r, err := risk.Score(f.CVSS, epss, e.rule.AssetCriticality, kev)
		if err != nil {
			// Evidence providers validate ranges, so this is a defect in the
			// source; treat it like a source failure rather than scoring zero.
			e.sourceFailure(name, err)
			return
		}
		scored = append(scored, Scored{Finding: f, KEV: kev, Risk: r})
	}
	sortScored(scored)

	if e.rule.DenyKEV {
		var k []Scored
		for _, s := range scored {
			if s.KEV {
				k = append(k, s)
			}
		}
		if len(k) > 0 {
			e.violate(RuleDenyKEV, name, fmt.Sprintf("%d finding(s) in the CISA KEV catalog", len(k)), k)
		}
	}
	if e.rule.MaxRisk != nil {
		var over []Scored
		for _, s := range scored {
			if s.Risk > *e.rule.MaxRisk {
				over = append(over, s)
			}
		}
		if len(over) > 0 {
			e.violate(RuleMaxRisk, name,
				fmt.Sprintf("%d finding(s) above max risk %.1f (highest %.1f)", len(over), *e.rule.MaxRisk, over[0].Risk), over)
		}
	}
}

func sortScored(s []Scored) {
	sort.Slice(s, func(i, j int) bool {
		a, b := s[i], s[j]
		switch {
		case a.Risk != b.Risk:
			return a.Risk > b.Risk
		case a.KEV != b.KEV:
			return a.KEV
		case a.EPSS != b.EPSS:
			return a.EPSS > b.EPSS
		case a.CVSS != b.CVSS:
			return a.CVSS > b.CVSS
		}
		return a.ID < b.ID
	})
}

func roundAge(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return d.Round(time.Minute).String()
}

// reason returns a short, single-line error description for messages. Raw
// provider errors can contain paths; only the first line is kept and the
// length is capped.
func reason(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clip(s, 160)
}

func clipRaw(s string) string { return clip(strings.Map(printable, s), 80) }

func printable(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return '?'
	}
	return r
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// Message renders the human-readable denial text. It lists each violated rule
// with the top findings. It is empty when there are no violations.
func (d *Decision) Message() string {
	if len(d.Violations) == 0 {
		return ""
	}
	var b strings.Builder
	verb := "denied by policy"
	if d.Mode == ModeAudit {
		verb = "would be denied by policy (audit mode)"
	}
	fmt.Fprintf(&b, "kevgate-admit: request %s (namespace %q, scope %q)\n", verb, d.Namespace, d.Scope)
	for i, v := range d.Violations {
		if i == maxViolations {
			fmt.Fprintf(&b, "... and %d more violation(s)\n", len(d.Violations)-maxViolations)
			break
		}
		fmt.Fprintf(&b, "- [%s] %s: %s\n", v.Rule, v.Image, v.Detail)
		for _, f := range v.Findings {
			fmt.Fprintf(&b, "    %s\n", findingLine(f))
		}
		if v.More > 0 {
			fmt.Fprintf(&b, "    ... and %d more\n", v.More)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func findingLine(f Scored) string {
	kev := "    "
	if f.KEV {
		kev = "KEV "
	}
	pkg := ""
	if f.Package != "" {
		pkg = "  " + f.Package
		if f.Installed != "" {
			pkg += " " + f.Installed
		}
		if f.Fixed != "" {
			pkg += " (fixed " + f.Fixed + ")"
		} else {
			pkg += " (no fix)"
		}
	}
	return fmt.Sprintf("%-16s %s risk %5.1f%s", f.ID, kev, f.Risk, pkg)
}

// ResponseWarnings returns the strings for AdmissionResponse.warnings: the
// per-violation summary in audit mode plus any non-blocking notices.
func (d *Decision) ResponseWarnings() []string {
	var out []string
	if d.Mode == ModeAudit {
		for _, v := range d.Violations {
			out = append(out, fmt.Sprintf("kevgate-admit audit: would deny [%s] %s: %s", v.Rule, v.Image, v.Detail))
		}
	}
	for _, w := range d.Warnings {
		out = append(out, "kevgate-admit: "+w)
	}
	if len(out) > maxWarnings {
		out = append(out[:maxWarnings-1], fmt.Sprintf("kevgate-admit: %d more warning(s) omitted", len(out)-maxWarnings+1))
	}
	for i, w := range out {
		out[i] = clip(w, maxWarningLen)
	}
	return out
}
