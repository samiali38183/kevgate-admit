// Package policy defines the YAML policy, validates it and evaluates images
// against it. Evaluation is pure: all evidence is looked up by the caller.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/samiali38183/kevgate-admit/internal/imageref"
)

// Mode selects between enforcing and audit (dry-run) behaviour.
type Mode string

// Modes.
const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

// Action is what to do when evidence is missing.
type Action string

// Actions for requireEvidence.
const (
	ActionDeny  Action = "deny"
	ActionWarn  Action = "warn"
	ActionAllow Action = "allow"
)

// FailMode decides what happens when the evidence source itself fails
// (timeout, malformed report) or the webhook hits an internal error.
type FailMode string

// Fail modes.
const (
	FailClosed FailMode = "closed"
	FailOpen   FailMode = "open"
)

// Rule names as they appear in messages, metrics and exceptions.
const (
	RuleMaxRisk           = "maxRisk"
	RuleDenyKEV           = "denyKev"
	RuleRequireDigest     = "requireDigest"
	RuleRequireEvidence   = "requireEvidence"
	RuleAllowedRegistries = "allowedRegistries"
	RuleImageRef          = "imageRef"
	RuleEvidenceError     = "evidenceError"
)

const (
	// DefaultACR is the asset criticality used when a rule does not set one.
	DefaultACR = 4
	// maxPolicyExceptions bounds the exception list of one rule.
	maxExceptions = 500
)

// Exception waives one rule or one CVE for a scope until it expires.
type Exception struct {
	ID            string
	CVE           string // waive this CVE; image optional
	Rule          string // waive this rule; image required
	Image         string // digest, or repository name (registry/repo), or empty for any
	Justification string
	Expires       time.Time // first instant at which the exception no longer applies
}

// Rule is the compiled rule set for one namespace scope.
type Rule struct {
	Mode              Mode // empty means: inherit the policy mode
	MaxRisk           *float64
	DenyKEV           bool
	RequireDigest     bool
	RequireEvidence   Action
	AllowedRegistries []string
	AssetCriticality  int
	MaxEvidenceAge    time.Duration // zero disables the staleness check
	IgnoreUnfixed     bool
	Exceptions        []Exception
}

// NeedsEvidence reports whether any check of the rule uses scan evidence.
func (r *Rule) NeedsEvidence() bool {
	return r.MaxRisk != nil || r.DenyKEV || r.RequireEvidence != ActionAllow
}

// Policy is a validated policy document.
type Policy struct {
	Mode       Mode
	Default    Rule
	Namespaces map[string]Rule
}

// RuleFor returns the rule that applies to a namespace and the scope name used
// in logs and metrics: the namespace when it has its own rule, else "_default".
func (p *Policy) RuleFor(ns string) (string, *Rule) {
	if r, ok := p.Namespaces[ns]; ok {
		return ns, &r
	}
	return "_default", &p.Default
}

// EffectiveMode resolves the rule mode against the policy mode.
func (p *Policy) EffectiveMode(r *Rule) Mode {
	if r.Mode != "" {
		return r.Mode
	}
	return p.Mode
}

type rawPolicy struct {
	Version    int                `json:"version"`
	Mode       string             `json:"mode"`
	Default    *rawRule           `json:"default"`
	Namespaces map[string]rawRule `json:"namespaces"`
}

type rawRule struct {
	Mode              string         `json:"mode"`
	MaxRisk           *float64       `json:"maxRisk"`
	DenyKEV           bool           `json:"denyKev"`
	RequireDigest     bool           `json:"requireDigest"`
	RequireEvidence   string         `json:"requireEvidence"`
	AllowedRegistries []string       `json:"allowedRegistries"`
	AssetCriticality  int            `json:"assetCriticality"`
	MaxEvidenceAge    string         `json:"maxEvidenceAge"`
	IgnoreUnfixed     bool           `json:"ignoreUnfixed"`
	Exceptions        []rawException `json:"exceptions"`
}

type rawException struct {
	ID            string `json:"id"`
	CVE           string `json:"cve"`
	Rule          string `json:"rule"`
	Image         string `json:"image"`
	Justification string `json:"justification"`
	Expires       string `json:"expires"`
}

// MaxPolicyBytes bounds a policy file.
const MaxPolicyBytes = 1 << 20

// Parse decodes a policy with strict field checking and validates it.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, errors.New("policy: file too large")
	}
	var raw rawPolicy
	if err := yaml.UnmarshalStrict(data, &raw); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if raw.Version != 1 {
		return nil, fmt.Errorf("policy: version must be 1, got %d", raw.Version)
	}
	mode, err := parseMode(raw.Mode, false)
	if err != nil {
		return nil, err
	}
	if raw.Default == nil {
		return nil, errors.New("policy: a default rule is required")
	}
	p := &Policy{Mode: mode, Namespaces: map[string]Rule{}}
	if p.Default, err = compileRule("default", *raw.Default); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(raw.Namespaces))
	for ns := range raw.Namespaces {
		names = append(names, ns)
	}
	sort.Strings(names)
	for _, ns := range names {
		if ns == "" || len(ns) > 63 || strings.ContainsAny(ns, " /*") {
			return nil, fmt.Errorf("policy: invalid namespace key %q", ns)
		}
		r, err := compileRule("namespaces."+ns, raw.Namespaces[ns])
		if err != nil {
			return nil, err
		}
		p.Namespaces[ns] = r
	}
	return p, nil
}

func parseMode(s string, allowEmpty bool) (Mode, error) {
	switch Mode(s) {
	case ModeEnforce, ModeAudit:
		return Mode(s), nil
	case "":
		if allowEmpty {
			return "", nil
		}
		return ModeEnforce, nil
	}
	return "", fmt.Errorf("policy: mode must be enforce or audit, got %q", s)
}

func compileRule(where string, in rawRule) (Rule, error) {
	r := Rule{
		DenyKEV:          in.DenyKEV,
		RequireDigest:    in.RequireDigest,
		AssetCriticality: in.AssetCriticality,
		IgnoreUnfixed:    in.IgnoreUnfixed,
		MaxRisk:          in.MaxRisk,
	}
	var err error
	if r.Mode, err = parseMode(in.Mode, true); err != nil {
		return r, fmt.Errorf("%s: %w", where, err)
	}
	if r.MaxRisk != nil && !(*r.MaxRisk >= 0 && *r.MaxRisk <= 100) {
		return r, fmt.Errorf("policy: %s.maxRisk must be in 0..100", where)
	}
	switch Action(in.RequireEvidence) {
	case "":
		r.RequireEvidence = ActionDeny
	case ActionDeny, ActionWarn, ActionAllow:
		r.RequireEvidence = Action(in.RequireEvidence)
	default:
		return r, fmt.Errorf("policy: %s.requireEvidence must be deny, warn or allow", where)
	}
	if r.AssetCriticality == 0 {
		r.AssetCriticality = DefaultACR
	}
	if r.AssetCriticality < 1 || r.AssetCriticality > 8 {
		return r, fmt.Errorf("policy: %s.assetCriticality must be in 1..8", where)
	}
	if in.MaxEvidenceAge != "" {
		d, err := time.ParseDuration(in.MaxEvidenceAge)
		if err != nil || d <= 0 {
			return r, fmt.Errorf("policy: %s.maxEvidenceAge must be a positive duration such as 168h", where)
		}
		r.MaxEvidenceAge = d
	}
	for _, reg := range in.AllowedRegistries {
		if reg == "" || strings.Contains(reg, "://") || strings.ContainsAny(reg, " *@") || strings.HasPrefix(reg, "/") {
			return r, fmt.Errorf("policy: %s.allowedRegistries: invalid entry %q (use host or host/path, no scheme)", where, reg)
		}
		r.AllowedRegistries = append(r.AllowedRegistries, strings.ToLower(strings.TrimSuffix(reg, "/")))
	}
	if len(in.Exceptions) > maxExceptions {
		return r, fmt.Errorf("policy: %s has more than %d exceptions", where, maxExceptions)
	}
	seen := map[string]bool{}
	for i, e := range in.Exceptions {
		ex, err := compileException(e)
		if err != nil {
			return r, fmt.Errorf("policy: %s.exceptions[%d]: %w", where, i, err)
		}
		if seen[ex.ID] {
			return r, fmt.Errorf("policy: %s.exceptions[%d]: duplicate id %q", where, i, ex.ID)
		}
		seen[ex.ID] = true
		r.Exceptions = append(r.Exceptions, ex)
	}
	return r, nil
}

var waivableRules = map[string]bool{
	RuleRequireDigest: true, RuleAllowedRegistries: true, RuleRequireEvidence: true,
}

func compileException(e rawException) (Exception, error) {
	ex := Exception{ID: e.ID, Justification: strings.TrimSpace(e.Justification), Image: e.Image}
	if e.ID == "" || len(e.ID) > 64 || strings.ContainsAny(e.ID, " \t\r\n") {
		return ex, errors.New("id is required (no spaces, at most 64 characters)")
	}
	if len(ex.Justification) < 10 {
		return ex, errors.New("justification is required (at least 10 characters)")
	}
	if (e.CVE == "") == (e.Rule == "") {
		return ex, errors.New("set exactly one of cve or rule")
	}
	if e.CVE != "" {
		ex.CVE = strings.ToUpper(e.CVE)
		if !validCVE(ex.CVE) {
			return ex, fmt.Errorf("invalid cve %q", e.CVE)
		}
	} else {
		if !waivableRules[e.Rule] {
			return ex, fmt.Errorf("rule %q cannot be waived (allowed: requireDigest, allowedRegistries, requireEvidence)", e.Rule)
		}
		if e.Image == "" {
			return ex, errors.New("a rule exception needs an image (digest or registry/repository)")
		}
		ex.Rule = e.Rule
	}
	if e.Image != "" && !strings.HasPrefix(e.Image, "sha256:") && !strings.HasPrefix(e.Image, "sha512:") {
		ref, err := imageref.Parse(e.Image)
		if err != nil || ref.Tag != "" || ref.Digest != "" {
			return ex, fmt.Errorf("image %q must be a digest or a repository name without tag", e.Image)
		}
		ex.Image = ref.Name()
	}
	if strings.HasPrefix(e.Image, "sha") && !validDigest(e.Image) {
		return ex, fmt.Errorf("image %q is not a valid digest", e.Image)
	}
	if e.Expires == "" {
		return ex, errors.New("expires is required")
	}
	t, err := parseExpiry(e.Expires)
	if err != nil {
		return ex, err
	}
	ex.Expires = t
	return ex, nil
}

// parseExpiry accepts YYYY-MM-DD (valid through the end of that day, UTC) or
// an RFC 3339 timestamp (valid until that instant).
func parseExpiry(s string) (time.Time, error) {
	if d, err := time.Parse("2006-01-02", s); err == nil {
		return d.Add(24 * time.Hour), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expires %q must be YYYY-MM-DD or RFC 3339", s)
}
