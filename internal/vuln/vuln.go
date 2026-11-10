// Package vuln holds the finding type shared by all evidence sources.
package vuln

import "regexp"

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$`)

// ValidID reports whether s is a plausible advisory identifier (CVE, GHSA, ...).
// It keeps control characters and whitespace out of messages and logs.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Finding is one vulnerability reported for an image.
type Finding struct {
	ID        string  // CVE or advisory identifier, upper-case
	Package   string  // affected package name
	Installed string  // installed version
	Fixed     string  // first fixed version, empty when no fix is known
	Severity  string  // scanner severity label
	CVSS      float64 // 0..10
	EPSS      float64 // 0..1, valid only when HasEPSS
	HasEPSS   bool
	KEVHint   bool // evidence source says the finding is in KEV
}
