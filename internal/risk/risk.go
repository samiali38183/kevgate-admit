// Package risk implements the finding risk model shared with the kevgate
// service:
//
//	risk = 100 * (0.40*kev + 0.25*acr/8 + 0.20*epss + 0.20*cvss/10) / 1.05
//
// The arithmetic order and the rounding rule match the Python implementation
// in kevgate/scoring.py so both produce identical one-decimal scores.
package risk

import (
	"fmt"
	"strconv"
)

// Weights of the model. They are exported for documentation and tests.
const (
	WeightKEV  = 0.40
	WeightACR  = 0.25
	WeightEPSS = 0.20
	WeightCVSS = 0.20
)

// The weights are copied into variables so that the sum and the products are
// evaluated in float64 at run time, exactly like the Python float arithmetic.
// Constant expressions would be evaluated with arbitrary precision and could
// differ from the reference in the last bit.
var (
	wKEV   float64 = WeightKEV
	wACR   float64 = WeightACR
	wEPSS  float64 = WeightEPSS
	wCVSS  float64 = WeightCVSS
	wTotal         = wKEV + wACR + wEPSS + wCVSS
)

// Score returns the 0..100 risk score rounded to one decimal.
// cvss must be in 0..10, epss in 0..1 and acr (asset criticality) in 1..8.
func Score(cvss, epss float64, acr int, kev bool) (float64, error) {
	if !(cvss >= 0 && cvss <= 10) {
		return 0, fmt.Errorf("risk: cvss %v out of range 0..10", cvss)
	}
	if !(epss >= 0 && epss <= 1) {
		return 0, fmt.Errorf("risk: epss %v out of range 0..1", epss)
	}
	if acr < 1 || acr > 8 {
		return 0, fmt.Errorf("risk: acr %d out of range 1..8", acr)
	}
	k := 0.0
	if kev {
		k = 1.0
	}
	// Explicit conversions stop the compiler from fusing multiply-adds, which
	// would change the last bit on some architectures.
	a := float64(wKEV * k)
	b := float64(wACR * (float64(acr) / 8))
	c := float64(wEPSS * epss)
	d := float64(wCVSS * (cvss / 10))
	raw := float64(float64(float64(a+b)+c) + d)
	s := float64(float64(raw/wTotal) * 100)
	if s > 100 {
		s = 100
	}
	if s < 0 {
		s = 0
	}
	return round1(s), nil
}

// round1 rounds to one decimal using the correctly rounded decimal expansion
// of the float64 value, which is what Python's round(x, 1) does.
func round1(x float64) float64 {
	v, err := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 1, 64), 64)
	if err != nil {
		return x
	}
	return v
}
