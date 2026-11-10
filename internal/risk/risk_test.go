package risk

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// Hand-computed from the formula
// 100 * (0.40*kev + 0.25*acr/8 + 0.20*epss + 0.20*cvss/10) / 1.05
// using exact rational arithmetic, then rounded to one decimal.
func TestScoreHandComputed(t *testing.T) {
	tests := []struct {
		name string
		cvss float64
		epss float64
		acr  int
		kev  bool
		want float64
	}{
		{"all maximum", 10, 1, 8, true, 100.0},
		{"all minimum no kev", 0, 0, 1, false, 3.0},       // 0.03125/1.05 = 2.976
		{"mid values no kev", 7.5, 0.5, 4, false, 35.7},   // 0.375/1.05 = 35.714
		{"kev high everything", 9.8, 0.97, 8, true, 99.0}, // 1.04/1.05 = 99.047
		{"low acr", 5, 0.01, 2, false, 15.7},              // 0.1645/1.05 = 15.666
		{"kev mid", 6.1, 0.05, 5, true, 65.5},             // 0.68825/1.05 = 65.547
		{"kev only plus acr 8", 0, 0, 8, true, 61.9},      // 0.65/1.05 = 61.904
		{"cvss only", 10, 0, 1, false, 22.0},              // 0.23125/1.05 = 22.023
		{"typical low", 3.1, 0.002, 4, false, 17.8},       // 0.1874/1.05 = 17.847
		{"typical medium high", 8.8, 0.3, 6, false, 40.3}, // 0.4235/1.05 = 40.333
		{"kev with acr 4 only", 0, 0, 4, true, 50.0},      // 0.525/1.05 = 0.5 exactly
		{"max non-kev at acr 8", 10, 1, 8, false, 61.9},   // 0.65/1.05 = 61.904
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Score(tc.cvss, tc.epss, tc.acr, tc.kev)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Score(%v,%v,%d,%v) = %v, want %v", tc.cvss, tc.epss, tc.acr, tc.kev, got, tc.want)
			}
		})
	}
}

func TestScoreRejectsOutOfRange(t *testing.T) {
	tests := []struct {
		name string
		cvss float64
		epss float64
		acr  int
	}{
		{"cvss negative", -0.1, 0, 4},
		{"cvss above 10", 10.1, 0, 4},
		{"cvss NaN", math.NaN(), 0, 4},
		{"epss negative", 5, -0.01, 4},
		{"epss above 1", 5, 1.01, 4},
		{"epss NaN", 5, math.NaN(), 4},
		{"epss Inf", 5, math.Inf(1), 4},
		{"acr zero", 5, 0.5, 0},
		{"acr nine", 5, 0.5, 9},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Score(tc.cvss, tc.epss, tc.acr, false); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestScoreMonotonic(t *testing.T) {
	base, _ := Score(5, 0.5, 4, false)
	for name, got := range map[string]func() (float64, error){
		"kev":  func() (float64, error) { return Score(5, 0.5, 4, true) },
		"cvss": func() (float64, error) { return Score(6, 0.5, 4, false) },
		"epss": func() (float64, error) { return Score(5, 0.6, 4, false) },
		"acr":  func() (float64, error) { return Score(5, 0.5, 5, false) },
	} {
		v, err := got()
		if err != nil {
			t.Fatal(err)
		}
		if v <= base {
			t.Errorf("raising %s: %v not above %v", name, v, base)
		}
	}
}

// TestParityWithPythonKevgate compares against vectors produced by running the
// Python kevgate.scoring.risk_score (see scripts/gen_parity.py).
func TestParityWithPythonKevgate(t *testing.T) {
	raw, err := os.ReadFile("testdata/parity_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		CVSS float64 `json:"cvss"`
		EPSS float64 `json:"epss"`
		ACR  int     `json:"acr"`
		KEV  bool    `json:"kev"`
		Risk float64 `json:"risk"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 1000 {
		t.Fatalf("only %d vectors; regenerate with scripts/gen_parity.py", len(vectors))
	}
	for i, v := range vectors {
		got, err := Score(v.CVSS, v.EPSS, v.ACR, v.KEV)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if got != v.Risk {
			t.Fatalf("vector %d (cvss=%v epss=%v acr=%d kev=%v): go=%v python=%v", i, v.CVSS, v.EPSS, v.ACR, v.KEV, got, v.Risk)
		}
	}
	t.Logf("%d vectors identical to the Python implementation", len(vectors))
}

func TestRound1TieBehaviour(t *testing.T) {
	// Python: round(0.25, 1) == 0.2 and round(0.35, 1) == 0.3 (0.35 is stored
	// slightly below the tie), round(2.675, 2) style cases follow the exact
	// binary value. strconv does the same.
	for in, want := range map[float64]float64{0.25: 0.2, 0.35: 0.3, 0.45: 0.5, 99.95: 100.0, 12.34: 12.3} {
		if got := round1(in); got != want {
			t.Errorf("round1(%v) = %v, want %v", in, got, want)
		}
	}
}
