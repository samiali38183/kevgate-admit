// Package epss loads EPSS scores from a local CSV file in the FIRST.org
// format (cve,epss,percentile, optionally preceded by # comment lines).
package epss

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,19}$`)

// Table maps CVE IDs to EPSS probabilities.
type Table struct {
	m map[string]float64
}

// Len returns the number of entries.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.m)
}

// Lookup returns the EPSS score for a CVE. It is safe to call on a nil table.
func (t *Table) Lookup(cve string) (float64, bool) {
	if t == nil {
		return 0, false
	}
	v, ok := t.m[strings.ToUpper(cve)]
	return v, ok
}

// Parse reads a CSV document. Every data row must have a valid CVE ID and a
// score in 0..1; a bad row rejects the whole file so a corrupt download never
// silently replaces a good table.
func Parse(data []byte) (*Table, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	t := &Table{m: make(map[string]float64)}
	line := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		line++
		if len(rec) < 2 {
			return nil, fmt.Errorf("epss: row %d: need at least cve,epss", line)
		}
		id := strings.ToUpper(strings.TrimSpace(rec[0]))
		if line == 1 && id == "CVE" {
			continue
		}
		if !cveRe.MatchString(id) {
			return nil, fmt.Errorf("epss: row %d: invalid CVE id", line)
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		if err != nil || !(v >= 0 && v <= 1) {
			return nil, fmt.Errorf("epss: row %d: score must be a number in 0..1", line)
		}
		t.m[id] = v
	}
	if len(t.m) == 0 {
		return nil, errors.New("epss: no entries")
	}
	return t, nil
}
