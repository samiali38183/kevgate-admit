package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

const (
	httpMaxBody  = 4 << 20
	httpMaxItems = 1000
)

// HTTPProvider asks a kevgate service for the findings recorded against an
// image digest, using GET /queue?asset=<digest>&limit=N. kevgate does not
// store scan timestamps, so ScannedAt is zero and the maxEvidenceAge rule does
// not apply to this source. An empty answer is reported as ErrNotFound because
// the API cannot tell an unknown asset from a clean one.
type HTTPProvider struct {
	BaseURL string
	Token   string // optional bearer token
	Client  *http.Client
}

// Name implements Provider.
func (p *HTTPProvider) Name() string { return "kevgate-http" }

type queueItem struct {
	CVE  string   `json:"cve"`
	CVSS *float64 `json:"cvss"`
	EPSS *float64 `json:"epss"`
	KEV  bool     `json:"kev"`
}

// Lookup implements Provider.
func (p *HTTPProvider) Lookup(ctx context.Context, digest string) (*Evidence, error) {
	if !ValidDigest(digest) {
		return nil, errors.New("evidence: malformed digest")
	}
	base, err := url.Parse(p.BaseURL)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, errors.New("evidence: invalid kevgate base URL")
	}
	u := base.JoinPath("queue")
	q := url.Values{}
	q.Set("asset", digest)
	q.Set("limit", "100")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evidence: kevgate request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("evidence: kevgate returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("evidence: read kevgate response: %w", err)
	}
	if len(body) > httpMaxBody {
		return nil, errors.New("evidence: kevgate response too large")
	}
	var items []queueItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("evidence: kevgate response: %w", err)
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	if len(items) > httpMaxItems {
		return nil, errors.New("evidence: kevgate returned too many items")
	}
	ev := &Evidence{Digest: digest, Source: "kevgate-http"}
	for i, it := range items {
		id := strings.ToUpper(strings.TrimSpace(it.CVE))
		if !vuln.ValidID(id) || it.CVSS == nil || it.EPSS == nil {
			return nil, fmt.Errorf("evidence: kevgate item %d is missing cve, cvss or epss", i)
		}
		if !(*it.CVSS >= 0 && *it.CVSS <= 10) || !(*it.EPSS >= 0 && *it.EPSS <= 1) {
			return nil, fmt.Errorf("evidence: kevgate item %d has out-of-range scores", i)
		}
		ev.Findings = append(ev.Findings, vuln.Finding{
			ID: id, CVSS: *it.CVSS, EPSS: *it.EPSS, HasEPSS: true, KEVHint: it.KEV,
		})
	}
	return ev, nil
}
