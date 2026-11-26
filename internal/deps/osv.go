package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const (
	DefaultOSVBaseURL  = "https://api.osv.dev"
	DefaultOSVCacheTTL = 6 * time.Hour
	maxOSVWorkers      = 8
)

type OSVOptions struct {
	Online        bool
	BaseURL       string
	Timeout       time.Duration
	OfflineDBPath string
	CacheDir      string
	CacheTTL      time.Duration
	NoCache       bool
}

type OfflineVulnDB struct {
	Vulnerabilities []OfflineAdvisory `json:"vulnerabilities"`
}

type OfflineAdvisory struct {
	ID               string   `json:"id"`
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	AffectedVersions []string `json:"affected_versions"`
	Severity         string   `json:"severity"`
	Summary          string   `json:"summary"`
	FixedVersion     string   `json:"fixed_version"`
}

func LoadOfflineVulnDB(path string) (*OfflineVulnDB, error) {
	raw, err := readBoundedDepsFile(path)
	if err != nil {
		return nil, fmt.Errorf("load offline vuln DB %q: %w", path, err)
	}
	var db OfflineVulnDB
	if err := json.Unmarshal([]byte(raw), &db); err != nil {
		return nil, fmt.Errorf("parse offline vuln DB %q: %w", path, err)
	}
	return &db, nil
}

func AuditDependencies(ctx context.Context, comps []Component, opts OSVOptions) ([]schema.Finding, error) {
	var findings []schema.Finding
	seen := make(map[string]struct{})
	now := time.Now().UTC()

	if strings.TrimSpace(opts.OfflineDBPath) != "" {
		db, err := LoadOfflineVulnDB(opts.OfflineDBPath)
		if err != nil {
			return nil, err
		}
		for _, c := range comps {
			for _, adv := range db.Vulnerabilities {
				if !matchesOfflineAdvisory(c, adv) {
					continue
				}
				key := c.PURL + "|" + adv.ID
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, vulnToFinding(c, adv.ID, adv.Severity, adv.Summary, adv.FixedVersion, nil, now))
			}
		}
	}

	if opts.Online && len(comps) > 0 {
		onlineHits, err := QueryOSVBatch(ctx, comps, opts)
		if err != nil {
			return nil, err
		}
		for _, f := range onlineHits {
			key := f.Target + "|" + f.ID
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func matchesOfflineAdvisory(c Component, adv OfflineAdvisory) bool {
	if !strings.EqualFold(strings.TrimSpace(adv.Ecosystem), c.Ecosystem) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(adv.Package), c.Name) {
		return false
	}
	for _, av := range adv.AffectedVersions {
		trimmed := strings.TrimSpace(av)
		if trimmed == "*" || strings.EqualFold(trimmed, c.Version) {
			return true
		}
	}
	return false
}

type osvBatchReq struct {
	Queries []osvBatchQuery `json:"queries"`
}

type osvBatchQuery struct {
	Package osvPkg `json:"package"`
	Version string `json:"version"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Summary  string   `json:"summary"`
			Severity string   `json:"severity"`
			Fixed    string   `json:"fixed_version"`
		} `json:"vulns"`
	} `json:"results"`
}

type cachedOSVVuln struct {
	ID         string            `json:"id"`
	Aliases    []string          `json:"aliases,omitempty"`
	Summary    string            `json:"summary"`
	Severity   string            `json:"severity"`
	FixedByPkg map[string]string `json:"fixed_by_pkg,omitempty"`
	FirstFixed string            `json:"first_fixed,omitempty"`
	FetchedAt  time.Time         `json:"fetched_at"`
}

func (c *cachedOSVVuln) fixedFor(comp Component) string {
	if c == nil {
		return ""
	}
	if len(c.FixedByPkg) > 0 {
		key := strings.ToLower(strings.TrimSpace(comp.Ecosystem)) + ":" + strings.ToLower(strings.TrimSpace(comp.Name))
		if fv, ok := c.FixedByPkg[key]; ok && fv != "" {
			return fv
		}
	}
	return c.FirstFixed
}

func QueryOSVBatch(ctx context.Context, comps []Component, opts OSVOptions) ([]schema.Finding, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		baseURL = DefaultOSVBaseURL
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	type rawHit struct {
		comp    Component
		vulnID  string
		aliases []string
		sev     string
		summary string
		fixed   string
	}
	var rawHits []rawHit

	const batchSize = 100
	for start := 0; start < len(comps); start += batchSize {
		end := start + batchSize
		if end > len(comps) {
			end = len(comps)
		}
		chunk := comps[start:end]

		reqBody := osvBatchReq{Queries: make([]osvBatchQuery, 0, len(chunk))}
		for _, c := range chunk {
			reqBody.Queries = append(reqBody.Queries, osvBatchQuery{
				Package: osvPkg{Name: c.Name, Ecosystem: c.Ecosystem},
				Version: c.Version,
			})
		}
		payload, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/querybatch", bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build OSV querybatch request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", schema.ToolName+"/"+schema.Version)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("query OSV API: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read OSV response: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
		}

		var decoded osvBatchResp
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode OSV response: %w", err)
		}

		for idx, res := range decoded.Results {
			if idx >= len(chunk) {
				break
			}
			comp := chunk[idx]
			for _, v := range res.Vulns {
				rawHits = append(rawHits, rawHit{
					comp:    comp,
					vulnID:  strings.TrimSpace(v.ID),
					aliases: v.Aliases,
					sev:     strings.TrimSpace(v.Severity),
					summary: strings.TrimSpace(v.Summary),
					fixed:   strings.TrimSpace(v.Fixed),
				})
			}
		}
	}

	if len(rawHits) == 0 {
		return nil, nil
	}

	cacheDir := ""
	if !opts.NoCache {
		cacheDir = resolveOSVCacheDir(opts.CacheDir)
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = DefaultOSVCacheTTL
	}

	details := make(map[string]*cachedOSVVuln)
	var toFetch []string
	seenFetch := make(map[string]struct{})
	now := time.Now().UTC()

	for _, hit := range rawHits {
		if hit.vulnID == "" {
			continue
		}
		if hit.sev != "" && hit.summary != "" && hit.fixed != "" && len(hit.aliases) > 0 {
			continue
		}
		if _, done := seenFetch[hit.vulnID]; done {
			continue
		}
		seenFetch[hit.vulnID] = struct{}{}

		if cacheDir != "" {
			if cached := readCachedOSVVuln(cacheDir, hit.vulnID, ttl, now); cached != nil {
				details[hit.vulnID] = cached
				continue
			}
		}
		toFetch = append(toFetch, hit.vulnID)
	}

	if len(toFetch) > 0 {
		fetched := fetchOSVVulnsParallel(ctx, client, baseURL, toFetch, now)
		for id, det := range fetched {
			details[id] = det
			if cacheDir != "" {
				writeCachedOSVVuln(cacheDir, id, det)
			}
		}
	}

	findings := make([]schema.Finding, 0, len(rawHits))
	for _, hit := range rawHits {
		sev := hit.sev
		summary := hit.summary
		fixed := hit.fixed
		aliases := hit.aliases
		if det := details[hit.vulnID]; det != nil {
			if sev == "" {
				sev = det.Severity
			}
			if summary == "" {
				summary = det.Summary
			}
			if fixed == "" {
				fixed = det.fixedFor(hit.comp)
			}
			if len(aliases) == 0 && len(det.Aliases) > 0 {
				aliases = det.Aliases
			}
		}
		if sev == "" {
			sev = "high"
		}
		if summary == "" {
			summary = fmt.Sprintf("Vulnerability %s affects %s@%s", hit.vulnID, hit.comp.Name, hit.comp.Version)
		}
		findings = append(findings, vulnToFinding(hit.comp, hit.vulnID, sev, summary, fixed, aliases, now))
	}

	return findings, nil
}

func fetchOSVVulnsParallel(ctx context.Context, client *http.Client, baseURL string, vulnIDs []string, now time.Time) map[string]*cachedOSVVuln {
	out := make(map[string]*cachedOSVVuln, len(vulnIDs))
	if len(vulnIDs) == 0 {
		return out
	}

	workers := maxOSVWorkers
	if len(vulnIDs) < workers {
		workers = len(vulnIDs)
	}

	jobs := make(chan string, len(vulnIDs))
	for _, id := range vulnIDs {
		jobs <- id
	}
	close(jobs)

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for vulnID := range jobs {
				if ctx.Err() != nil {
					return
				}
				det := fetchSingleOSVVulnDetail(ctx, client, baseURL, vulnID, now)
				if det != nil {
					mu.Lock()
					out[vulnID] = det
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return out
}

func fetchSingleOSVVulnDetail(ctx context.Context, client *http.Client, baseURL, vulnID string, now time.Time) *cachedOSVVuln {
	if vulnID == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/vulns/"+vulnID, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", schema.ToolName+"/"+schema.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	var doc struct {
		ID               string   `json:"id"`
		Aliases          []string `json:"aliases"`
		Summary          string   `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Events []struct {
					Fixed string `json:"fixed,omitempty"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}

	sev := strings.ToLower(strings.TrimSpace(doc.DatabaseSpecific.Severity))
	if sev == "" {
		for _, s := range doc.Severity {
			if scoreNum, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err == nil {
				switch {
				case scoreNum >= 9.0:
					sev = "critical"
				case scoreNum >= 7.0:
					sev = "high"
				case scoreNum >= 4.0:
					sev = "medium"
				case scoreNum > 0:
					sev = "low"
				}
				if sev != "" {
					break
				}
			}
		}
	}

	fixedByPkg := make(map[string]string)
	firstFixed := ""
	for _, aff := range doc.Affected {
		pkgKey := strings.ToLower(strings.TrimSpace(aff.Package.Ecosystem)) + ":" + strings.ToLower(strings.TrimSpace(aff.Package.Name))
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				fv := strings.TrimSpace(ev.Fixed)
				if fv == "" {
					continue
				}
				if firstFixed == "" {
					firstFixed = fv
				}
				if aff.Package.Name != "" && fixedByPkg[pkgKey] == "" {
					fixedByPkg[pkgKey] = fv
				}
			}
		}
	}

	return &cachedOSVVuln{
		ID:         vulnID,
		Aliases:    doc.Aliases,
		Summary:    strings.TrimSpace(doc.Summary),
		Severity:   sev,
		FixedByPkg: fixedByPkg,
		FirstFixed: firstFixed,
		FetchedAt:  now,
	}
}

func resolveOSVCacheDir(explicit string) string {
	dir := strings.TrimSpace(explicit)
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil || strings.TrimSpace(base) == "" {
			return ""
		}
		dir = filepath.Join(base, schema.ToolName, "osv")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return dir
}

func readCachedOSVVuln(cacheDir, vulnID string, ttl time.Duration, now time.Time) *cachedOSVVuln {
	p := filepath.Join(cacheDir, schema.SanitizeIDPart(vulnID)+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var entry cachedOSVVuln
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil
	}
	if entry.FetchedAt.IsZero() || now.Sub(entry.FetchedAt) > ttl {
		return nil
	}
	return &entry
}

func writeCachedOSVVuln(cacheDir, vulnID string, entry *cachedOSVVuln) {
	if entry == nil || cacheDir == "" || vulnID == "" {
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	target := filepath.Join(cacheDir, schema.SanitizeIDPart(vulnID)+".json")
	tmp, err := os.CreateTemp(cacheDir, ".tmp-osv-*.json")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	_, wErr := tmp.Write(data)
	cErr := tmp.Close()
	if wErr != nil || cErr != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, target); err != nil {
		_ = os.Remove(tmpPath)
	}
}

func vulnToFinding(c Component, vulnID, rawSev, summary, fixedVer string, aliases []string, now time.Time) schema.Finding {
	sev := mapAdvisorySeverity(rawSev)
	ruleID := "PIPE-102"
	if sev == schema.SeverityCritical || sev == schema.SeverityHigh {
		ruleID = "PIPE-101"
	}

	rem := fmt.Sprintf("Upgrade %s (%s) from %s to a patched release.", c.Name, c.Ecosystem, c.Version)
	if fixedVer != "" {
		rem = fmt.Sprintf("Upgrade %s (%s) from %s to %s or later.", c.Name, c.Ecosystem, c.Version, fixedVer)
	}

	ev := map[string]any{
		"advisory_id": vulnID,
		"ecosystem":   c.Ecosystem,
		"package":     c.Name,
		"version":     c.Version,
		"purl":        c.PURL,
		"standard":    "OWASP CI/CD-SEC-3",
	}
	if len(aliases) > 0 {
		ev["aliases"] = aliases
	}
	if cveID := extractPrimaryCVE(vulnID, aliases); cveID != "" {
		ev["cve_id"] = cveID
	}
	if fixedVer != "" {
		ev["fixed_version"] = fixedVer
	}
	if c.Line > 0 {
		ev["line"] = c.Line
	}

	return schema.NewFinding(
		ruleID, "deps", sev,
		fmt.Sprintf("Vulnerable dependency %s@%s (%s)", c.Name, c.Version, vulnID),
		summary,
		c.ManifestPath,
		ev,
		rem,
		"D3-SBOM",
		fmt.Sprintf("%s-%s-%s", c.Name, c.Version, vulnID),
		now,
	)
}

func extractPrimaryCVE(vulnID string, aliases []string) string {
	up := strings.ToUpper(strings.TrimSpace(vulnID))
	if strings.HasPrefix(up, "CVE-") {
		return up
	}
	for _, a := range aliases {
		ca := strings.ToUpper(strings.TrimSpace(a))
		if strings.HasPrefix(ca, "CVE-") {
			return ca
		}
	}
	return ""
}

func mapAdvisorySeverity(raw string) schema.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return schema.SeverityCritical
	case "high":
		return schema.SeverityHigh
	case "medium", "moderate":
		return schema.SeverityMedium
	case "low":
		return schema.SeverityLow
	default:
		return schema.SeverityHigh
	}
}
