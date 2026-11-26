package deps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const (
	DefaultKEVURL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL       = "https://api.first.org/data/v1/epss"
	DefaultRiskCacheTTL  = 12 * time.Hour
	DefaultEPSSThreshold = 0.50
)

type RiskOptions struct {
	KEVPath       string
	OnlineKEV     bool
	OnlineEPSS    bool
	EPSSThreshold float64
	CacheDir      string
	CacheTTL      time.Duration
	NoCache       bool
	KEVURL        string
	EPSSURL       string
	Timeout       time.Duration
}

type epssEntry struct {
	CVE        string    `json:"cve"`
	EPSS       float64   `json:"epss"`
	Percentile float64   `json:"percentile"`
	FetchedAt  time.Time `json:"fetched_at"`
}

type kevCacheDoc struct {
	CVEs      map[string]string `json:"cves"`
	FetchedAt time.Time         `json:"fetched_at"`
}

// EnrichFindingsWithRisk upgrades PIPE-101/PIPE-102 advisories matching CISA KEV or EPSS >= threshold to critical PIPE-106.
func EnrichFindingsWithRisk(ctx context.Context, findings []schema.Finding, opts RiskOptions) ([]schema.Finding, error) {
	hasKEV := strings.TrimSpace(opts.KEVPath) != "" || opts.OnlineKEV
	if (!hasKEV && !opts.OnlineEPSS) || len(findings) == 0 {
		return findings, nil
	}

	threshold := opts.EPSSThreshold
	if threshold <= 0 {
		threshold = DefaultEPSSThreshold
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = DefaultRiskCacheTTL
	}

	var cacheDir string
	if !opts.NoCache {
		cacheDir = resolveOSVCacheDir(opts.CacheDir)
	}
	client := &http.Client{Timeout: timeout}
	now := time.Now().UTC()

	var kevMap map[string]string
	if hasKEV {
		loaded, err := loadKEVMap(ctx, client, opts, cacheDir, ttl, now)
		if err != nil {
			return nil, err
		}
		kevMap = loaded
	}

	cves := collectVulnerabilityCVEs(findings)
	var epssMap map[string]epssEntry
	if opts.OnlineEPSS && len(cves) > 0 {
		loaded, err := loadEPSSScores(ctx, client, opts, cves, cacheDir, ttl, now)
		if err != nil {
			return nil, err
		}
		epssMap = loaded
	}

	out := make([]schema.Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID != "PIPE-101" && f.RuleID != "PIPE-102" {
			out = append(out, f)
			continue
		}
		matchedCVEs := findingCVEs(f)
		var primaryCVE string
		if len(matchedCVEs) > 0 {
			primaryCVE = matchedCVEs[0]
		}

		inKEV := false
		kevName := ""
		var bestEPSS epssEntry
		hasEPSS := false

		for _, cve := range matchedCVEs {
			if name, ok := kevMap[cve]; ok && !inKEV {
				inKEV = true
				kevName = name
				primaryCVE = cve
			}
			if e, ok := epssMap[cve]; ok && (!hasEPSS || e.EPSS > bestEPSS.EPSS) {
				bestEPSS = e
				hasEPSS = true
				if !inKEV {
					primaryCVE = cve
				}
			}
		}

		if f.Evidence == nil {
			f.Evidence = make(map[string]any)
		}
		if hasEPSS {
			f.Evidence["epss_score"] = bestEPSS.EPSS
			f.Evidence["epss_percentile"] = bestEPSS.Percentile
		}
		if inKEV {
			f.Evidence["kev"] = true
			if kevName != "" {
				f.Evidence["kev_vulnerability"] = kevName
			}
		}

		if inKEV || (hasEPSS && bestEPSS.EPSS >= threshold) {
			f.RuleID = "PIPE-106"
			f.Severity = schema.SeverityCritical
			f.Evidence["standard"] = "CISA KEV / EPSS"
			if primaryCVE != "" {
				f.Evidence["cve_id"] = primaryCVE
			}
			pkgName, _ := f.Evidence["package"].(string)
			pkgVer, _ := f.Evidence["version"].(string)
			if pkgName != "" && primaryCVE != "" {
				f.ID = fmt.Sprintf("pipe-106-%s-%s-%s", schema.SanitizeIDPart(pkgName), schema.SanitizeIDPart(pkgVer), schema.SanitizeIDPart(primaryCVE))
			}

			var reasons []string
			if inKEV {
				reasons = append(reasons, "listed in CISA Known Exploited Vulnerabilities")
			}
			if hasEPSS && bestEPSS.EPSS >= threshold {
				reasons = append(reasons, fmt.Sprintf("EPSS %.2f (p%.0f)", bestEPSS.EPSS, bestEPSS.Percentile*100))
			}
			f.Title = fmt.Sprintf("Prioritized exploited/high-EPSS vulnerability in %s@%s (%s)", pkgName, pkgVer, primaryCVE)
			f.Remediation = fmt.Sprintf("URGENT (%s): %s", strings.Join(reasons, ", "), f.Remediation)
		}

		out = append(out, f)
	}
	return out, nil
}

func loadKEVMap(ctx context.Context, client *http.Client, opts RiskOptions, cacheDir string, ttl time.Duration, now time.Time) (map[string]string, error) {
	if strings.TrimSpace(opts.KEVPath) != "" {
		raw, err := os.ReadFile(opts.KEVPath)
		if err != nil {
			return nil, fmt.Errorf("read KEV catalog %q: %w", opts.KEVPath, err)
		}
		return parseCISAKEVFeed(raw)
	}

	if cacheDir != "" {
		cacheFile := filepath.Join(cacheDir, "cisa-kev.json")
		if raw, err := os.ReadFile(cacheFile); err == nil {
			var doc kevCacheDoc
			if json.Unmarshal(raw, &doc) == nil && !doc.FetchedAt.IsZero() && now.Sub(doc.FetchedAt) <= ttl && doc.CVEs != nil {
				return doc.CVEs, nil
			}
		}
	}

	kevURL := strings.TrimSpace(opts.KEVURL)
	if kevURL == "" {
		kevURL = DefaultKEVURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build KEV request: %w", err)
	}
	req.Header.Set("User-Agent", schema.ToolName+"/"+schema.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CISA KEV catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read KEV response: %w", err)
	}
	kevMap, err := parseCISAKEVFeed(body)
	if err != nil {
		return nil, err
	}

	if cacheDir != "" {
		if encoded, mErr := json.Marshal(kevCacheDoc{CVEs: kevMap, FetchedAt: now}); mErr == nil {
			writeAtomicFile(filepath.Join(cacheDir, "cisa-kev.json"), encoded)
		}
	}
	return kevMap, nil
}

func parseCISAKEVFeed(raw []byte) (map[string]string, error) {
	var feed struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &feed); err != nil {
		return nil, fmt.Errorf("parse CISA KEV JSON: %w", err)
	}
	out := make(map[string]string, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if strings.HasPrefix(cve, "CVE-") {
			out[cve] = strings.TrimSpace(v.VulnerabilityName)
		}
	}
	return out, nil
}

func loadEPSSScores(ctx context.Context, client *http.Client, opts RiskOptions, cves []string, cacheDir string, ttl time.Duration, now time.Time) (map[string]epssEntry, error) {
	out := make(map[string]epssEntry, len(cves))
	var uncached []string

	for _, cve := range cves {
		if cacheDir != "" {
			p := filepath.Join(cacheDir, "epss-"+schema.SanitizeIDPart(cve)+".json")
			if raw, err := os.ReadFile(p); err == nil {
				var ent epssEntry
				if json.Unmarshal(raw, &ent) == nil && !ent.FetchedAt.IsZero() && now.Sub(ent.FetchedAt) <= ttl {
					out[cve] = ent
					continue
				}
			}
		}
		uncached = append(uncached, cve)
	}

	if len(uncached) == 0 {
		return out, nil
	}

	epssBase := strings.TrimRight(strings.TrimSpace(opts.EPSSURL), "/")
	if epssBase == "" {
		epssBase = DefaultEPSSURL
	}

	const batchSize = 50
	for start := 0; start < len(uncached); start += batchSize {
		end := start + batchSize
		if end > len(uncached) {
			end = len(uncached)
		}
		chunk := uncached[start:end]
		reqURL := epssBase + "?cve=" + url.QueryEscape(strings.Join(chunk, ","))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build EPSS request: %w", err)
		}
		req.Header.Set("User-Agent", schema.ToolName+"/"+schema.Version)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("query EPSS API: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read EPSS response: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("EPSS API returned HTTP %d", resp.StatusCode)
		}

		var decoded struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode EPSS JSON: %w", err)
		}

		for _, item := range decoded.Data {
			cve := strings.ToUpper(strings.TrimSpace(item.CVE))
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			score, _ := strconv.ParseFloat(strings.TrimSpace(item.EPSS), 64)
			pct, _ := strconv.ParseFloat(strings.TrimSpace(item.Percentile), 64)
			ent := epssEntry{
				CVE:        cve,
				EPSS:       score,
				Percentile: pct,
				FetchedAt:  now,
			}
			out[cve] = ent
			if cacheDir != "" {
				if raw, mErr := json.Marshal(ent); mErr == nil {
					writeAtomicFile(filepath.Join(cacheDir, "epss-"+schema.SanitizeIDPart(cve)+".json"), raw)
				}
			}
		}
	}

	return out, nil
}

func collectVulnerabilityCVEs(findings []schema.Finding) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, f := range findings {
		if f.RuleID != "PIPE-101" && f.RuleID != "PIPE-102" {
			continue
		}
		for _, cve := range findingCVEs(f) {
			if _, ok := seen[cve]; !ok {
				seen[cve] = struct{}{}
				out = append(out, cve)
			}
		}
	}
	sort.Strings(out)
	return out
}

func findingCVEs(f schema.Finding) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		up := strings.ToUpper(strings.TrimSpace(raw))
		if !strings.HasPrefix(up, "CVE-") {
			return
		}
		if _, ok := seen[up]; !ok {
			seen[up] = struct{}{}
			out = append(out, up)
		}
	}
	if adv, ok := f.Evidence["advisory_id"].(string); ok {
		add(adv)
	}
	if cve, ok := f.Evidence["cve_id"].(string); ok {
		add(cve)
	}
	switch al := f.Evidence["aliases"].(type) {
	case []string:
		for _, a := range al {
			add(a)
		}
	case []any:
		for _, item := range al {
			if s, ok := item.(string); ok {
				add(s)
			}
		}
	}
	return out
}

func writeAtomicFile(target string, data []byte) {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".tmp-risk-*.json")
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
