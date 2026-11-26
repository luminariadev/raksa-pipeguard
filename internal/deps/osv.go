package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const DefaultOSVBaseURL = "https://api.osv.dev"

type OSVOptions struct {
	Online        bool
	BaseURL       string
	Timeout       time.Duration
	OfflineDBPath string
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
				findings = append(findings, vulnToFinding(c, adv.ID, adv.Severity, adv.Summary, adv.FixedVersion, now))
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
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Severity string `json:"severity"`
			Fixed    string `json:"fixed_version"`
		} `json:"vulns"`
	} `json:"results"`
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
	var findings []schema.Finding
	now := time.Now().UTC()

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
				sev := strings.TrimSpace(v.Severity)
				summary := strings.TrimSpace(v.Summary)
				if sev == "" || summary == "" {
					fetchedSev, fetchedSum := fetchOSVVulnDetail(ctx, client, baseURL, v.ID)
					if sev == "" {
						sev = fetchedSev
					}
					if summary == "" {
						summary = fetchedSum
					}
				}
				if sev == "" {
					sev = "high"
				}
				if summary == "" {
					summary = fmt.Sprintf("Vulnerability %s affects %s@%s", v.ID, comp.Name, comp.Version)
				}
				findings = append(findings, vulnToFinding(comp, v.ID, sev, summary, v.Fixed, now))
			}
		}
	}

	return findings, nil
}

func fetchOSVVulnDetail(ctx context.Context, client *http.Client, baseURL, vulnID string) (string, string) {
	if vulnID == "" {
		return "", ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/vulns/"+vulnID, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", schema.ToolName+"/"+schema.Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", ""
	}
	var doc struct {
		Summary          string `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return "", ""
	}
	return strings.ToLower(strings.TrimSpace(doc.DatabaseSpecific.Severity)), strings.TrimSpace(doc.Summary)
}

func vulnToFinding(c Component, vulnID, rawSev, summary, fixedVer string, now time.Time) schema.Finding {
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
