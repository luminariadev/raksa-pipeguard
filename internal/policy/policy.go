package policy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"gopkg.in/yaml.v3"
)

const MaxPolicyBytes = 1024 * 1024

type Policy struct {
	MinSeverity    schema.Severity `yaml:"min_severity" json:"min_severity"`
	DeniedLicenses []string        `yaml:"denied_licenses" json:"denied_licenses"`
	Suppressions   []Suppression   `yaml:"suppressions" json:"suppressions"`
	CustomRules    []CustomRule    `yaml:"custom_rules" json:"custom_rules"`
}

type CustomRule struct {
	ID          string          `yaml:"id" json:"id"`
	Title       string          `yaml:"title" json:"title"`
	Severity    schema.Severity `yaml:"severity" json:"severity"`
	Pattern     string          `yaml:"pattern" json:"pattern"`
	PathGlob    string          `yaml:"path_glob" json:"path_glob"`
	Remediation string          `yaml:"remediation" json:"remediation"`
	compiled    *regexp.Regexp
}

type Suppression struct {
	RuleID         string `yaml:"rule_id" json:"rule_id"`
	TargetContains string `yaml:"target_contains" json:"target_contains"`
	Reason         string `yaml:"reason" json:"reason"`
	ExpiresOn      string `yaml:"expires_on" json:"expires_on"`
}

func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open policy %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat policy %q: %w", path, err)
	}
	if info.Size() > MaxPolicyBytes {
		return nil, fmt.Errorf("policy %q exceeds %d byte limit", path, MaxPolicyBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	if len(raw) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy %q exceeds %d byte limit", path, MaxPolicyBytes)
	}

	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse YAML/JSON policy %q: %w", path, err)
	}

	if strings.TrimSpace(string(p.MinSeverity)) != "" {
		sev, err := schema.ParseSeverity(string(p.MinSeverity))
		if err != nil {
			return nil, fmt.Errorf("policy min_severity: %w", err)
		}
		p.MinSeverity = sev
	}

	for idx, sup := range p.Suppressions {
		if strings.TrimSpace(sup.RuleID) == "" {
			return nil, fmt.Errorf("suppression #%d has empty rule_id", idx)
		}
		if strings.TrimSpace(sup.Reason) == "" {
			return nil, fmt.Errorf("suppression #%d (%s) requires non-empty audit reason", idx, sup.RuleID)
		}
		if exp := strings.TrimSpace(sup.ExpiresOn); exp != "" {
			if _, err := time.Parse("2006-01-02", exp); err != nil {
				return nil, fmt.Errorf("suppression #%d (%s) invalid expires_on %q (expected YYYY-MM-DD)", idx, sup.RuleID, sup.ExpiresOn)
			}
		}
	}

	for idx := range p.CustomRules {
		r := &p.CustomRules[idx]
		r.ID = strings.TrimSpace(r.ID)
		r.Title = strings.TrimSpace(r.Title)
		r.Pattern = strings.TrimSpace(r.Pattern)
		r.PathGlob = strings.TrimSpace(r.PathGlob)
		r.Remediation = strings.TrimSpace(r.Remediation)
		if r.ID == "" {
			return nil, fmt.Errorf("custom_rules #%d has empty id", idx)
		}
		if r.Title == "" {
			return nil, fmt.Errorf("custom_rules #%d (%s) has empty title", idx, r.ID)
		}
		if r.Pattern == "" {
			return nil, fmt.Errorf("custom_rules #%d (%s) has empty regex pattern", idx, r.ID)
		}
		sev, err := schema.ParseSeverity(string(r.Severity))
		if err != nil {
			return nil, fmt.Errorf("custom_rules #%d (%s) severity: %w", idx, r.ID, err)
		}
		r.Severity = sev
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom_rules #%d (%s) invalid regex: %w", idx, r.ID, err)
		}
		r.compiled = re
		if r.PathGlob != "" {
			if _, err := filepath.Match(r.PathGlob, "sample.txt"); err != nil {
				return nil, fmt.Errorf("custom_rules #%d (%s) invalid path_glob %q: %w", idx, r.ID, r.PathGlob, err)
			}
		}
		if r.Remediation == "" {
			r.Remediation = fmt.Sprintf("Remediate custom policy violation %s according to organization guidelines.", r.ID)
		}
	}

	return &p, nil
}

func ApplyPolicy(findings []schema.Finding, p *Policy, today time.Time) ([]schema.Finding, int) {
	if p == nil {
		return findings, 0
	}
	todayDate := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	kept := make([]schema.Finding, 0, len(findings))
	filtered := 0

	for _, f := range findings {
		if p.MinSeverity != "" && !f.Severity.MeetsThreshold(p.MinSeverity) {
			filtered++
			continue
		}
		if isSuppressed(f, p.Suppressions, todayDate) {
			filtered++
			continue
		}
		kept = append(kept, f)
	}
	return kept, filtered
}

func isSuppressed(f schema.Finding, suppressions []Suppression, todayDate time.Time) bool {
	for _, sup := range suppressions {
		if !strings.EqualFold(strings.TrimSpace(sup.RuleID), f.RuleID) {
			continue
		}
		if sub := strings.TrimSpace(sup.TargetContains); sub != "" && !strings.Contains(f.Target, sub) {
			continue
		}
		if exp := strings.TrimSpace(sup.ExpiresOn); exp != "" {
			expDate, err := time.Parse("2006-01-02", exp)
			if err != nil || expDate.Before(todayDate) {
				// Fail closed once expiration passes.
				continue
			}
		}
		return true
	}
	return false
}

// LoadOptionalPolicy loads explicitPath when provided, or <scanTarget>/.pipeguard.yml if present.
func LoadOptionalPolicy(scanTarget, explicitPath string) (*Policy, error) {
	if strings.TrimSpace(explicitPath) != "" {
		return LoadPolicy(explicitPath)
	}
	if strings.TrimSpace(scanTarget) == "" {
		return nil, nil
	}
	baseDir := scanTarget
	if fi, err := os.Stat(scanTarget); err == nil && !fi.IsDir() {
		baseDir = filepath.Dir(scanTarget)
	}
	candidate := filepath.Join(baseDir, ".pipeguard.yml")
	if _, err := os.Stat(candidate); err == nil {
		return LoadPolicy(candidate)
	}
	return nil, nil
}
