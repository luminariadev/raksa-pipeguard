package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

func TestPolicyAuditReasonAndFailClosedExpiration(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(badPath, []byte("suppressions:\n  - rule_id: PIPE-206\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(badPath); err == nil {
		t.Fatalf("expected error when audit reason is omitted")
	}

	goodPath := filepath.Join(dir, "good.yml")
	content := `min_severity: medium
suppressions:
  - rule_id: PIPE-206
    target_contains: Dockerfile
    reason: CLI-only distroless image without network listener
    expires_on: "2099-12-31"
  - rule_id: PIPE-103
    reason: Legacy expired waiver
    expires_on: "2020-01-01"
`
	if err := os.WriteFile(goodPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadPolicy(goodPath)
	if err != nil {
		t.Fatalf("unexpected error loading policy: %v", err)
	}

	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	findings := []schema.Finding{
		{RuleID: "PIPE-206", Severity: schema.SeverityLow, Target: "file://Dockerfile"},
		{RuleID: "PIPE-103", Severity: schema.SeverityMedium, Target: "file://requirements.txt"},
		{RuleID: "PIPE-401", Severity: schema.SeverityCritical, Target: "file://.github/workflows/pr.yml"},
	}

	kept, filtered := ApplyPolicy(findings, pol, now)
	if filtered != 1 || len(kept) != 2 {
		t.Fatalf("expected 1 filtered and 2 kept (expired PIPE-103 must fail closed), got filtered=%d kept=%+v", filtered, kept)
	}
}

func TestCustomRulesAndBaselineRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Invalid regex in custom_rules must fail closed.
	invalidPolPath := filepath.Join(dir, "bad-custom.yml")
	if err := os.WriteFile(invalidPolPath, []byte("custom_rules:\n  - id: ORG-1\n    title: Bad\n    severity: high\n    pattern: \"[unclosed\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(invalidPolPath); err == nil {
		t.Fatalf("expected error on invalid custom rule regex")
	}

	polPath := filepath.Join(dir, "policy.yml")
	polYAML := `custom_rules:
  - id: ORG-001
    title: Disallow unapproved internal registry mirror
    severity: high
    pattern: "registry\\.legacy\\.internal"
    path_glob: "*.yml"
    remediation: Migrate images to ghcr.io/org-verified registry.
`
	if err := os.WriteFile(polPath, []byte(polYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadPolicy(polPath)
	if err != nil {
		t.Fatalf("LoadPolicy custom rule: %v", err)
	}

	workDir := filepath.Join(dir, "repo")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "deploy.yml"), []byte("image: registry.legacy.internal/app:1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "notes.txt"), []byte("image: registry.legacy.internal/app:1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hits, err := EvaluateCustomRules(workDir, pol)
	if err != nil {
		t.Fatalf("EvaluateCustomRules: %v", err)
	}
	if len(hits) != 1 || hits[0].RuleID != "PIPE-501" || hits[0].Evidence["custom_rule_id"] != "ORG-001" {
		t.Fatalf("expected 1 PIPE-501 match on deploy.yml only, got %+v", hits)
	}

	// Baseline round-trip filters known finding while surfacing new finding.
	baselineFile := filepath.Join(dir, "baseline.json")
	if err := WriteBaseline(baselineFile, hits); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	loaded, err := LoadBaseline(baselineFile)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	extra := schema.Finding{
		RuleID:   "PIPE-501",
		Module:   "policy",
		Severity: schema.SeverityHigh,
		Target:   "file://other.yml",
		Title:    "New regression finding",
	}
	remaining, suppressed := FilterBaseline(append(hits, extra), loaded)
	if suppressed != 1 || len(remaining) != 1 || remaining[0].Title != "New regression finding" {
		t.Fatalf("unexpected baseline filter result: suppressed=%d remaining=%+v", suppressed, remaining)
	}
}
