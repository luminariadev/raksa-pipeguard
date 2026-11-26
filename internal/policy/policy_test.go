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
