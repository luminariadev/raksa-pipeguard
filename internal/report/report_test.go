package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

func TestTableSanitizesANSIAndPrintsScore(t *testing.T) {
	now := time.Date(2026, 11, 26, 14, 0, 0, 0, time.UTC)
	rep := schema.NewReport([]schema.Finding{
		{
			ID:          "pipe-206-1",
			RuleID:      "PIPE-206",
			Module:      "iac",
			Layer:       schema.LayerDevSecOps,
			Severity:    schema.SeverityLow,
			Title:       "Expose\x1b]0;pwn\x07Check",
			Description: "No healthcheck",
			Target:      "file:///tmp/\x1b[31mDockerfile\x1b[0m",
			Remediation: "Add HEALTHCHECK",
			MitreD3FEND: "D3-CH",
			Timestamp:   now,
		},
	}, now)

	out := FormatTableRender(rep)
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x07") {
		t.Fatalf("ANSI escape leaked into output: %q", out)
	}
	if !strings.Contains(out, "score: 97/100 (A+)") || !strings.Contains(out, "ExposeCheck") {
		t.Fatalf("missing score or sanitized text: %s", out)
	}
}

func TestJSONAndSARIF21Output(t *testing.T) {
	now := time.Date(2026, 11, 26, 14, 0, 0, 0, time.UTC)
	rep := schema.NewReport([]schema.Finding{
		{
			ID:          "pipe-401-1",
			RuleID:      "PIPE-401",
			Module:      "ci",
			Layer:       schema.LayerDevSecOps,
			Severity:    schema.SeverityCritical,
			Title:       "Unsafe pull_request_target checkout",
			Description: "Checks out PR head",
			Target:      "file://.github/workflows/pr.yml",
			Evidence:    map[string]any{"line": 12},
			Remediation: "Use pull_request",
			MitreD3FEND: "D3-CH",
			Timestamp:   now,
		},
		{
			ID:          "pipe-201-1",
			RuleID:      "PIPE-201",
			Module:      "iac",
			Layer:       schema.LayerDevSecOps,
			Severity:    schema.SeverityHigh,
			Title:       "Root container user",
			Description: "Missing USER",
			Target:      "file://Dockerfile",
			Evidence:    map[string]any{"line": 4},
			Remediation: "Use nonroot",
			MitreD3FEND: "D3-CH",
			Timestamp:   now,
		},
	}, now)

	jsonOut, err := FormatJSONRender(rep)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["schema_version"] != "1.0" || parsed["layer"] != "devsecops" {
		t.Fatalf("invalid JSON metadata: %+v", parsed)
	}

	sarifOut, err := FormatSARIFRender(rep)
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	if err := json.Unmarshal([]byte(sarifOut), &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", sarif["version"])
	}
	run0 := sarif["runs"].([]any)[0].(map[string]any)
	rules := run0["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 || rules[0].(map[string]any)["id"] != "PIPE-201" || rules[1].(map[string]any)["id"] != "PIPE-401" {
		t.Fatalf("rules not sorted deterministically: %+v", rules)
	}
}
