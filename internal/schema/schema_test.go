package schema

import (
	"testing"
	"time"
)

func TestParseSeverityAndThresholds(t *testing.T) {
	sev, err := ParseSeverity(" CRITICAL ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityCritical {
		t.Fatalf("got %q want %q", sev, SeverityCritical)
	}
	if !SeverityHigh.MeetsThreshold(SeverityMedium) {
		t.Fatalf("high must meet medium threshold")
	}
	if SeverityLow.MeetsThreshold(SeverityHigh) {
		t.Fatalf("low must not meet high threshold")
	}
	if _, err := ParseSeverity("invalid"); err == nil {
		t.Fatalf("expected error on invalid severity")
	}
}

func TestRuleCatalogContains24UniqueRules(t *testing.T) {
	rules := RuleCatalog()
	if len(rules) != 24 {
		t.Fatalf("expected 24 PIPE rules, got %d", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if r.RuleID == "" || r.Title == "" || r.Standard == "" || r.MitreD3FEND == "" {
			t.Fatalf("incomplete rule metadata: %+v", r)
		}
		if _, dup := seen[r.RuleID]; dup {
			t.Fatalf("duplicate rule id %q", r.RuleID)
		}
		seen[r.RuleID] = struct{}{}
	}
}

func TestComputePostureAndReportSummary(t *testing.T) {
	now := time.Date(2026, 11, 26, 14, 0, 0, 0, time.UTC)
	clean := NewReport(nil, now)
	if clean.Posture.Score != 100 || clean.Posture.Grade != "A+" || clean.Layer != LayerDevSecOps {
		t.Fatalf("unexpected clean report metadata: %+v", clean)
	}

	rep := NewReport([]Finding{
		{RuleID: "PIPE-001", Severity: SeverityCritical},
		{RuleID: "PIPE-201", Severity: SeverityHigh},
		{RuleID: "PIPE-205", Severity: SeverityMedium},
	}, now)
	if rep.Summary.Total != 3 || rep.Summary.Critical != 1 || rep.Summary.High != 1 || rep.Summary.Medium != 1 {
		t.Fatalf("unexpected summary: %+v", rep.Summary)
	}
	if rep.Posture.Score != 44 || rep.Posture.Grade != "F" {
		t.Fatalf("unexpected score %+v", rep.Posture)
	}
	if !rep.HasThresholdBreach(SeverityCritical) || rep.HasThresholdBreach("") {
		t.Fatalf("unexpected threshold check result")
	}
}
