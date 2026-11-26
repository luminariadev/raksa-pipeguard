package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const MaxBaselineBytes = 8 * 1024 * 1024

type BaselineEntry struct {
	Fingerprint string          `json:"fingerprint"`
	RuleID      string          `json:"rule_id"`
	Module      string          `json:"module"`
	Severity    schema.Severity `json:"severity"`
	Target      string          `json:"target"`
	Title       string          `json:"title"`
}

type BaselineFile struct {
	SchemaVersion string          `json:"schema_version"`
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Count         int             `json:"count"`
	Entries       []BaselineEntry `json:"entries"`
}

// Fingerprint computes a deterministic cross-platform identifier for baseline comparisons.
func Fingerprint(f schema.Finding) string {
	normTarget := strings.ReplaceAll(strings.TrimSpace(f.Target), `\`, "/")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s",
		strings.TrimSpace(f.RuleID),
		strings.TrimSpace(f.Module),
		normTarget,
		strings.TrimSpace(f.Title),
	)))
	return hex.EncodeToString(sum[:12])
}

// WriteBaseline persists deduplicated deterministic finding fingerprints to path.
func WriteBaseline(path string, findings []schema.Finding) error {
	seen := make(map[string]struct{}, len(findings))
	entries := make([]BaselineEntry, 0, len(findings))
	for _, f := range findings {
		fp := Fingerprint(f)
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		entries = append(entries, BaselineEntry{
			Fingerprint: fp,
			RuleID:      f.RuleID,
			Module:      f.Module,
			Severity:    f.Severity,
			Target:      strings.ReplaceAll(f.Target, `\`, "/"),
			Title:       f.Title,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].RuleID != entries[j].RuleID {
			return entries[i].RuleID < entries[j].RuleID
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})

	doc := BaselineFile{
		SchemaVersion: schema.SchemaVersion,
		Tool:          schema.ToolName,
		Version:       schema.Version,
		GeneratedAt:   time.Now().UTC(),
		Count:         len(entries),
		Entries:       entries,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create baseline directory: %w", err)
		}
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("write baseline %q: %w", path, err)
	}
	return nil
}

// LoadBaseline reads a baseline JSON file and returns the fingerprint lookup set.
func LoadBaseline(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat baseline %q: %w", path, err)
	}
	if info.Size() > MaxBaselineBytes {
		return nil, fmt.Errorf("baseline %q exceeds %d byte limit", path, MaxBaselineBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxBaselineBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	if len(raw) > MaxBaselineBytes {
		return nil, fmt.Errorf("baseline %q exceeds %d byte limit", path, MaxBaselineBytes)
	}

	var doc BaselineFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse baseline JSON %q: %w", path, err)
	}
	if doc.SchemaVersion == "" {
		return nil, fmt.Errorf("invalid baseline %q: missing schema_version", path)
	}

	out := make(map[string]struct{}, len(doc.Entries))
	for _, e := range doc.Entries {
		if fp := strings.TrimSpace(e.Fingerprint); fp != "" {
			out[fp] = struct{}{}
		}
	}
	return out, nil
}

// FilterBaseline removes known findings present in the baseline set.
func FilterBaseline(findings []schema.Finding, baseline map[string]struct{}) ([]schema.Finding, int) {
	if len(baseline) == 0 {
		return findings, 0
	}
	kept := make([]schema.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if _, known := baseline[Fingerprint(f)]; known {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}
