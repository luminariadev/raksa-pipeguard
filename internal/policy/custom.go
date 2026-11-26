package policy

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const MaxCustomRuleScanBytes = 2 * 1024 * 1024

// EvaluateCustomRules executes compiled regex rules from p against workspace text files under root.
func EvaluateCustomRules(root string, p *Policy) ([]schema.Finding, error) {
	if p == nil || len(p.CustomRules) == 0 {
		return nil, nil
	}

	// Defensive compile check for callers constructing Policy structs programmatically in tests.
	for i := range p.CustomRules {
		if p.CustomRules[i].compiled == nil && strings.TrimSpace(p.CustomRules[i].Pattern) != "" {
			re, err := regexp.Compile(p.CustomRules[i].Pattern)
			if err != nil {
				return nil, fmt.Errorf("compile custom rule %s: %w", p.CustomRules[i].ID, err)
			}
			p.CustomRules[i].compiled = re
		}
	}

	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("stat custom-rule path %q: %w", root, err)
	}

	var files []string
	if !info.IsDir() {
		files = append(files, cleanRoot)
	} else {
		walkErr := filepath.WalkDir(cleanRoot, func(p string, d fs.DirEntry, wErr error) error {
			if wErr != nil {
				return wErr
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "vendor", "target", "dist", "build", ".next":
					if p != cleanRoot {
						return filepath.SkipDir
					}
				}
				return nil
			}
			files = append(files, p)
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk custom-rule dir %q: %w", root, walkErr)
		}
	}
	sort.Strings(files)

	now := time.Now().UTC()
	var findings []schema.Finding

	for _, fpath := range files {
		rel, relErr := filepath.Rel(cleanRoot, fpath)
		if relErr != nil {
			rel = fpath
		}
		relSlash := filepath.ToSlash(rel)
		if !info.IsDir() {
			relSlash = filepath.Base(fpath)
		}

		// Check if at least one rule applies to this path before reading the file.
		var matchingRules []CustomRule
		for _, r := range p.CustomRules {
			if r.compiled == nil {
				continue
			}
			if ruleMatchesPath(r.PathGlob, fpath, relSlash) {
				matchingRules = append(matchingRules, r)
			}
		}
		if len(matchingRules) == 0 {
			continue
		}

		content, ok := readBoundedText(fpath)
		if !ok {
			continue
		}
		target := "file://" + filepath.ToSlash(fpath)
		lines := strings.Split(content, "\n")

		for idx, rawLine := range lines {
			line := strings.TrimRight(rawLine, "\r")
			if strings.TrimSpace(line) == "" || strings.Contains(line, "MustCompile(") {
				continue
			}
			lineNo := idx + 1
			for _, rule := range matchingRules {
				if !rule.compiled.MatchString(line) {
					continue
				}
				rem := rule.Remediation
				if rem == "" {
					rem = fmt.Sprintf("Remediate custom policy rule %s.", rule.ID)
				}
				findings = append(findings, schema.NewFinding(
					"PIPE-501",
					"policy",
					rule.Severity,
					rule.Title,
					fmt.Sprintf("Custom organization policy rule %s triggered on line %d.", rule.ID, lineNo),
					target,
					map[string]any{
						"custom_rule_id": rule.ID,
						"line":           lineNo,
						"standard":       "Enterprise Custom Policy",
					},
					rem,
					"D3-CH",
					fmt.Sprintf("%s-%s-l%d", rule.ID, filepath.Base(fpath), lineNo),
					now,
				))
			}
		}
	}

	return findings, nil
}

func ruleMatchesPath(glob, fullPath, relSlash string) bool {
	if strings.TrimSpace(glob) == "" {
		return true
	}
	base := filepath.Base(fullPath)
	if ok, _ := filepath.Match(glob, base); ok {
		return true
	}
	if ok, _ := filepath.Match(glob, relSlash); ok {
		return true
	}
	return false
}

func readBoundedText(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > MaxCustomRuleScanBytes {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxCustomRuleScanBytes+1))
	if err != nil || len(data) > MaxCustomRuleScanBytes {
		return "", false
	}
	probe := data
	if len(probe) > 8192 {
		probe = probe[:8192]
	}
	if bytes.IndexByte(probe, 0) >= 0 {
		return "", false
	}
	return string(data), true
}
