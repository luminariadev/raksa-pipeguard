package ciworkflow

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"gopkg.in/yaml.v3"
)

const MaxWorkflowBytes = 1024 * 1024

var (
	untrustedExprRe = regexp.MustCompile(`(?i)\$\{\{[^}]*\b(?:github\.event\.(?:issue\.|pull_request\.(?:title|body|head\.)|comment\.|review\.|review_comment\.|discussion\.|commits|head_commit\.|pages|workflow_run\.(?:head_branch|pull_requests)|client_payload)|github\.head_ref)\b[^}]*\}\}`)
	prHeadCheckout  = regexp.MustCompile(`(?i)(?:github\.event\.pull_request\.head|github\.head_ref|gh\s+pr\s+checkout|pull/\$\{)`)
	sha40Re         = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	trustedOwnerTag = regexp.MustCompile(`^(?:actions|github)/`)
)

// ScanPath audits GitHub Actions workflow YAML files found under root.
func ScanPath(root string) ([]schema.Finding, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("stat ci workflow path %s: %w", root, err)
	}

	var files []string
	if !info.IsDir() {
		files = append(files, cleanRoot)
	} else {
		directWorkflowDir := strings.HasSuffix(filepath.ToSlash(cleanRoot), ".github/workflows") ||
			filepath.Base(cleanRoot) == "workflows"

		walkErr := filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" && path != cleanRoot {
					return filepath.SkipDir
				}
				switch name {
				case "node_modules", "vendor", "target", "dist", "build", ".next":
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			rel, relErr := filepath.Rel(cleanRoot, path)
			if relErr != nil {
				rel = path
			}
			slashed := filepath.ToSlash(rel)
			if directWorkflowDir && !strings.Contains(slashed, "/") {
				files = append(files, path)
				return nil
			}
			if strings.Contains(slashed, ".github/workflows/") {
				files = append(files, path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk ci workflows under %s: %w", root, walkErr)
		}
	}

	sort.Strings(files)
	findings := make([]schema.Finding, 0)
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, fmt.Errorf("stat workflow %s: %w", f, err)
		}
		if fi.Size() > MaxWorkflowBytes {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read workflow %s: %w", f, err)
		}
		rel, err := filepath.Rel(cleanRoot, f)
		target := filepath.ToSlash(f)
		if info.IsDir() && err == nil {
			target = filepath.ToSlash(rel)
		}
		itemFindings, err := ScanContent(string(data), target)
		if err != nil {
			return nil, err
		}
		findings = append(findings, itemFindings...)
	}
	return findings, nil
}

// ScanContent audits a single GitHub Actions workflow YAML document.
func ScanContent(content, target string) ([]schema.Finding, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewBufferString(content))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", target, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}

	root := doc.Content[0]
	now := time.Now().UTC()
	findings := make([]schema.Finding, 0)

	hasPRTarget, prTargetLine := hasTrigger(root, "pull_request_target")

	topPermsNode := mappingValue(root, "permissions")
	hasTopPerms := topPermsNode != nil
	if hasTopPerms && isWriteAllPermissions(topPermsNode) {
		findings = append(findings, schema.NewFinding(
			"PIPE-403",
			"ci",
			schema.SeverityHigh,
			"Workflow grants overly broad write-all GITHUB_TOKEN permissions",
			"Top-level permissions: write-all grants full read/write scopes to every job.",
			target,
			map[string]any{"line": topPermsNode.Line, "scope": "top-level", "permissions": "write-all"},
			"Replace permissions: write-all with minimal least-privilege scopes such as contents: read.",
			"D3-CH",
			fmt.Sprintf("perms-top-%d", topPermsNode.Line),
			now,
		))
	}

	jobsNode := mappingValue(root, "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		if !hasTopPerms {
			findings = append(findings, missingPermissionsFinding(target, root.Line, now))
		}
		return findings, nil
	}

	allJobsScoped := true
	jobCount := 0
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		jobName := jobsNode.Content[i].Value
		jobMap := jobsNode.Content[i+1]
		if jobMap.Kind != yaml.MappingNode {
			allJobsScoped = false
			continue
		}
		jobCount++

		jobPerms := mappingValue(jobMap, "permissions")
		if jobPerms == nil {
			allJobsScoped = false
		} else if isWriteAllPermissions(jobPerms) {
			findings = append(findings, schema.NewFinding(
				"PIPE-403",
				"ci",
				schema.SeverityHigh,
				"Workflow job grants write-all GITHUB_TOKEN permissions",
				fmt.Sprintf("Job %q configures permissions: write-all instead of least-privilege scopes.", jobName),
				target,
				map[string]any{"line": jobPerms.Line, "job": jobName, "permissions": "write-all"},
				"Restrict job permissions to only required scopes such as contents: read.",
				"D3-CH",
				fmt.Sprintf("perms-job-%s-%d", jobName, jobPerms.Line),
				now,
			))
		}

		if jobUses := mappingValue(jobMap, "uses"); jobUses != nil && jobUses.Kind == yaml.ScalarNode {
			if f, ok := checkActionPinning(jobUses.Value, target, jobName, jobUses.Line, now); ok {
				findings = append(findings, f)
			}
		}

		stepsNode := mappingValue(jobMap, "steps")
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}
		for idx, stepNode := range stepsNode.Content {
			if stepNode.Kind != yaml.MappingNode {
				continue
			}
			usesNode := mappingValue(stepNode, "uses")
			withNode := mappingValue(stepNode, "with")
			runNode := mappingValue(stepNode, "run")

			if usesNode != nil && usesNode.Kind == yaml.ScalarNode {
				if f, ok := checkActionPinning(usesNode.Value, target, jobName, usesNode.Line, now); ok {
					findings = append(findings, f)
				}
				if hasPRTarget && isCheckoutAction(usesNode.Value) && withNode != nil {
					if refNode := mappingValue(withNode, "ref"); refNode != nil && prHeadCheckout.MatchString(refNode.Value) {
						findings = append(findings, schema.NewFinding(
							"PIPE-401",
							"ci",
							schema.SeverityCritical,
							"pull_request_target workflow checks out untrusted PR head ref",
							fmt.Sprintf("Job %q (trigger line %d) runs under pull_request_target and checks out untrusted PR head ref %q.", jobName, prTargetLine, refNode.Value),
							target,
							map[string]any{"line": refNode.Line, "job": jobName, "step": idx + 1, "ref": refNode.Value},
							"Switch trigger to pull_request, or never check out PR head refs inside workflows that hold repository secrets.",
							"D3-CH",
							fmt.Sprintf("prtarget-checkout-%s-%d", jobName, refNode.Line),
							now,
						))
					}
				}
			}

			if runNode != nil && runNode.Kind == yaml.ScalarNode {
				if hasPRTarget && prHeadCheckout.MatchString(runNode.Value) {
					findings = append(findings, schema.NewFinding(
						"PIPE-401",
						"ci",
						schema.SeverityCritical,
						"pull_request_target workflow fetches or checks out PR head code",
						fmt.Sprintf("Job %q fetches PR head code under pull_request_target, exposing privileged secrets to fork PR changes.", jobName),
						target,
						map[string]any{"line": runNode.Line, "job": jobName, "step": idx + 1},
						"Use pull_request without privileged secrets, or isolate untrusted PR execution.",
						"D3-CH",
						fmt.Sprintf("prtarget-run-%s-%d", jobName, runNode.Line),
						now,
					))
				}

				if match := untrustedExprRe.FindString(runNode.Value); match != "" {
					findings = append(findings, schema.NewFinding(
						"PIPE-402",
						"ci",
						schema.SeverityCritical,
						"Untrusted GitHub event expression interpolated directly in shell run",
						fmt.Sprintf("Job %q embeds %s directly in a shell script block, enabling script injection.", jobName, match),
						target,
						map[string]any{"line": runNode.Line, "job": jobName, "step": idx + 1, "expression": match},
						"Bind the expression to an intermediate env variable on the step and reference it as \"$VAR\" in shell.",
						"D3-IV",
						fmt.Sprintf("inject-%s-%d", jobName, runNode.Line),
						now,
					))
				}
			}
		}
	}

	if !hasTopPerms && (jobCount == 0 || !allJobsScoped) {
		findings = append(findings, missingPermissionsFinding(target, root.Line, now))
	}

	return findings, nil
}

func missingPermissionsFinding(target string, line int, now time.Time) schema.Finding {
	return schema.NewFinding(
		"PIPE-403",
		"ci",
		schema.SeverityHigh,
		"Workflow omits explicit least-privilege permissions block",
		"No top-level permissions block is declared and one or more jobs omit explicit permissions, falling back to default repository token scopes.",
		target,
		map[string]any{"line": line, "scope": "workflow"},
		"Declare an explicit top-level `permissions: { contents: read }` block and elevate only where required.",
		"D3-CH",
		fmt.Sprintf("perms-missing-%d", line),
		now,
	)
}

func hasTrigger(root *yaml.Node, triggerName string) (bool, int) {
	onNode := mappingValue(root, "on")
	if onNode == nil {
		// YAML 1.1 compatibility if unquoted `on` ever decodes as `"true"`.
		onNode = mappingValue(root, "true")
	}
	if onNode == nil {
		return false, 0
	}
	switch onNode.Kind {
	case yaml.ScalarNode:
		return strings.EqualFold(strings.TrimSpace(onNode.Value), triggerName), onNode.Line
	case yaml.SequenceNode:
		for _, item := range onNode.Content {
			if strings.EqualFold(strings.TrimSpace(item.Value), triggerName) {
				return true, item.Line
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(onNode.Content); i += 2 {
			if strings.EqualFold(strings.TrimSpace(onNode.Content[i].Value), triggerName) {
				return true, onNode.Content[i].Line
			}
		}
	}
	return false, 0
}

func isWriteAllPermissions(node *yaml.Node) bool {
	if node.Kind == yaml.ScalarNode {
		return strings.EqualFold(strings.TrimSpace(node.Value), "write-all")
	}
	return false
}

func isCheckoutAction(uses string) bool {
	lower := strings.ToLower(strings.TrimSpace(uses))
	return strings.HasPrefix(lower, "actions/checkout@")
}

func checkActionPinning(usesRaw, target, jobName string, line int, now time.Time) (schema.Finding, bool) {
	uses := strings.TrimSpace(usesRaw)
	if uses == "" || strings.HasPrefix(uses, "./") {
		return schema.Finding{}, false
	}
	if strings.HasPrefix(strings.ToLower(uses), "docker://") {
		img := strings.TrimPrefix(uses, "docker://")
		lowerImg := strings.ToLower(img)
		if !strings.Contains(lowerImg, "@sha256:") && (strings.HasSuffix(lowerImg, ":latest") || !strings.Contains(lowerImg, ":")) {
			return schema.NewFinding(
				"PIPE-404",
				"ci",
				schema.SeverityMedium,
				"Workflow docker:// step uses unpinned or :latest container image",
				fmt.Sprintf("Job %q references %q without an immutable image tag or digest.", jobName, uses),
				target,
				map[string]any{"line": line, "job": jobName, "uses": uses},
				"Pin container images by immutable version tag or @sha256 digest.",
				"D3-SBOM",
				fmt.Sprintf("pin-docker-%s-%d", jobName, line),
				now,
			), true
		}
		return schema.Finding{}, false
	}

	atIdx := strings.LastIndex(uses, "@")
	if atIdx == -1 {
		return schema.NewFinding(
			"PIPE-404",
			"ci",
			schema.SeverityMedium,
			"Workflow action omits immutable version or commit SHA reference",
			fmt.Sprintf("Job %q references %q without a version tag or 40-character commit SHA.", jobName, uses),
			target,
			map[string]any{"line": line, "job": jobName, "uses": uses},
			"Pin third-party actions to a full 40-character commit SHA (and official actions/* or github/* actions to a release tag or SHA).",
			"D3-SBOM",
			fmt.Sprintf("pin-noref-%s-%d", jobName, line),
			now,
		), true
	}

	actionName := uses[:atIdx]
	ref := uses[atIdx+1:]
	lowerRef := strings.ToLower(ref)

	if lowerRef == "main" || lowerRef == "master" || lowerRef == "head" || lowerRef == "latest" {
		return schema.NewFinding(
			"PIPE-404",
			"ci",
			schema.SeverityMedium,
			"Workflow action tracks mutable branch reference",
			fmt.Sprintf("Job %q uses mutable ref @%s on %q, allowing upstream tag or branch tampering.", jobName, ref, actionName),
			target,
			map[string]any{"line": line, "job": jobName, "uses": uses, "ref": ref},
			"Replace mutable branch refs (@main/@master/@HEAD) with an immutable 40-character commit SHA.",
			"D3-SBOM",
			fmt.Sprintf("pin-branch-%s-%d", jobName, line),
			now,
		), true
	}

	if sha40Re.MatchString(ref) {
		return schema.Finding{}, false
	}

	if trustedOwnerTag.MatchString(strings.ToLower(actionName)) && strings.HasPrefix(lowerRef, "v") {
		return schema.Finding{}, false
	}

	return schema.NewFinding(
		"PIPE-404",
		"ci",
		schema.SeverityMedium,
		"Third-party workflow action is not pinned to a 40-character commit SHA",
		fmt.Sprintf("Job %q uses third-party action %q pinned only to mutable ref %q instead of a 40-character commit SHA.", jobName, actionName, ref),
		target,
		map[string]any{"line": line, "job": jobName, "uses": uses, "ref": ref},
		"Pin third-party GitHub Actions to an audited full 40-character commit SHA.",
		"D3-SBOM",
		fmt.Sprintf("pin-thirdparty-%s-%d", jobName, line),
		now,
	), true
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
