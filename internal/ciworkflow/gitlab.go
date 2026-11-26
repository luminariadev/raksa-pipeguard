package ciworkflow

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"gopkg.in/yaml.v3"
)

var (
	pipeShellRe       = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|\r\n]*\|\s*(?:sh|bash|zsh|ash|dash)\b`)
	sensitiveVarKeyRe = regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api_key|apikey|private_key|credential)`)
	scriptLeakCmdRe   = regexp.MustCompile(`(?i)(?:\bprintenv\b|\benv\s*\|\s*grep\b|\becho\s+["']?\$(?:CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|DEPLOY_TOKEN|NPM_TOKEN|API_KEY|SECRET))`)
	gitlabVarRefRe    = regexp.MustCompile(`^\$[A-Za-z0-9_{}]+$`)
)

// ScanGitLabContent audits a GitLab CI configuration (.gitlab-ci.yml) for PIPE-405..PIPE-407.
func ScanGitLabContent(content, target string) ([]schema.Finding, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewBufferString(content))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse gitlab ci %s: %w", target, err)
	}
	return scanGitLabNode(&doc, target), nil
}

func isGitLabYAML(root *yaml.Node, target string) bool {
	if strings.Contains(strings.ToLower(target), ".gitlab-ci") {
		return true
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return false
	}
	if mappingValue(root, "on") != nil || mappingValue(root, "true") != nil || mappingValue(root, "jobs") != nil {
		return false
	}
	for _, key := range []string{"stages", "include", "before_script", "after_script", "script", "default"} {
		if mappingValue(root, key) != nil {
			return true
		}
	}
	return false
}

func scanGitLabNode(doc *yaml.Node, target string) []schema.Finding {
	if doc == nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	root := doc.Content[0]
	now := time.Now().UTC()
	findings := make([]schema.Finding, 0)

	topVars := collectVarStrings(mappingValue(root, "variables"))
	topTLSDisabled := hasEmptyTLSCertDir(topVars)

	if imgNode := mappingValue(root, "image"); imgNode != nil {
		if f, ok := checkGitLabImage(imgNode, target, "global", now); ok {
			findings = append(findings, f)
		}
	}
	if defNode := mappingValue(root, "default"); defNode != nil && defNode.Kind == yaml.MappingNode {
		if imgNode := mappingValue(defNode, "image"); imgNode != nil {
			if f, ok := checkGitLabImage(imgNode, target, "default", now); ok {
				findings = append(findings, f)
			}
		}
		findings = append(findings, scanGitLabServices(mappingValue(defNode, "services"), topTLSDisabled, target, "default", now)...)
		findings = append(findings, scanGitLabScripts(defNode, target, "default", now)...)
	}

	findings = append(findings, scanGitLabServices(mappingValue(root, "services"), topTLSDisabled, target, "global", now)...)
	findings = append(findings, scanGitLabVariables(mappingValue(root, "variables"), target, "global", now)...)
	findings = append(findings, scanGitLabInclude(mappingValue(root, "include"), target, now)...)
	findings = append(findings, scanGitLabScripts(root, target, "global", now)...)

	reserved := map[string]bool{
		"stages": true, "include": true, "variables": true, "services": true,
		"image": true, "before_script": true, "after_script": true,
		"default": true, "cache": true, "workflow": true,
	}

	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]
		if reserved[key] || val.Kind != yaml.MappingNode {
			continue
		}

		if imgNode := mappingValue(val, "image"); imgNode != nil {
			if f, ok := checkGitLabImage(imgNode, target, key, now); ok {
				findings = append(findings, f)
			}
		}
		jobVars := collectVarStrings(mappingValue(val, "variables"))
		tlsDisabled := topTLSDisabled || hasEmptyTLSCertDir(jobVars)
		findings = append(findings, scanGitLabServices(mappingValue(val, "services"), tlsDisabled, target, key, now)...)
		findings = append(findings, scanGitLabVariables(mappingValue(val, "variables"), target, key, now)...)
		findings = append(findings, scanGitLabScripts(val, target, key, now)...)
	}

	return findings
}

func collectVarStrings(varsNode *yaml.Node) map[string]string {
	out := make(map[string]string)
	if varsNode == nil || varsNode.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		k := varsNode.Content[i].Value
		v := varsNode.Content[i+1]
		if v.Kind == yaml.ScalarNode {
			out[k] = v.Value
		} else if v.Kind == yaml.MappingNode {
			if vn := mappingValue(v, "value"); vn != nil && vn.Kind == yaml.ScalarNode {
				out[k] = vn.Value
			}
		}
	}
	return out
}

func hasEmptyTLSCertDir(vars map[string]string) bool {
	val, exists := vars["DOCKER_TLS_CERTDIR"]
	return exists && strings.TrimSpace(val) == ""
}

func checkGitLabImage(node *yaml.Node, target, scope string, now time.Time) (schema.Finding, bool) {
	imgRef, line := extractGitLabImageName(node)
	if imgRef == "" || strings.Contains(imgRef, "$") {
		return schema.Finding{}, false
	}
	low := strings.ToLower(imgRef)
	if !strings.Contains(low, "@sha256:") && (strings.HasSuffix(low, ":latest") || !hasImageTag(imgRef)) {
		return schema.NewFinding(
			"PIPE-407",
			"ci",
			schema.SeverityMedium,
			"GitLab CI container image uses mutable :latest or untagged reference",
			fmt.Sprintf("Scope %q uses container image %q without a pinned version tag or @sha256 digest.", scope, imgRef),
			target,
			map[string]any{"line": line, "scope": scope, "image": imgRef},
			"Pin CI images to an immutable release tag or @sha256 digest.",
			"D3-SBOM",
			fmt.Sprintf("gitlab-image-%s-%d", scope, line),
			now,
		), true
	}
	return schema.Finding{}, false
}

func hasImageTag(img string) bool {
	lastSlash := strings.LastIndexByte(img, '/')
	lastColon := strings.LastIndexByte(img, ':')
	return lastColon > lastSlash
}

func extractGitLabImageName(node *yaml.Node) (string, int) {
	if node == nil {
		return "", 0
	}
	if node.Kind == yaml.ScalarNode {
		return strings.TrimSpace(node.Value), node.Line
	}
	if node.Kind == yaml.MappingNode {
		if nameNode := mappingValue(node, "name"); nameNode != nil && nameNode.Kind == yaml.ScalarNode {
			return strings.TrimSpace(nameNode.Value), nameNode.Line
		}
	}
	return "", node.Line
}

func scanGitLabServices(servicesNode *yaml.Node, tlsDisabled bool, target, scope string, now time.Time) []schema.Finding {
	if servicesNode == nil || servicesNode.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []schema.Finding
	for _, svc := range servicesNode.Content {
		img, line := extractGitLabImageName(svc)
		if img == "" {
			continue
		}
		if tlsDisabled && strings.Contains(strings.ToLower(img), "dind") {
			findings = append(findings, schema.NewFinding(
				"PIPE-405",
				"ci",
				schema.SeverityCritical,
				"GitLab CI runs privileged docker:dind with TLS disabled",
				fmt.Sprintf("Scope %q configures DinD service %q alongside DOCKER_TLS_CERTDIR: \"\", exposing an unauthenticated Docker daemon socket.", scope, img),
				target,
				map[string]any{"line": line, "scope": scope, "service": img},
				"Enable TLS with DOCKER_TLS_CERTDIR: \"/certs\" or replace privileged DinD with rootless Kaniko/BuildKit.",
				"D3-CH",
				fmt.Sprintf("gitlab-dind-%s-%d", scope, line),
				now,
			))
		}
	}
	return findings
}

func scanGitLabVariables(varsNode *yaml.Node, target, scope string, now time.Time) []schema.Finding {
	if varsNode == nil || varsNode.Kind != yaml.MappingNode {
		return nil
	}
	var findings []schema.Finding
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		keyNode := varsNode.Content[i]
		valNode := varsNode.Content[i+1]
		key := strings.TrimSpace(keyNode.Value)
		if !sensitiveVarKeyRe.MatchString(key) {
			continue
		}
		var valStr string
		if valNode.Kind == yaml.ScalarNode {
			valStr = valNode.Value
		} else if valNode.Kind == yaml.MappingNode {
			if vn := mappingValue(valNode, "value"); vn != nil {
				valStr = vn.Value
			}
		}
		trimmed := strings.TrimSpace(valStr)
		if len(trimmed) < 6 || gitlabVarRefRe.MatchString(trimmed) || isSafeVarPlaceholder(trimmed) {
			continue
		}
		findings = append(findings, schema.NewFinding(
			"PIPE-406",
			"ci",
			schema.SeverityHigh,
			"GitLab CI variable hardcodes sensitive credential literal",
			fmt.Sprintf("Variable %q in %q embeds a static credential value directly inside pipeline YAML.", key, scope),
			target,
			map[string]any{"line": keyNode.Line, "scope": scope, "variable": key},
			"Move credentials to protected, masked GitLab CI/CD Variables or OIDC secret backends.",
			"D3-KM",
			fmt.Sprintf("gitlab-var-%s-%s-%d", scope, key, keyNode.Line),
			now,
		))
	}
	return findings
}

func isSafeVarPlaceholder(v string) bool {
	low := strings.ToLower(v)
	switch low {
	case "true", "false", "null", "changeme", "placeholder", "example", "your_secret_here":
		return true
	}
	return strings.Contains(low, "example") || strings.Contains(low, "placeholder")
}

func scanGitLabInclude(incNode *yaml.Node, target string, now time.Time) []schema.Finding {
	if incNode == nil {
		return nil
	}
	var entries []*yaml.Node
	switch incNode.Kind {
	case yaml.SequenceNode:
		entries = incNode.Content
	case yaml.ScalarNode, yaml.MappingNode:
		entries = []*yaml.Node{incNode}
	}

	var findings []schema.Finding
	for _, entry := range entries {
		if entry.Kind == yaml.ScalarNode {
			val := strings.TrimSpace(entry.Value)
			if strings.HasPrefix(strings.ToLower(val), "http://") {
				findings = append(findings, insecureIncludeFinding(target, entry.Line, val, now))
			}
			continue
		}
		if entry.Kind != yaml.MappingNode {
			continue
		}
		if rem := mappingValue(entry, "remote"); rem != nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(rem.Value)), "http://") {
			findings = append(findings, insecureIncludeFinding(target, rem.Line, rem.Value, now))
		}
		if proj := mappingValue(entry, "project"); proj != nil && strings.TrimSpace(proj.Value) != "" {
			refNode := mappingValue(entry, "ref")
			refVal := ""
			refLine := proj.Line
			if refNode != nil {
				refVal = strings.TrimSpace(refNode.Value)
				refLine = refNode.Line
			}
			lowRef := strings.ToLower(refVal)
			if refVal == "" || lowRef == "main" || lowRef == "master" || lowRef == "head" {
				findings = append(findings, schema.NewFinding(
					"PIPE-407",
					"ci",
					schema.SeverityMedium,
					"GitLab CI include references mutable or unpinned remote project ref",
					fmt.Sprintf("Cross-project include %q omits an immutable tag/SHA or tracks mutable ref %q.", proj.Value, refVal),
					target,
					map[string]any{"line": refLine, "project": proj.Value, "ref": refVal},
					"Pin external GitLab CI includes to a full commit SHA or immutable release tag.",
					"D3-SBOM",
					fmt.Sprintf("gitlab-inc-ref-%d", refLine),
					now,
				))
			}
		}
	}
	return findings
}

func insecureIncludeFinding(target string, line int, remote string, now time.Time) schema.Finding {
	return schema.NewFinding(
		"PIPE-407",
		"ci",
		schema.SeverityMedium,
		"GitLab CI include fetches remote template over unencrypted HTTP",
		fmt.Sprintf("Remote CI include %q uses insecure http:// transport vulnerable to MITM tampering.", remote),
		target,
		map[string]any{"line": line, "remote": remote},
		"Serve remote CI templates exclusively over HTTPS or pin project includes to a commit SHA.",
		"D3-SBOM",
		fmt.Sprintf("gitlab-inc-http-%d", line),
		now,
	)
}

func scanGitLabScripts(mapNode *yaml.Node, target, scope string, now time.Time) []schema.Finding {
	var findings []schema.Finding
	for _, blockKey := range []string{"before_script", "script", "after_script"} {
		blk := mappingValue(mapNode, blockKey)
		if blk == nil {
			continue
		}
		var cmdNodes []*yaml.Node
		switch blk.Kind {
		case yaml.ScalarNode:
			cmdNodes = []*yaml.Node{blk}
		case yaml.SequenceNode:
			cmdNodes = blk.Content
		}
		for _, n := range cmdNodes {
			if n.Kind != yaml.ScalarNode {
				continue
			}
			if pipeShellRe.MatchString(n.Value) {
				findings = append(findings, schema.NewFinding(
					"PIPE-405",
					"ci",
					schema.SeverityCritical,
					"GitLab CI script pipes remote download directly into shell",
					fmt.Sprintf("Block %s in %q executes an unverified remote curl/wget payload via shell pipe.", blockKey, scope),
					target,
					map[string]any{"line": n.Line, "scope": scope, "block": blockKey},
					"Download verified artifacts with SHA-256 checksum validation before executing them.",
					"D3-CH",
					fmt.Sprintf("gitlab-pipe-sh-%s-%d", scope, n.Line),
					now,
				))
			}
			if scriptLeakCmdRe.MatchString(n.Value) {
				findings = append(findings, schema.NewFinding(
					"PIPE-406",
					"ci",
					schema.SeverityHigh,
					"GitLab CI script exposes environment variables or secret tokens in logs",
					fmt.Sprintf("Block %s in %q runs printenv/env-grep or echoes sensitive CI tokens into build logs.", blockKey, scope),
					target,
					map[string]any{"line": n.Line, "scope": scope, "block": blockKey},
					"Remove diagnostic dumps of CI tokens and secret environment variables from job scripts.",
					"D3-KM",
					fmt.Sprintf("gitlab-leak-%s-%d", scope, n.Line),
					now,
				))
			}
		}
	}
	return findings
}
