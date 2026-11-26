package fix

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type FixResult struct {
	Kind          string   `json:"kind"`
	Target        string   `json:"target"`
	Changed       bool     `json:"changed"`
	Changes       []string `json:"changes"`
	ManualReviews []string `json:"manual_reviews,omitempty"`
	Patched       string   `json:"patched"`
	Diff          string   `json:"diff"`
}

// SuggestFixes produces deterministic hardening patches for Dockerfile, Kubernetes YAML, and GitHub Actions workflows.
func SuggestFixes(content, kind, target string) (FixResult, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dockerfile":
		return fixDockerfile(content, target), nil
	case "kubernetes", "k8s":
		return fixKubernetesYAML(content, target)
	case "github-actions", "github", "gha", "ci":
		return fixGitHubActionsYAML(content, target)
	default:
		return FixResult{}, fmt.Errorf("unsupported fix kind %q: expected dockerfile, kubernetes, or github-actions", kind)
	}
}

func fixDockerfile(content, target string) FixResult {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var (
		changes []string
		manual  []string
		out     []string
		hasUser bool
		lastTag string
	)

	for _, line := range lines {
		trim := strings.TrimSpace(line)
		up := strings.ToUpper(trim)

		if strings.HasPrefix(up, "FROM ") {
			hasUser = strings.Contains(strings.ToLower(trim), "nonroot")
			lastTag = trim
			if strings.Contains(strings.ToLower(trim), ":latest") {
				manual = append(manual, "Replace mutable ':latest' in '"+trim+"' with a verified release tag or @sha256: digest.")
			}
			out = append(out, line)
			continue
		}
		if strings.HasPrefix(up, "USER ") {
			val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trim, trim[:5])))
			if val == "root" || val == "0" || strings.HasPrefix(val, "root:") || strings.HasPrefix(val, "0:") {
				out = append(out, "USER 10001:10001")
				changes = append(changes, "Replaced explicit root USER with non-root UID/GID 10001:10001.")
				hasUser = true
				continue
			}
			hasUser = true
		}
		if strings.Contains(line, "chmod 777") || strings.Contains(line, "chmod -R 777") {
			replaced := strings.ReplaceAll(strings.ReplaceAll(line, "chmod -R 777", "chmod -R 0755"), "chmod 777", "chmod 0755")
			out = append(out, replaced)
			changes = append(changes, "Tightened overly permissive chmod 777 to 0755.")
			continue
		}
		out = append(out, line)
	}

	if lastTag != "" && !hasUser {
		insertAt := len(out)
		for i := len(out) - 1; i >= 0; i-- {
			u := strings.ToUpper(strings.TrimSpace(out[i]))
			if strings.HasPrefix(u, "CMD ") || strings.HasPrefix(u, "CMD[") || strings.HasPrefix(u, "ENTRYPOINT ") || strings.HasPrefix(u, "ENTRYPOINT[") {
				insertAt = i
				break
			}
		}
		injected := make([]string, 0, len(out)+1)
		injected = append(injected, out[:insertAt]...)
		injected = append(injected, "USER 10001:10001")
		injected = append(injected, out[insertAt:]...)
		out = injected
		changes = append(changes, "Added non-root USER 10001:10001 before runtime entrypoint.")
	}

	patched := strings.Join(out, "\n")
	return FixResult{
		Kind:          "dockerfile",
		Target:        target,
		Changed:       patched != strings.ReplaceAll(content, "\r\n", "\n"),
		Changes:       changes,
		ManualReviews: manual,
		Patched:       patched,
		Diff:          buildUnifiedDiff(target, content, patched),
	}
}

func fixKubernetesYAML(content, target string) (FixResult, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewBufferString(content))
	if err := dec.Decode(&doc); err != nil {
		return FixResult{}, fmt.Errorf("parse kubernetes YAML %s: %w", target, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return FixResult{Kind: "kubernetes", Target: target, Patched: content}, nil
	}

	var changes []string
	root := doc.Content[0]
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i].Value
				v := n.Content[i+1]
				switch k {
				case "hostNetwork", "hostPID", "hostIPC":
					if v.Kind == yaml.ScalarNode && strings.EqualFold(v.Value, "true") {
						v.Value = "false"
						v.Tag = "!!bool"
						changes = append(changes, fmt.Sprintf("Set %s: false on pod spec.", k))
					}
				case "containers", "initContainers":
					if v.Kind == yaml.SequenceNode {
						for _, cNode := range v.Content {
							if cNode.Kind == yaml.MappingNode {
								cChanges := hardenK8sContainer(cNode)
								changes = append(changes, cChanges...)
							}
						}
					}
				}
				walk(v)
			}
		} else if n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				walk(item)
			}
		}
	}
	walk(root)

	var outBuf bytes.Buffer
	enc := yaml.NewEncoder(&outBuf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return FixResult{}, err
	}
	_ = enc.Close()

	patched := outBuf.String()
	return FixResult{
		Kind:    "kubernetes",
		Target:  target,
		Changed: patched != content,
		Changes: changes,
		Patched: patched,
		Diff:    buildUnifiedDiff(target, content, patched),
	}, nil
}

func hardenK8sContainer(cNode *yaml.Node) []string {
	var changes []string
	sec := mapLookup(cNode, "securityContext")
	if sec == nil {
		sec = &yaml.Node{Kind: yaml.MappingNode}
		setMapScalar(cNode, "securityContext", "")
		// Replace just inserted placeholder value with mapping node.
		for i := 0; i+1 < len(cNode.Content); i += 2 {
			if cNode.Content[i].Value == "securityContext" {
				cNode.Content[i+1] = sec
			}
		}
		changes = append(changes, "Added container securityContext block.")
	}

	if priv := mapLookup(sec, "privileged"); priv != nil && strings.EqualFold(priv.Value, "true") {
		priv.Value = "false"
		priv.Tag = "!!bool"
		changes = append(changes, "Disabled privileged: true on container.")
	}
	for _, boolKey := range []struct {
		k, v string
	}{
		{"runAsNonRoot", "true"},
		{"allowPrivilegeEscalation", "false"},
		{"readOnlyRootFilesystem", "true"},
	} {
		cur := mapLookup(sec, boolKey.k)
		if cur == nil {
			setMapTypedScalar(sec, boolKey.k, boolKey.v, "!!bool")
			changes = append(changes, fmt.Sprintf("Set securityContext.%s: %s.", boolKey.k, boolKey.v))
		} else if !strings.EqualFold(cur.Value, boolKey.v) {
			cur.Value = boolKey.v
			cur.Tag = "!!bool"
			changes = append(changes, fmt.Sprintf("Updated securityContext.%s to %s.", boolKey.k, boolKey.v))
		}
	}

	caps := mapLookup(sec, "capabilities")
	if caps == nil {
		caps = &yaml.Node{Kind: yaml.MappingNode}
		sec.Content = append(sec.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "capabilities"}, caps)
	}
	if drop := mapLookup(caps, "drop"); drop == nil {
		caps.Content = append(caps.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "drop"},
			&yaml.Node{
				Kind:    yaml.SequenceNode,
				Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "ALL"}},
			},
		)
		changes = append(changes, "Dropped ALL Linux capabilities on container.")
	}

	res := mapLookup(cNode, "resources")
	if res == nil {
		res = &yaml.Node{Kind: yaml.MappingNode}
		cNode.Content = append(cNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "resources"}, res)
	}
	if mapLookup(res, "limits") == nil {
		lim := &yaml.Node{Kind: yaml.MappingNode}
		setMapScalar(lim, "cpu", "500m")
		setMapScalar(lim, "memory", "256Mi")
		res.Content = append(res.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "limits"}, lim)
		changes = append(changes, "Added bounded CPU/memory resource limits.")
	}
	return changes
}

func fixGitHubActionsYAML(content, target string) (FixResult, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewBufferString(content))
	if err := dec.Decode(&doc); err != nil {
		return FixResult{}, fmt.Errorf("parse workflow YAML %s: %w", target, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return FixResult{Kind: "github-actions", Target: target, Patched: content}, nil
	}

	var changes []string
	var manual []string
	root := doc.Content[0]

	onNode := mapLookup(root, "on")
	if onNode == nil {
		onNode = mapLookup(root, "true")
	}
	if onNode != nil {
		if rewriteTriggerPRTarget(onNode) {
			changes = append(changes, "Converted risky pull_request_target trigger to pull_request.")
		}
	}

	perms := mapLookup(root, "permissions")
	if perms == nil {
		pMap := &yaml.Node{Kind: yaml.MappingNode}
		setMapScalar(pMap, "contents", "read")
		insertMapNodeAfter(root, "on", "permissions", pMap)
		changes = append(changes, "Inserted top-level least-privilege permissions: { contents: read }.")
	} else if perms.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(perms.Value), "write-all") {
		pMap := &yaml.Node{Kind: yaml.MappingNode}
		setMapScalar(pMap, "contents", "read")
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "permissions" {
				root.Content[i+1] = pMap
				break
			}
		}
		changes = append(changes, "Replaced permissions: write-all with least-privilege permissions: { contents: read }.")
	}

	jobs := mapLookup(root, "jobs")
	if jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobs.Content); i += 2 {
			jobMap := jobs.Content[i+1]
			steps := mapLookup(jobMap, "steps")
			if steps == nil || steps.Kind != yaml.SequenceNode {
				continue
			}
			for _, step := range steps.Content {
				if step.Kind != yaml.MappingNode {
					continue
				}
				if uses := mapLookup(step, "uses"); uses != nil {
					if strings.Contains(uses.Value, "@main") || strings.Contains(uses.Value, "@master") {
						manual = append(manual, fmt.Sprintf("Pin mutable action ref %q to a full 40-character commit SHA.", uses.Value))
					}
				}
				if runNode := mapLookup(step, "run"); runNode != nil && strings.Contains(runNode.Value, "${{") && strings.Contains(strings.ToLower(runNode.Value), "github.event.") {
					if moved := hoistExprToStepEnv(step, runNode); moved {
						changes = append(changes, "Moved ${{ github.event.* }} expression out of shell run into safe step env variable.")
					}
				}
			}
		}
	}

	var outBuf bytes.Buffer
	enc := yaml.NewEncoder(&outBuf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return FixResult{}, err
	}
	_ = enc.Close()

	patched := outBuf.String()
	return FixResult{
		Kind:          "github-actions",
		Target:        target,
		Changed:       patched != content,
		Changes:       changes,
		ManualReviews: manual,
		Patched:       patched,
		Diff:          buildUnifiedDiff(target, content, patched),
	}, nil
}

func rewriteTriggerPRTarget(onNode *yaml.Node) bool {
	switch onNode.Kind {
	case yaml.ScalarNode:
		if strings.EqualFold(onNode.Value, "pull_request_target") {
			onNode.Value = "pull_request"
			return true
		}
	case yaml.SequenceNode:
		changed := false
		for _, item := range onNode.Content {
			if strings.EqualFold(item.Value, "pull_request_target") {
				item.Value = "pull_request"
				changed = true
			}
		}
		return changed
	case yaml.MappingNode:
		for i := 0; i+1 < len(onNode.Content); i += 2 {
			if strings.EqualFold(onNode.Content[i].Value, "pull_request_target") {
				onNode.Content[i].Value = "pull_request"
				return true
			}
		}
	}
	return false
}

func hoistExprToStepEnv(step, runNode *yaml.Node) bool {
	s := runNode.Value
	start := strings.Index(s, "${{")
	if start < 0 {
		return false
	}
	end := strings.Index(s[start:], "}}")
	if end < 0 {
		return false
	}
	expr := s[start : start+end+2]
	if !strings.Contains(strings.ToLower(expr), "github.event.") && !strings.Contains(strings.ToLower(expr), "github.head_ref") {
		return false
	}

	envNode := mapLookup(step, "env")
	if envNode == nil || envNode.Kind != yaml.MappingNode {
		envNode = &yaml.Node{Kind: yaml.MappingNode}
		insertMapNodeAfter(step, "name", "env", envNode)
	}
	varName := "UNTRUSTED_EVENT_INPUT"
	setMapScalar(envNode, varName, expr)
	runNode.Value = strings.Replace(s, expr, "$"+varName, 1)
	return true
}

func mapLookup(m *yaml.Node, key string) *yaml.Node {
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

func setMapScalar(m *yaml.Node, key, val string) {
	setMapTypedScalar(m, key, val, "!!str")
}

func setMapTypedScalar(m *yaml.Node, key, val, tag string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Kind = yaml.ScalarNode
			m.Content[i+1].Value = val
			m.Content[i+1].Tag = tag
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: val, Tag: tag},
	)
}

func insertMapNodeAfter(m *yaml.Node, afterKey, newKey string, newVal *yaml.Node) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: newKey}
	idx := -1
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == afterKey || (afterKey == "on" && m.Content[i].Value == "true") {
			idx = i + 2
			break
		}
	}
	if idx < 0 {
		m.Content = append(m.Content, keyNode, newVal)
		return
	}
	out := make([]*yaml.Node, 0, len(m.Content)+2)
	out = append(out, m.Content[:idx]...)
	out = append(out, keyNode, newVal)
	out = append(out, m.Content[idx:]...)
	m.Content = out
}

func buildUnifiedDiff(target, oldText, newText string) string {
	oldLines := strings.Split(strings.ReplaceAll(oldText, "\r\n", "\n"), "\n")
	newLines := strings.Split(strings.ReplaceAll(newText, "\r\n", "\n"), "\n")
	if strings.Join(oldLines, "\n") == strings.Join(newLines, "\n") {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n@@ -1,%d +1,%d @@\n", target, target, len(oldLines), len(newLines))
	for _, l := range oldLines {
		fmt.Fprintf(&b, "-%s\n", l)
	}
	for _, l := range newLines {
		fmt.Fprintf(&b, "+%s\n", l)
	}
	return b.String()
}
