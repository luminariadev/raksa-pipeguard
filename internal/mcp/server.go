package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/ciworkflow"
	"github.com/luminariadev/raksa-pipeguard/internal/deps"
	"github.com/luminariadev/raksa-pipeguard/internal/iac"
	"github.com/luminariadev/raksa-pipeguard/internal/policy"
	"github.com/luminariadev/raksa-pipeguard/internal/report"
	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"github.com/luminariadev/raksa-pipeguard/internal/secrets"
)

const (
	MaxLineBytes    = 2 * 1024 * 1024
	ProtocolVersion = "2024-11-05"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError"`
}

// ServeStdio handles newline-delimited JSON-RPC 2.0 MCP requests from in until EOF.
func ServeStdio(in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, 64*1024)
	var writeMu sync.Mutex

	writeJSON := func(resp rpcResponse) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		payload, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		_, err = out.Write(append(payload, '\n'))
		return err
	}

	for {
		line, err := readBoundedLine(reader, MaxLineBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			_ = writeJSON(rpcResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32600, Message: err.Error()},
			})
			if errors.Is(err, errLineTooLarge) {
				// Drain remainder of oversized line so framing recovers cleanly or stop.
				continue
			}
			return err
		}

		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(trimmed, &req); err != nil {
			_ = writeJSON(rpcResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: fmt.Sprintf("invalid JSON: %v", err)},
			})
			continue
		}

		// JSON-RPC notifications (no ID) must not emit responses.
		if len(bytes.TrimSpace(req.ID)) == 0 || bytes.Equal(bytes.TrimSpace(req.ID), []byte("null")) {
			continue
		}

		resp := dispatchRequest(req)
		if err := writeJSON(resp); err != nil {
			return err
		}
	}
}

var errLineTooLarge = errors.New("request line exceeds 2 MiB size limit")

func readBoundedLine(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := r.ReadSlice('\n')
		buf = append(buf, frag...)
		if len(buf) > maxBytes {
			// Discard until newline or EOF to keep stream state safe.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return nil, errLineTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if errors.Is(err, io.EOF) && len(buf) == 0 {
			return nil, io.EOF
		}
		return buf, nil
	}
}

func dispatchRequest(req rpcRequest) rpcResponse {
	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    schema.ToolName,
				"version": schema.Version,
			},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": ToolDefinitions()}
	case "tools/call":
		var params toolCallParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				resp.Error = &rpcError{Code: -32602, Message: fmt.Sprintf("invalid params: %v", err)}
				return resp
			}
		}
		result := executeTool(params.Name, params.Arguments)
		resp.Result = result
	default:
		resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}
	}
	return resp
}

// ToolDefinitions returns the 7 registered MCP tools.
func ToolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "pipeguard_list_rules",
			Description: "List the raksa-pipeguard PIPE-* DevSecOps security rules with severities, standards, and MITRE D3FEND mappings.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"module": map[string]any{
						"type":        "string",
						"description": "Optional module filter: secrets, deps, iac, ci, or policy.",
					},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_scan_secrets",
			Description: "Scan a workspace path, optional git diff base, and git commit history for hardcoded credentials, private keys, and high-entropy secrets.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path":                map[string]any{"type": "string", "description": "File or repository directory to scan."},
					"entropy_threshold":   map[string]any{"type": "number", "description": "Shannon entropy threshold (default 4.2)."},
					"diff_base":           map[string]any{"type": "string", "description": "Optional git base ref (e.g. origin/main) to scan PR diff lines."},
					"include_git_history": map[string]any{"type": "boolean", "description": "Also scan recent git history commits for PIPE-006."},
					"git_commits":         map[string]any{"type": "integer", "description": "Maximum git commits to inspect (default 25)."},
					"policy_path":         map[string]any{"type": "string", "description": "Optional .pipeguard.yml waiver policy path."},
					"baseline_path":       map[string]any{"type": "string", "description": "Optional baseline JSON path to suppress existing fingerprints."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_scan_deps",
			Description: "Inventory dependency lockfiles, check SPDX licenses, and audit packages against an offline OSV database and/or cached live OSV.dev API.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path":          map[string]any{"type": "string", "description": "Project directory to inspect."},
					"offline_db":    map[string]any{"type": "string", "description": "Optional local offline OSV advisory JSON file."},
					"online":        map[string]any{"type": "boolean", "description": "Query live api.osv.dev batch API (default false)."},
					"no_cache":      map[string]any{"type": "boolean", "description": "Bypass local OSV disk cache when online is true."},
					"policy_path":   map[string]any{"type": "string", "description": "Optional .pipeguard.yml waiver policy path."},
					"baseline_path": map[string]any{"type": "string", "description": "Optional baseline JSON path to suppress existing fingerprints."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_generate_sbom",
			Description: "Generate a deterministic CycloneDX 1.5 JSON SBOM from Go, Node, Rust, and Python manifests/lockfiles.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Project directory to inventory."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_scan_iac",
			Description: "Audit Dockerfile, Kubernetes YAML, or Terraform HCL security configuration by path or inline snippet.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":        map[string]any{"type": "string", "description": "Directory or IaC file to scan."},
					"content":     map[string]any{"type": "string", "description": "Inline IaC content to scan instead of reading from disk."},
					"kind":        map[string]any{"type": "string", "description": "IaC format when using content: dockerfile, kubernetes, or terraform."},
					"target":      map[string]any{"type": "string", "description": "Logical target name when scanning inline content."},
					"policy_path": map[string]any{"type": "string", "description": "Optional .pipeguard.yml waiver policy path."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_scan_ci_workflow",
			Description: "Audit GitHub Actions workflows (.github/workflows/*.yml) and GitLab CI (.gitlab-ci.yml) pipelines for privilege misuse, script injection, secret leaks, and unpinned images/actions.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":        map[string]any{"type": "string", "description": "Repository root, .github/workflows dir, .gitlab-ci.yml, or workflow file."},
					"content":     map[string]any{"type": "string", "description": "Inline GitHub Actions or GitLab CI YAML."},
					"target":      map[string]any{"type": "string", "description": "Logical target path when using content (use .gitlab-ci.yml for GitLab CI)."},
					"policy_path": map[string]any{"type": "string", "description": "Optional .pipeguard.yml waiver policy path."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "pipeguard_scan_repo",
			Description: "Run full Layer 4 DevSecOps gate across secrets, dependencies/licenses, IaC, CI workflows, custom org rules, baseline diffing, and posture scoring.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path":                map[string]any{"type": "string", "description": "Repository directory to scan."},
					"policy_path":         map[string]any{"type": "string", "description": "Optional .pipeguard.yml waiver and custom rules policy path."},
					"baseline_path":       map[string]any{"type": "string", "description": "Optional baseline JSON file to suppress known fingerprints."},
					"diff_base":           map[string]any{"type": "string", "description": "Optional git base ref to filter findings to changed files plus PR diff secrets."},
					"offline_db":          map[string]any{"type": "string", "description": "Optional local offline OSV advisory JSON file."},
					"online":              map[string]any{"type": "boolean", "description": "Query live api.osv.dev batch API (default false)."},
					"no_cache":            map[string]any{"type": "boolean", "description": "Disable local OSV disk cache when online is true."},
					"include_git_history": map[string]any{"type": "boolean", "description": "Scan recent git commits for leaked history secrets."},
					"git_commits":         map[string]any{"type": "integer", "description": "Max commits when include_git_history is true (default 25)."},
					"format":              map[string]any{"type": "string", "description": "Output format: json (default), sarif, or table."},
				},
				"additionalProperties": false,
			},
		},
	}
}

func executeTool(name string, args map[string]any) toolCallResult {
	switch name {
	case "pipeguard_list_rules":
		moduleFilter := strings.ToLower(getString(args, "module"))
		catalog := schema.RuleCatalog()
		var filtered []schema.RuleInfo
		for _, r := range catalog {
			if moduleFilter == "" || strings.EqualFold(r.Module, moduleFilter) {
				filtered = append(filtered, r)
			}
		}
		payload, err := json.MarshalIndent(map[string]any{
			"schema_version": schema.SchemaVersion,
			"tool":           schema.ToolName,
			"total":          len(filtered),
			"rules":          filtered,
		}, "", "  ")
		if err != nil {
			return errToolResult(err.Error())
		}
		return okToolResult(string(payload))

	case "pipeguard_scan_secrets":
		target := getString(args, "path")
		if target == "" {
			return errToolResult("missing required argument: path")
		}
		entropy := getFloat(args, "entropy_threshold", secrets.DefaultMinEntropy)
		opts := secrets.ScanOptions{EntropyThreshold: entropy}
		findings, err := secrets.ScanPath(target, opts)
		if err != nil {
			return errToolResult(err.Error())
		}
		diffBase := getString(args, "diff_base")
		if diffBase != "" {
			diffHits, err := secrets.ScanGitDiffBase(target, diffBase, opts)
			if err != nil {
				return errToolResult(err.Error())
			}
			findings = append(findings, diffHits...)
		}
		if getBool(args, "include_git_history") {
			commits := getInt(args, "git_commits", 25)
			histFindings, err := secrets.ScanGitHistory(target, commits, opts)
			if err != nil {
				return errToolResult(err.Error())
			}
			findings = append(findings, histFindings...)
		}
		return formatToolFindings(findings, nil, target, getString(args, "policy_path"), getString(args, "baseline_path"), diffBase, report.FormatJSON)

	case "pipeguard_scan_deps":
		target := getString(args, "path")
		if target == "" {
			return errToolResult("missing required argument: path")
		}
		polPath := getString(args, "policy_path")
		pol, err := policy.LoadOptionalPolicy(target, polPath)
		if err != nil {
			return errToolResult(err.Error())
		}
		comps, invFindings, err := deps.InventoryFromPath(target)
		if err != nil {
			return errToolResult(err.Error())
		}
		var denied []string
		if pol != nil {
			denied = pol.DeniedLicenses
		}
		invFindings = append(invFindings, deps.AuditLicenses(comps, denied)...)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		vulnFindings, err := deps.AuditDependencies(ctx, comps, deps.OSVOptions{
			Online:        getBool(args, "online"),
			OfflineDBPath: getString(args, "offline_db"),
			Timeout:       15 * time.Second,
			NoCache:       getBool(args, "no_cache"),
		})
		if err != nil {
			return errToolResult(err.Error())
		}
		findings := append(invFindings, vulnFindings...)
		return formatToolFindings(findings, pol, target, polPath, getString(args, "baseline_path"), "", report.FormatJSON)

	case "pipeguard_generate_sbom":
		target := getString(args, "path")
		if target == "" {
			return errToolResult("missing required argument: path")
		}
		comps, _, err := deps.InventoryFromPath(target)
		if err != nil {
			return errToolResult(err.Error())
		}
		sbomJSON, err := deps.GenerateCycloneDX(target, comps)
		if err != nil {
			return errToolResult(err.Error())
		}
		return okToolResult(sbomJSON)

	case "pipeguard_scan_iac":
		content := getString(args, "content")
		target := getString(args, "path")
		policyPath := getString(args, "policy_path")
		var findings []schema.Finding
		var err error
		if content != "" {
			kind := getString(args, "kind")
			if kind == "" {
				return errToolResult("kind (dockerfile, kubernetes, or terraform) is required when content is provided")
			}
			logicalTarget := getString(args, "target")
			if logicalTarget == "" {
				logicalTarget = "inline." + kind
			}
			findings, err = iac.ScanContent(content, kind, logicalTarget)
		} else if target != "" {
			findings, err = iac.ScanPath(target)
		} else {
			return errToolResult("either path or content must be provided")
		}
		if err != nil {
			return errToolResult(err.Error())
		}
		return formatToolFindings(findings, nil, target, policyPath, "", "", report.FormatJSON)

	case "pipeguard_scan_ci_workflow":
		content := getString(args, "content")
		target := getString(args, "path")
		policyPath := getString(args, "policy_path")
		var findings []schema.Finding
		var err error
		if content != "" {
			logicalTarget := getString(args, "target")
			if logicalTarget == "" {
				logicalTarget = ".github/workflows/inline.yml"
			}
			findings, err = ciworkflow.ScanContent(content, logicalTarget)
		} else if target != "" {
			findings, err = ciworkflow.ScanPath(target)
		} else {
			return errToolResult("either path or content must be provided")
		}
		if err != nil {
			return errToolResult(err.Error())
		}
		return formatToolFindings(findings, nil, target, policyPath, "", "", report.FormatJSON)

	case "pipeguard_scan_repo":
		target := getString(args, "path")
		if target == "" {
			return errToolResult("missing required argument: path")
		}
		formatStr := getString(args, "format")
		if formatStr == "" {
			formatStr = "json"
		}
		outFormat, err := report.ParseFormat(formatStr)
		if err != nil {
			return errToolResult(err.Error())
		}

		polPath := getString(args, "policy_path")
		pol, err := policy.LoadOptionalPolicy(target, polPath)
		if err != nil {
			return errToolResult(err.Error())
		}

		secFindings, err := secrets.ScanPath(target, secrets.ScanOptions{})
		if err != nil {
			return errToolResult(err.Error())
		}
		var allFindings []schema.Finding
		allFindings = append(allFindings, secFindings...)

		diffBase := getString(args, "diff_base")
		if diffBase != "" {
			diffHits, err := secrets.ScanGitDiffBase(target, diffBase, secrets.ScanOptions{})
			if err != nil {
				return errToolResult(err.Error())
			}
			allFindings = append(allFindings, diffHits...)
		}

		if getBool(args, "include_git_history") {
			commits := getInt(args, "git_commits", 25)
			histFindings, err := secrets.ScanGitHistory(target, commits, secrets.ScanOptions{})
			if err != nil {
				return errToolResult(err.Error())
			}
			allFindings = append(allFindings, histFindings...)
		}

		comps, invFindings, err := deps.InventoryFromPath(target)
		if err != nil {
			return errToolResult(err.Error())
		}
		allFindings = append(allFindings, invFindings...)

		var denied []string
		if pol != nil {
			denied = pol.DeniedLicenses
		}
		allFindings = append(allFindings, deps.AuditLicenses(comps, denied)...)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		vulnFindings, err := deps.AuditDependencies(ctx, comps, deps.OSVOptions{
			Online:        getBool(args, "online"),
			OfflineDBPath: getString(args, "offline_db"),
			Timeout:       15 * time.Second,
			NoCache:       getBool(args, "no_cache"),
		})
		if err != nil {
			return errToolResult(err.Error())
		}
		allFindings = append(allFindings, vulnFindings...)

		iacFindings, err := iac.ScanPath(target)
		if err != nil {
			return errToolResult(err.Error())
		}
		allFindings = append(allFindings, iacFindings...)

		ciFindings, err := ciworkflow.ScanPath(target)
		if err != nil {
			return errToolResult(err.Error())
		}
		allFindings = append(allFindings, ciFindings...)

		if pol != nil && len(pol.CustomRules) > 0 {
			customHits, err := policy.EvaluateCustomRules(target, pol)
			if err != nil {
				return errToolResult(err.Error())
			}
			allFindings = append(allFindings, customHits...)
		}

		return formatToolFindings(allFindings, pol, target, polPath, getString(args, "baseline_path"), diffBase, outFormat)

	default:
		return errToolResult(fmt.Sprintf("unknown tool: %s", name))
	}
}

func formatToolFindings(findings []schema.Finding, pol *policy.Policy, scanTarget, explicitPolicy, baselinePath, diffBase string, format report.OutputFormat) toolCallResult {
	if pol == nil {
		loaded, err := policy.LoadOptionalPolicy(scanTarget, explicitPolicy)
		if err != nil {
			return errToolResult(err.Error())
		}
		pol = loaded
	}
	if strings.TrimSpace(diffBase) != "" {
		changed, err := secrets.ChangedFilesSince(scanTarget, diffBase)
		if err != nil {
			return errToolResult(err.Error())
		}
		findings = policy.FilterFindingsByChangedFiles(scanTarget, findings, changed)
	}
	filtered, _ := policy.ApplyPolicy(findings, pol, time.Now().UTC())
	if strings.TrimSpace(baselinePath) != "" {
		baseSet, err := policy.LoadBaseline(baselinePath)
		if err != nil {
			return errToolResult(err.Error())
		}
		filtered, _ = policy.FilterBaseline(filtered, baseSet)
	}
	rep := schema.NewReport(filtered, time.Now().UTC())

	var buf bytes.Buffer
	if err := report.WriteReport(&buf, rep, format); err != nil {
		return errToolResult(err.Error())
	}
	return okToolResult(buf.String())
}

func okToolResult(text string) toolCallResult {
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: text}},
		IsError: false,
	}
}

func errToolResult(msg string) toolCallResult {
	return toolCallResult{
		Content: []toolContent{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getFloat(m map[string]any, key string, fallback float64) float64 {
	if m == nil {
		return fallback
	}
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return fallback
}

func getInt(m map[string]any, key string, fallback int) int {
	if m == nil {
		return fallback
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return fallback
}
