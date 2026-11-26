package mcp

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPStdioLifecycleAndTools(t *testing.T) {
	if len(ToolDefinitions()) != 7 {
		t.Fatalf("expected 7 MCP tools, got %d", len(ToolDefinitions()))
	}

	vulnPath := filepath.Join("..", "..", "testdata", "vulnerable")
	hardenedPath := filepath.Join("..", "..", "testdata", "hardened")

	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pipeguard_list_rules","arguments":{"module":"ci"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pipeguard_scan_iac","arguments":{"content":"FROM alpine:latest\nRUN chmod 777 /tmp\n","kind":"dockerfile","target":"inline.Dockerfile"}}}`,
		mustMarshalCall(5, "pipeguard_scan_repo", map[string]any{"path": hardenedPath}),
		mustMarshalCall(6, "pipeguard_scan_repo", map[string]any{
			"path":       vulnPath,
			"offline_db": filepath.Join(vulnPath, "offline_osv.json"),
		}),
		mustMarshalCall(7, "pipeguard_generate_sbom", map[string]any{"path": vulnPath}),
	}

	var out bytes.Buffer
	if err := ServeStdio(strings.NewReader(strings.Join(requests, "\n")+"\n"), &out); err != nil {
		t.Fatalf("ServeStdio failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// 7 ID-bearing requests (notification emits no response).
	if len(lines) != 7 {
		t.Fatalf("expected 7 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}

	// Verify initialize + tools/list + rules + IaC inline + hardened score=100 + vuln breach + CycloneDX.
	var listResp struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("unmarshal tools/list response: %v", err)
	}
	if len(listResp.Result.Tools) != 7 {
		t.Fatalf("expected 7 listed tools, got %d", len(listResp.Result.Tools))
	}

	hardenedText := extractToolText(t, lines[4])
	if !strings.Contains(hardenedText, `"score": 100`) || !strings.Contains(hardenedText, `"grade": "A+"`) {
		t.Fatalf("expected hardened scan to score 100 A+, got:\n%s", hardenedText)
	}

	vulnText := extractToolText(t, lines[5])
	if !strings.Contains(vulnText, "PIPE-401") || !strings.Contains(vulnText, "CVE-2021-23337") {
		t.Fatalf("expected vulnerable repo scan to include PIPE-401 and CVE-2021-23337, got:\n%s", vulnText)
	}

	sbomText := extractToolText(t, lines[6])
	if !strings.Contains(sbomText, `"bomFormat": "CycloneDX"`) || !strings.Contains(sbomText, `"lodash"`) {
		t.Fatalf("expected CycloneDX 1.5 SBOM with lodash, got:\n%s", sbomText)
	}
}

func mustMarshalCall(id int, toolName string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	})
	return string(b)
}

func extractToolText(t *testing.T, rawLine string) string {
	t.Helper()
	var resp struct {
		Result toolCallResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(rawLine), &resp); err != nil {
		t.Fatalf("unmarshal response line: %v", err)
	}
	if resp.Result.IsError || len(resp.Result.Content) == 0 {
		t.Fatalf("unexpected tool error result: %+v", resp.Result)
	}
	return resp.Result.Content[0].Text
}
