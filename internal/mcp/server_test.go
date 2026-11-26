package mcp

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPStdioLifecycleAndTools(t *testing.T) {
	if len(ToolDefinitions()) != 9 {
		t.Fatalf("expected 9 MCP tools, got %d", len(ToolDefinitions()))
	}

	vulnPath := filepath.Join("..", "..", "testdata", "vulnerable")
	hardenedPath := filepath.Join("..", "..", "testdata", "hardened")
	tarPath := writeTestDockerTar(t)

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
		mustMarshalCall(7, "pipeguard_generate_sbom", map[string]any{
			"path":   vulnPath,
			"format": "spdx",
		}),
		mustMarshalCall(8, "pipeguard_scan_ci_workflow", map[string]any{
			"content": "stages: [build]\nimage: docker:latest\nvariables:\n  DOCKER_TLS_CERTDIR: \"\"\nservices:\n  - docker:dind\nbuild:\n  script:\n    - echo ok\n",
			"target":  ".gitlab-ci.yml",
		}),
		mustMarshalCall(9, "pipeguard_scan_image", map[string]any{"path": tarPath}),
		mustMarshalCall(10, "pipeguard_suggest_fix", map[string]any{
			"content": "FROM alpine:latest\nRUN chmod 777 /tmp\n",
			"kind":    "dockerfile",
			"target":  "Dockerfile",
		}),
	}

	var out bytes.Buffer
	if err := ServeStdio(strings.NewReader(strings.Join(requests, "\n")+"\n"), &out); err != nil {
		t.Fatalf("ServeStdio failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// 10 ID-bearing requests (notification emits no response).
	if len(lines) != 10 {
		t.Fatalf("expected 10 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}

	// Verify initialize + tools/list + rules + IaC + hardened + vuln + SPDX + GitLab + scan_image + suggest_fix.
	var listResp struct {
		Result struct {
			Tools []toolDefinition `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("unmarshal tools/list response: %v", err)
	}
	if len(listResp.Result.Tools) != 9 {
		t.Fatalf("expected 9 listed tools, got %d", len(listResp.Result.Tools))
	}

	hardenedText := extractToolText(t, lines[4])
	if !strings.Contains(hardenedText, `"score": 100`) || !strings.Contains(hardenedText, `"grade": "A+"`) {
		t.Fatalf("expected hardened scan to score 100 A+, got:\n%s", hardenedText)
	}

	vulnText := extractToolText(t, lines[5])
	if !strings.Contains(vulnText, "PIPE-401") || !strings.Contains(vulnText, "CVE-2021-23337") || !strings.Contains(vulnText, "PIPE-105") || !strings.Contains(vulnText, "PIPE-405") {
		t.Fatalf("expected vulnerable repo scan to include PIPE-401, PIPE-405, PIPE-105, and CVE-2021-23337, got:\n%s", vulnText)
	}

	sbomText := extractToolText(t, lines[6])
	if !strings.Contains(sbomText, `"spdxVersion": "SPDX-2.3"`) || !strings.Contains(sbomText, `"lodash"`) {
		t.Fatalf("expected SPDX 2.3 SBOM with lodash, got:\n%s", sbomText)
	}

	gitlabText := extractToolText(t, lines[7])
	if !strings.Contains(gitlabText, "PIPE-405") || !strings.Contains(gitlabText, "PIPE-407") {
		t.Fatalf("expected GitLab CI MCP scan to include PIPE-405 and PIPE-407, got:\n%s", gitlabText)
	}

	imageText := extractToolText(t, lines[8])
	if !strings.Contains(imageText, "PIPE-201") || !strings.Contains(imageText, "PIPE-203") || !strings.Contains(imageText, "PIPE-105") || !strings.Contains(imageText, "busybox") {
		t.Fatalf("expected image scan to include PIPE-201, PIPE-203, PIPE-105, and busybox, got:\n%s", imageText)
	}

	fixText := extractToolText(t, lines[9])
	if !strings.Contains(fixText, "USER 10001:10001") || !strings.Contains(fixText, "@@") {
		t.Fatalf("expected suggest_fix unified diff with USER 10001:10001, got:\n%s", fixText)
	}
}

func writeTestDockerTar(t *testing.T) string {
	t.Helper()
	var layerBuf bytes.Buffer
	ltw := tar.NewWriter(&layerBuf)
	apkDB := []byte("P:busybox\nV:1.36.1-r29\nL:GPL-2.0-only\n\n")
	if err := ltw.WriteHeader(&tar.Header{
		Name:     "lib/apk/db/installed",
		Mode:     0o644,
		Size:     int64(len(apkDB)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ltw.Write(apkDB); err != nil {
		t.Fatal(err)
	}
	if err := ltw.Close(); err != nil {
		t.Fatal(err)
	}

	cfgRaw, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"User": "",
			"Env":  []string{"DB_PASSWORD=MySuperSecretLayerPass99"},
		},
	})
	manifestRaw, _ := json.Marshal([]map[string]any{
		{
			"Config":   "config.json",
			"RepoTags": []string{"mcp-test/app:0.3.0"},
			"Layers":   []string{"layer.tar"},
		},
	})

	outPath := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	for name, data := range map[string][]byte{
		"manifest.json": manifestRaw,
		"config.json":   cfgRaw,
		"layer.tar":     layerBuf.Bytes(),
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return outPath
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
