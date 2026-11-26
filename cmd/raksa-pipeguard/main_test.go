package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLISubcommandsHardenedAndVulnerableFixtures(t *testing.T) {
	hardened := filepath.Join("..", "..", "testdata", "hardened")
	vuln := filepath.Join("..", "..", "testdata", "vulnerable")

	// 1. version --json
	var out, errBuf bytes.Buffer
	code := run([]string{"version", "--json"}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), `"raksa-pipeguard"`) {
		t.Fatalf("version --json failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// 2. rules
	out.Reset()
	errBuf.Reset()
	code = run([]string{"rules"}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), "Total rules: 24") {
		t.Fatalf("rules failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// 3. scan-repo on hardened fixture -> exit 0 and score 100 A+
	out.Reset()
	errBuf.Reset()
	code = run([]string{"scan-repo", "--path", hardened, "--fail-on", "low", "--format", "json"}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), `"score": 100`) || !strings.Contains(out.String(), `"grade": "A+"`) {
		t.Fatalf("hardened scan-repo expected exit 0 / 100 A+, got code=%d err=%s out=%s", code, errBuf.String(), out.String())
	}

	// 4. scan-repo on vulnerable fixture -> exit 2 + writes valid SARIF file
	sarifOut := filepath.Join(t.TempDir(), "out.sarif")
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"scan-repo",
		"--path", vuln,
		"--offline-db", filepath.Join(vuln, "offline_osv.json"),
		"--policy", filepath.Join(vuln, "policy_suppress.yml"),
		"--format", "sarif",
		"--output", sarifOut,
	}, &out, &errBuf, strings.NewReader(""))
	if code != exitBreach {
		t.Fatalf("vulnerable scan-repo expected exit 2, got code=%d err=%s", code, errBuf.String())
	}
	sarifBytes, err := os.ReadFile(sarifOut)
	if err != nil || !strings.Contains(string(sarifBytes), `"version": "2.1.0"`) || !strings.Contains(string(sarifBytes), "PIPE-401") {
		t.Fatalf("expected valid SARIF output, err=%v content=%s", err, string(sarifBytes))
	}
	// Suppressed PIPE-206 should be excluded by policy_suppress.yml.
	if strings.Contains(string(sarifBytes), `"PIPE-206"`) {
		t.Fatalf("expected PIPE-206 to be suppressed by policy_suppress.yml")
	}

	// 5. scan-secrets, scan-deps, scan-iac, scan-ci individual gates on vulnerable fixture
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"scan-secrets", "--path", vuln, "--fail-on", "medium"}, exitBreach},
		{[]string{"scan-deps", "--path", vuln, "--offline-db", filepath.Join(vuln, "offline_osv.json")}, exitBreach},
		{[]string{"scan-iac", "--path", vuln}, exitBreach},
		{[]string{"scan-ci", "--path", vuln}, exitBreach},
		{[]string{"sbom", "--path", vuln}, exitOK},
	} {
		out.Reset()
		errBuf.Reset()
		got := run(tc.args, &out, &errBuf, strings.NewReader(""))
		if got != tc.code {
			t.Fatalf("command %v expected exit %d, got %d (stderr: %s)", tc.args, tc.code, got, errBuf.String())
		}
	}

	// 6. Unknown subcommand returns exit 1
	out.Reset()
	errBuf.Reset()
	if got := run([]string{"unknown-cmd"}, &out, &errBuf, strings.NewReader("")); got != exitErr {
		t.Fatalf("expected exit 1 on unknown command, got %d", got)
	}
}
