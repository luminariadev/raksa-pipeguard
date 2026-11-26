package main

import (
	"bytes"
	"os"
	"os/exec"
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
	if code != exitOK || !strings.Contains(out.String(), `"raksa-pipeguard"`) || !strings.Contains(out.String(), `"0.2.0"`) {
		t.Fatalf("version --json failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// 2. rules
	out.Reset()
	errBuf.Reset()
	code = run([]string{"rules"}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), "Total rules: 29") {
		t.Fatalf("rules failed code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// 3. scan-repo on hardened fixture -> exit 0 and score 100 A+ (including positional before flag)
	out.Reset()
	errBuf.Reset()
	code = run([]string{"scan-repo", hardened, "--fail-on", "low", "--format", "json"}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), `"score": 100`) || !strings.Contains(out.String(), `"grade": "A+"`) {
		t.Fatalf("hardened positional-before-flag scan-repo expected exit 0 / 100 A+ JSON, got code=%d err=%s out=%s", code, errBuf.String(), out.String())
	}

	// Extra unexpected positional arguments must fail cleanly with exit 1.
	out.Reset()
	errBuf.Reset()
	if got := run([]string{"scan-repo", "--path", hardened, "unexpected"}, &out, &errBuf, strings.NewReader("")); got != exitErr {
		t.Fatalf("expected exit 1 for extra positional arg, got %d", got)
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

	// 6. Baseline round-trip, custom org rules (PIPE-501), PIPE-105 licenses, GitLab CI, and --diff-base
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"scan-repo",
		"--path", vuln,
		"--offline-db", filepath.Join(vuln, "offline_osv.json"),
		"--policy", filepath.Join(vuln, "policy_suppress.yml"),
		"--write-baseline", baselinePath,
		"--fail-on", "none",
		"--format", "json",
	}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), "PIPE-105") || !strings.Contains(out.String(), "PIPE-405") {
		t.Fatalf("expected PIPE-105 & PIPE-405 in vulnerable v0.2.0 scan, got code=%d err=%s out=%s", code, errBuf.String(), out.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"scan-repo",
		"--path", vuln,
		"--offline-db", filepath.Join(vuln, "offline_osv.json"),
		"--policy", filepath.Join(vuln, "policy_suppress.yml"),
		"--baseline", baselinePath,
		"--fail-on", "low",
		"--format", "json",
	}, &out, &errBuf, strings.NewReader(""))
	if code != exitOK || !strings.Contains(out.String(), `"total": 0`) {
		t.Fatalf("expected baseline suppression to yield 0 findings exit 0, got code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	// Custom org rule (PIPE-501) + install-hook + diff-base inside temp git repo
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
		if gOut, gErr := cmd.CombinedOutput(); gErr != nil {
			t.Fatalf("git %v failed: %v (%s)", args, gErr, string(gOut))
		}
	}
	runGit("init", "-b", "main")
	runGit("config", "user.name", "luminariadev")
	runGit("config", "user.email", "rizkianuari83@gmail.com")
	if err := os.WriteFile(filepath.Join(repoDir, "legacy.yaml"), []byte("image: docker:1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "legacy.yaml")
	runGit("commit", "-m", "base")

	runGit("checkout", "-b", "pr-check")
	polFile := filepath.Join(repoDir, ".pipeguard.yml")
	if err := os.WriteFile(polFile, []byte("custom_rules:\n  - id: ORG-1\n    title: Legacy registry blocked\n    severity: high\n    pattern: \"registry\\\\.legacy\\\\.internal\"\n    path_glob: \"*.yaml\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "new_deploy.yaml"), []byte("image: registry.legacy.internal/svc:1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".pipeguard.yml", "new_deploy.yaml")
	runGit("commit", "-m", "add custom violation")

	out.Reset()
	errBuf.Reset()
	code = run([]string{"scan-repo", "--path", repoDir, "--diff-base", "main", "--fail-on", "high", "--format", "json"}, &out, &errBuf, strings.NewReader(""))
	if code != exitBreach || !strings.Contains(out.String(), "PIPE-501") {
		t.Fatalf("expected exit 2 PIPE-501 with --diff-base, got code=%d out=%s err=%s", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if got := run([]string{"install-hook", "--path", repoDir, "--fail-on", "medium"}, &out, &errBuf, strings.NewReader("")); got != exitOK {
		t.Fatalf("install-hook failed: code=%d err=%s", got, errBuf.String())
	}
	hookFile := filepath.Join(repoDir, ".git", "hooks", "pre-commit")
	hookRaw, err := os.ReadFile(hookFile)
	if err != nil || !strings.Contains(string(hookRaw), hookMarker) || !strings.Contains(string(hookRaw), "--fail-on medium") {
		t.Fatalf("unexpected pre-commit hook content: err=%v content=%s", err, string(hookRaw))
	}
	out.Reset()
	errBuf.Reset()
	if got := run([]string{"install-hook", "--path", repoDir, "--uninstall"}, &out, &errBuf, strings.NewReader("")); got != exitOK {
		t.Fatalf("install-hook --uninstall failed: code=%d err=%s", got, errBuf.String())
	}
	if _, statErr := os.Stat(hookFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected managed hook file to be removed")
	}

	// 7. Unknown subcommand returns exit 1
	out.Reset()
	errBuf.Reset()
	if got := run([]string{"unknown-cmd"}, &out, &errBuf, strings.NewReader("")); got != exitErr {
		t.Fatalf("expected exit 1 on unknown command, got %d", got)
	}
}
