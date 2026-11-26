package ciworkflow

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitHubActionsHardenedVsInsecure(t *testing.T) {
	hardened := `
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - uses: some-vendor/security-tool@0123456789abcdef0123456789abcdef01234567
      - name: Safely inspect PR title via env
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          printf '%s\n' "$PR_TITLE"
`
	cleanFindings, err := ScanContent(hardened, ".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("ScanContent hardened failed: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Fatalf("expected 0 findings on hardened workflow, got %d: %+v", len(cleanFindings), cleanFindings)
	}

	insecure := `
name: Vulnerable PR Gate
on:
  pull_request_target:
    types: [opened, synchronize]

permissions: write-all

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: thirdparty/linter-action@v2
      - name: Unsafe shell echo
        run: echo "Title is ${{ github.event.pull_request.title }}"
`
	badFindings, err := ScanContent(insecure, ".github/workflows/pr.yml")
	if err != nil {
		t.Fatalf("ScanContent insecure failed: %v", err)
	}
	seen := make(map[string]bool)
	for _, f := range badFindings {
		seen[f.RuleID] = true
	}
	for _, expected := range []string{"PIPE-401", "PIPE-402", "PIPE-403", "PIPE-404"} {
		if !seen[expected] {
			t.Fatalf("expected rule %s in insecure workflow findings, got %v", expected, seen)
		}
	}

	// Missing top-level permissions should also trigger PIPE-403.
	missingPerms := `
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo ok
`
	missingFindings, err := ScanContent(missingPerms, ".github/workflows/no-perms.yml")
	if err != nil {
		t.Fatalf("ScanContent missingPerms failed: %v", err)
	}
	if len(missingFindings) != 1 || missingFindings[0].RuleID != "PIPE-403" {
		t.Fatalf("expected single PIPE-403 finding for omitted permissions, got %+v", missingFindings)
	}
}

func TestScanPathDiscoversWorkflowsOnly(t *testing.T) {
	tmp := t.TempDir()
	wfDir := filepath.Join(tmp, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatalf("write unrelated yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "build.yml"), []byte("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := ScanPath(tmp)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "PIPE-403" {
		t.Fatalf("expected 1 PIPE-403 finding from .github/workflows/build.yml, got %+v", findings)
	}
}
