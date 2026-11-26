package secrets

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanContentDetectsRedactsAndAvoidsPlaceholders(t *testing.T) {
	awsSynthetic := "AKIA" + "9X7M4K2P8Q1R3T5V"
	ghSynthetic := "ghp" + "_" + strings.Repeat("Ab39Zx", 6)
	dbPassword := "Pr0d$DbPass!89XyZ"
	genericSecret := "k8F9pQ" + "3mX7vL" + "2wZ8nB" + "5rT4yJ" + "6hN1cM"

	doc := strings.Join([]string{
		"AWS_ACCESS_KEY_ID=" + awsSynthetic,
		"GITHUB_PAT=" + ghSynthetic,
		"DATABASE_URL=postgresql://appuser:" + dbPassword + "@pg.prod.internal:5432/orders",
		"API_SECRET=" + genericSecret,
		"SAFE_EXAMPLE=AKIA" + "IOSFODNN7EXAMPLE",
		"SAFE_ENV=${DATABASE_PASSWORD}",
		"DIGEST=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}, "\n")

	findings := ScanContent(doc, "file://.env.sample", ScanOptions{})
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings (placeholders and hex digest skipped), got %d: %+v", len(findings), findings)
	}

	rawJSON, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(rawJSON)
	for _, secret := range []string{awsSynthetic, ghSynthetic, dbPassword, genericSecret} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("raw secret %q leaked into serialized finding JSON!", secret)
		}
	}
}

func TestScanGitStagedAndHistory(t *testing.T) {
	dir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v (%s)", args, err, string(out))
		}
	}

	runGit("init", "-b", "main")
	runGit("config", "user.name", "luminariadev")
	runGit("config", "user.email", "rizkianuari83@gmail.com")

	cfgFile := filepath.Join(dir, "config.env")
	histSecret := "npm_" + strings.Repeat("Z7qK9m", 6)
	if err := os.WriteFile(cfgFile, []byte("NPM_TOKEN="+histSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "config.env")
	runGit("commit", "-m", "initial")

	histFindings, err := ScanGitHistory(dir, 10, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitHistory failed: %v", err)
	}
	if len(histFindings) != 1 || histFindings[0].RuleID != "PIPE-006" {
		t.Fatalf("expected 1 PIPE-006 git history finding, got %+v", histFindings)
	}
	histJSON, _ := json.Marshal(histFindings)
	if strings.Contains(string(histJSON), histSecret) {
		t.Fatalf("git history raw secret leaked into findings")
	}

	stagedSecret := "AIza" + "SyA9Kp2Lm4Nq6Rs8Tu0Vw2Xy4Za6Bc8De0F"
	if err := os.WriteFile(cfgFile, []byte("SAFE=1\nGCP_KEY="+stagedSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "config.env")

	stagedFindings, err := ScanGitStaged(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitStaged failed: %v", err)
	}
	if len(stagedFindings) != 1 || stagedFindings[0].RuleID != "PIPE-006" {
		t.Fatalf("expected 1 PIPE-006 staged finding, got %+v", stagedFindings)
	}
}

func TestExpandedKeywordsProvidersAndDiffBase(t *testing.T) {
	doToken := "dop_" + "v1_" + strings.Repeat("a1b2c3d4", 8)
	hfToken := "hf_" + strings.Repeat("Xy92Km31Pq48", 2)
	sgToken := "SG." + strings.Repeat("A9bC3dEf4g", 2) + "." + strings.Repeat("H8jK2mNp5q", 2)
	svcToken := "m9X2pQ" + "7wK4nL" + "8vR5tY" + "3bJ6fD" + "1hS8cW"
	jwtSecret := "r7T3wN" + "9kM5pQ" + "2xL8vB" + "4yF6hC" + "0zD1nG"

	doc := strings.Join([]string{
		"DO_PAT=" + doToken,
		"HF_TOKEN=" + hfToken,
		"SENDGRID_API_KEY=" + sgToken,
		"SERVICE_TOKEN=" + svcToken,
		"JWT_SECRET=" + jwtSecret,
	}, "\n")

	findings := ScanContent(doc, "file://.env.expanded", ScanOptions{})
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings from expanded rules and keywords, got %d: %+v", len(findings), findings)
	}

	dir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v (%s)", args, err, string(out))
		}
	}
	runGit("init", "-b", "main")
	runGit("config", "user.name", "luminariadev")
	runGit("config", "user.email", "rizkianuari83@gmail.com")
	if err := os.WriteFile(filepath.Join(dir, "base.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "base.txt")
	runGit("commit", "-m", "base commit")

	runGit("checkout", "-b", "feature/pr")
	if err := os.WriteFile(filepath.Join(dir, "service.env"), []byte("SERVICE_TOKEN="+svcToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "service.env")
	runGit("commit", "-m", "pr commit")

	changed, err := ChangedFilesSince(dir, "main")
	if err != nil {
		t.Fatalf("ChangedFilesSince failed: %v", err)
	}
	if _, ok := changed["service.env"]; !ok {
		t.Fatalf("expected service.env in changed files, got %v", changed)
	}

	diffHits, err := ScanGitDiffBase(dir, "main", ScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitDiffBase failed: %v", err)
	}
	if len(diffHits) != 1 || diffHits[0].RuleID != "PIPE-006" {
		t.Fatalf("expected 1 PIPE-006 diff-base finding, got %+v", diffHits)
	}
}
