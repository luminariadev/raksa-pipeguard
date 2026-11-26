package secrets

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

func ScanGitStaged(repoDir string, opts ScanOptions) ([]schema.Finding, error) {
	out, err := runGitDiff(repoDir, []string{"diff", "--cached", "-U0", "--no-color"})
	if err != nil {
		return nil, err
	}
	return scanUnifiedDiffOutput(out, "staged", opts), nil
}

func ScanGitHistory(repoDir string, maxCommits int, opts ScanOptions) ([]schema.Finding, error) {
	if maxCommits <= 0 {
		maxCommits = 50
	}
	args := []string{
		"log",
		fmt.Sprintf("-n%d", maxCommits),
		"-p",
		"-U0",
		"--no-color",
		"--format=RAKSA_COMMIT:%H",
	}
	out, err := runGitDiff(repoDir, args)
	if err != nil {
		return nil, err
	}
	return scanUnifiedDiffOutput(out, "history", opts), nil
}

func runGitDiff(repoDir string, gitArgs []string) (string, error) {
	fullArgs := append([]string{"-C", repoDir}, gitArgs...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(raw))
		if strings.Contains(msg, "does not have any commits yet") {
			return "", nil
		}
		return "", fmt.Errorf("git %s failed: %w (%s)", gitArgs[0], err, msg)
	}
	return string(raw), nil
}

func scanUnifiedDiffOutput(diffText string, gitScope string, opts ScanOptions) []schema.Finding {
	if strings.TrimSpace(diffText) == "" {
		return nil
	}

	var (
		findings   []schema.Finding
		curCommit  string
		curFile    string
		curNewLine int
	)

	lines := strings.Split(diffText, "\n")
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")

		if strings.HasPrefix(line, "RAKSA_COMMIT:") {
			curCommit = strings.TrimSpace(strings.TrimPrefix(line, "RAKSA_COMMIT:"))
			curFile = ""
			curNewLine = 0
			continue
		}
		if strings.HasPrefix(line, "+++ b/") {
			curFile = strings.TrimSpace(strings.TrimPrefix(line, "+++ b/"))
			continue
		}
		if strings.HasPrefix(line, "+++ /dev/null") {
			curFile = ""
			continue
		}
		if strings.HasPrefix(line, "@@ ") {
			curNewLine = parseHunkNewStart(line)
			continue
		}
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		if curFile == "" || isSkippedSecretFile(curFile) {
			curNewLine++
			continue
		}

		added := line[1:]
		target := "git://" + curFile
		if curCommit != "" && len(curCommit) >= 8 {
			target = fmt.Sprintf("git://%s@%s", curFile, curCommit[:8])
		}

		hits := ScanContent(added, target, opts)
		for _, h := range hits {
			h.RuleID = "PIPE-006"
			if h.Evidence == nil {
				h.Evidence = make(map[string]any)
			}
			h.Evidence["line"] = curNewLine
			h.Evidence["git_scope"] = gitScope
			if curCommit != "" {
				h.Evidence["commit"] = curCommit
			}
			h.Title = fmt.Sprintf("Secret exposed in Git %s diff", gitScope)
			h.Remediation = "Unstage or purge the secret from Git history (git filter-repo) and rotate the exposed credential immediately."
			if curCommit != "" && len(curCommit) >= 8 {
				h.ID = fmt.Sprintf("pipe-006-%s-%s-l%d", gitScope, curCommit[:8], curNewLine)
			} else {
				h.ID = fmt.Sprintf("pipe-006-%s-%s-l%d", gitScope, schema.SanitizeIDPart(curFile), curNewLine)
			}
			findings = append(findings, h)
		}
		curNewLine++
	}

	sortFindingsDeterministic(findings)
	return findings
}

func parseHunkNewStart(header string) int {
	plusIdx := strings.IndexByte(header, '+')
	if plusIdx < 0 {
		return 1
	}
	rest := header[plusIdx+1:]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == ',' || rest[i] == ' ' {
			end = i
			break
		}
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n <= 0 {
		return 1
	}
	return n
}
