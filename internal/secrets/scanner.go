package secrets

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const (
	MaxSecretScanBytes = 2 * 1024 * 1024
	DefaultMinEntropy  = 4.2
)

type ScanOptions struct {
	EntropyThreshold float64
	Workers          int
}

type secretPatternRule struct {
	ruleID      string
	kind        string
	severity    schema.Severity
	title       string
	description string
	remediation string
	regex       *regexp.Regexp
	extractIdx  int
}

var (
	secretPatternRules = []secretPatternRule{
		{
			ruleID:      "PIPE-001",
			kind:        "aws-access-key",
			severity:    schema.SeverityCritical,
			title:       "Hardcoded cloud provider access key detected",
			description: "File exposes an AWS Access Key ID literal.",
			remediation: "Revoke the exposed key immediately and migrate workloads to short-lived OIDC/IAM roles.",
			regex:       regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`),
			extractIdx:  1,
		},
		{
			ruleID:      "PIPE-001",
			kind:        "gcp-api-key",
			severity:    schema.SeverityCritical,
			title:       "Hardcoded cloud provider API key detected",
			description: "File exposes a Google Cloud Platform API key literal.",
			remediation: "Revoke and regenerate the API key with strict referrer/IP restrictions via secret management.",
			regex:       regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`),
			extractIdx:  1,
		},
		{
			ruleID:      "PIPE-002",
			kind:        "github-token",
			severity:    schema.SeverityCritical,
			title:       "Hardcoded VCS or registry token detected",
			description: "File contains a GitHub personal access or integration token.",
			remediation: "Revoke the exposed GitHub token in Developer Settings and use short-lived GITHUB_TOKEN or OIDC.",
			regex:       regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b`),
			extractIdx:  1,
		},
		{
			ruleID:      "PIPE-002",
			kind:        "gitlab-or-registry-token",
			severity:    schema.SeverityCritical,
			title:       "Hardcoded VCS or package registry token detected",
			description: "File contains a GitLab PAT, npm access token, or PyPI API token.",
			remediation: "Revoke the package/VCS token immediately and inject CI credentials via encrypted repository secrets.",
			regex:       regexp.MustCompile(`\b(glpat-[0-9A-Za-z_-]{20}|npm_[0-9A-Za-z]{36}|pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{20,})\b`),
			extractIdx:  1,
		},
		{
			ruleID:      "PIPE-003",
			kind:        "private-key-block",
			severity:    schema.SeverityCritical,
			title:       "Private cryptographic key material embedded in repository",
			description: "File embeds a PEM or OpenSSH private key block.",
			remediation: "Remove the private key from source control, purge Git history, and rotate the corresponding certificate/SSH keypair.",
			regex:       regexp.MustCompile(`-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`),
			extractIdx:  0,
		},
		{
			ruleID:      "PIPE-004",
			kind:        "saas-or-jwt-secret",
			severity:    schema.SeverityHigh,
			title:       "Hardcoded SaaS token, Slack token, or signed JWT detected",
			description: "File contains a hardcoded live SaaS credential or signed JWT.",
			remediation: "Rotate the credential at the provider and load runtime tokens from a secret manager.",
			regex:       regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24}|xox[baprs]-[0-9A-Za-z-]{10,}|eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})\b`),
			extractIdx:  1,
		},
		{
			ruleID:      "PIPE-004",
			kind:        "database-uri-password",
			severity:    schema.SeverityHigh,
			title:       "Authenticated database connection URI with embedded password detected",
			description: "Connection string contains a non-placeholder password directly inside the URL.",
			remediation: "Parameterize database credentials via runtime secrets rather than embedding passwords in URIs.",
			regex:       regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/"']+:([^\s@"']+)@[^\s/"']+`),
			extractIdx:  1,
		},
	}

	genericSecretAssignRe = regexp.MustCompile(
		`(?i)\b([a-z0-9_]*(?:api_key|apikey|api_secret|secret_key|access_token|auth_token|private_key|client_secret|db_password|app_secret|signing_key|password)[a-z0-9_]*)\b\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{16,})["']?`,
	)
)

func ScanPath(root string, opts ScanOptions) ([]schema.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat path %q: %w", root, err)
	}

	var files []string
	if !info.IsDir() {
		files = append(files, root)
	} else {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if isSkippedSecretDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if isSkippedSecretFile(d.Name()) {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk secret scan path %q: %w", root, err)
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 16 {
			workers = 16
		}
	}
	if workers > len(files) {
		workers = len(files)
	}

	fileCh := make(chan string, len(files))
	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	var (
		mu       sync.Mutex
		findings []schema.Finding
		wg       sync.WaitGroup
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []schema.Finding
			for path := range fileCh {
				raw, ok := readTextForSecrets(path)
				if !ok {
					continue
				}
				target := "file://" + strings.ReplaceAll(path, `\`, "/")
				local = append(local, ScanContent(raw, target, opts)...)
			}
			if len(local) > 0 {
				mu.Lock()
				findings = append(findings, local...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sortFindingsDeterministic(findings)
	return findings, nil
}

func ScanContent(content string, target string, opts ScanOptions) []schema.Finding {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	threshold := opts.EntropyThreshold
	if threshold <= 0 {
		threshold = DefaultMinEntropy
	}

	now := time.Now().UTC()
	var findings []schema.Finding
	lines := strings.Split(content, "\n")

	for idx, rawLine := range lines {
		lineNo := idx + 1
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Skip regex definitions inside scanner source code.
		if strings.Contains(line, "MustCompile(") {
			continue
		}

		lineMatchedSpecific := false
		for _, rule := range secretPatternRules {
			m := rule.regex.FindStringSubmatch(line)
			if len(m) == 0 {
				continue
			}
			secretVal := m[0]
			if rule.extractIdx > 0 && rule.extractIdx < len(m) {
				secretVal = m[rule.extractIdx]
			}
			if rule.ruleID != "PIPE-003" && IsPlaceholderSecret(secretVal) {
				continue
			}

			lineMatchedSpecific = true
			findings = append(findings, schema.NewFinding(
				rule.ruleID, "secrets", rule.severity,
				rule.title,
				fmt.Sprintf("%s Detected on line %d (value redacted).", rule.description, lineNo),
				target,
				map[string]any{
					"line":           lineNo,
					"pattern_kind":   rule.kind,
					"redacted_match": MaskSecret(secretVal),
					"standard":       "OWASP CI/CD-SEC-6",
				},
				rule.remediation,
				"D3-KM",
				fmt.Sprintf("%s-l%d-%s", filepath.Base(strings.TrimPrefix(target, "file://")), lineNo, rule.kind),
				now,
			))
		}

		if lineMatchedSpecific {
			continue
		}

		if gm := genericSecretAssignRe.FindStringSubmatch(line); len(gm) >= 3 {
			varName := gm[1]
			candidate := gm[2]
			if IsPlaceholderSecret(candidate) || looksLikePureHexDigest(candidate) {
				continue
			}
			ent := ShannonEntropy(candidate)
			if ent >= threshold {
				findings = append(findings, schema.NewFinding(
					"PIPE-005", "secrets", schema.SeverityHigh,
					"High-entropy generic secret assignment detected",
					fmt.Sprintf("Assignment to %q on line %d exceeds Shannon entropy threshold %.2f (observed %.2f; value redacted).", varName, lineNo, threshold, ent),
					target,
					map[string]any{
						"line":           lineNo,
						"variable":       varName,
						"entropy":        fmt.Sprintf("%.2f", ent),
						"redacted_match": MaskSecret(candidate),
						"standard":       "OWASP CI/CD-SEC-6",
					},
					fmt.Sprintf("Move %s to encrypted CI secrets or runtime secret manager and rotate the credential.", varName),
					"D3-KM",
					fmt.Sprintf("%s-l%d-entropy", filepath.Base(strings.TrimPrefix(target, "file://")), lineNo),
					now,
				))
			}
		}
	}

	return findings
}

func readTextForSecrets(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSecretScanBytes || info.Size() == 0 {
		return "", false
	}

	raw, err := io.ReadAll(io.LimitReader(f, MaxSecretScanBytes+1))
	if err != nil || len(raw) > MaxSecretScanBytes {
		return "", false
	}
	sampleLen := len(raw)
	if sampleLen > 512 {
		sampleLen = 512
	}
	if bytes.IndexByte(raw[:sampleLen], 0) >= 0 {
		return "", false
	}
	return string(raw), true
}

func isSkippedSecretDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "target" || name == "dist" || name == "vendor"
}

func isSkippedSecretFile(name string) bool {
	low := strings.ToLower(name)
	switch low {
	case "go.sum", "package-lock.json", "cargo.lock", "yarn.lock", "pnpm-lock.yaml":
		return true
	}
	ext := filepath.Ext(low)
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2":
		return true
	}
	return false
}

func looksLikePureHexDigest(s string) bool {
	if len(s) != 32 && len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func sortFindingsDeterministic(findings []schema.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		li, _ := findings[i].Evidence["line"].(int)
		lj, _ := findings[j].Evidence["line"].(int)
		if li != lj {
			return li < lj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ID < findings[j].ID
	})
}
