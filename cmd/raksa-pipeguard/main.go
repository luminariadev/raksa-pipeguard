package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/ciworkflow"
	"github.com/luminariadev/raksa-pipeguard/internal/deps"
	"github.com/luminariadev/raksa-pipeguard/internal/iac"
	"github.com/luminariadev/raksa-pipeguard/internal/mcp"
	"github.com/luminariadev/raksa-pipeguard/internal/policy"
	"github.com/luminariadev/raksa-pipeguard/internal/report"
	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"github.com/luminariadev/raksa-pipeguard/internal/secrets"
)

const (
	exitOK     = 0
	exitErr    = 1
	exitBreach = 2
	hookMarker = "# raksa-pipeguard managed hook"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout)
		return exitOK
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "scan-secrets":
		return runScanSecrets(rest, stdout, stderr)
	case "scan-deps":
		return runScanDeps(rest, stdout, stderr)
	case "sbom":
		return runSBOM(rest, stdout, stderr)
	case "scan-iac":
		return runScanIaC(rest, stdout, stderr)
	case "scan-ci":
		return runScanCI(rest, stdout, stderr)
	case "scan-repo":
		return runScanRepo(rest, stdout, stderr)
	case "install-hook":
		return runInstallHook(rest, stdout, stderr)
	case "rules":
		return runRules(rest, stdout, stderr)
	case "mcp":
		if err := mcp.ServeStdio(stdin, stdout); err != nil {
			fmt.Fprintf(stderr, "mcp error: %v\n", err)
			return exitErr
		}
		return exitOK
	case "version":
		return runVersion(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown subcommand: %s\n", cmd)
		printUsage(stderr)
		return exitErr
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `%s v%s - DevSecOps & CI/CD Security Gate (Layer 4)

Usage:
  raksa-pipeguard <subcommand> [flags]

Subcommands:
  scan-secrets   Scan workspace files, staged changes, PR diff, or git history for secrets
  scan-deps      Audit lockfiles, dependency licenses, and OSV advisories (cached/offline)
  sbom           Generate CycloneDX 1.5 JSON SBOM across Go, Node, Rust, Python, PHP, Maven
  scan-iac       Lint Dockerfiles, Kubernetes YAML manifests, and Terraform HCL files
  scan-ci        Audit GitHub Actions workflows and GitLab CI (.gitlab-ci.yml) pipelines
  scan-repo      Run all Layer 4 checks, custom rules, baseline diffing, and posture scoring
  install-hook   Install or remove a managed Git pre-commit staged secret-scanning hook
  rules          List built-in PIPE-* security rules and MITRE D3FEND mappings
  mcp            Start newline-delimited JSON-RPC 2.0 MCP server over stdio (7 tools)
  version        Print build version metadata

Common scan flags:
  --path <dir|file>       Target path to scan (default ".")
  --format <fmt>          Output format: table, json, sarif (default "table")
  --fail-on <sev>         Minimum severity for exit code 2: critical, high, medium, low, info, none (default "high")
  --policy <file>         Path to .pipeguard.yml waiver & custom rule policy (auto-discovers <path>/.pipeguard.yml)
  --baseline <file>       Suppress known fingerprints recorded in a baseline JSON file
  --write-baseline <file> Write post-policy findings as a baseline JSON snapshot
  --diff-base <git-ref>   Restrict findings to files changed since <git-ref> plus PR diff secrets
  --output <file>         Write output to file instead of stdout
`, schema.ToolName, schema.Version)
}

type commonScanFlags struct {
	path          string
	format        string
	failOn        string
	policy        string
	baseline      string
	writeBaseline string
	diffBase      string
	output        string
	outFormat     report.OutputFormat
	threshold     schema.Severity
}

func bindCommonFlags(fs *flag.FlagSet, c *commonScanFlags) {
	fs.StringVar(&c.path, "path", ".", "target path to inspect")
	fs.StringVar(&c.format, "format", "table", "output format: table, json, sarif")
	fs.StringVar(&c.failOn, "fail-on", "high", "exit code 2 threshold: critical, high, medium, low, info, none")
	fs.StringVar(&c.policy, "policy", "", "path to .pipeguard.yml waiver and custom rules file")
	fs.StringVar(&c.baseline, "baseline", "", "suppress known findings from baseline JSON")
	fs.StringVar(&c.writeBaseline, "write-baseline", "", "save current findings snapshot to baseline JSON")
	fs.StringVar(&c.diffBase, "diff-base", "", "scope scan to files changed relative to git ref")
	fs.StringVar(&c.output, "output", "", "write output report to file path")
}

type boolFlagger interface {
	IsBoolFlag() bool
}

// reorderArgs places flags ahead of positional arguments so both `cmd path --flag val` and `cmd --flag val path` parse consistently.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			name := strings.TrimLeft(arg, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				flags = append(flags, arg)
				continue
			}
			f := fs.Lookup(name)
			isBool := false
			if f != nil {
				if bf, ok := f.Value.(boolFlagger); ok && bf.IsBoolFlag() {
					isBool = true
				}
			}
			flags = append(flags, arg)
			if f != nil && !isBool && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}

func parseFlagsWithHelp(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (int, bool) {
	fs.SetOutput(stderr)
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return exitOK, false
		}
		return exitErr, false
	}
	return exitOK, true
}

func validateCommonFlags(fs *flag.FlagSet, c *commonScanFlags) error {
	pathExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "path" {
			pathExplicit = true
		}
	})

	if fs.NArg() > 1 || (pathExplicit && fs.NArg() > 0) {
		return fmt.Errorf("unexpected extra positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if !pathExplicit && fs.NArg() == 1 {
		c.path = fs.Arg(0)
	}

	outFmt, err := report.ParseFormat(c.format)
	if err != nil {
		return err
	}
	c.outFormat = outFmt

	if strings.EqualFold(strings.TrimSpace(c.failOn), "none") {
		c.threshold = ""
	} else {
		sev, err := schema.ParseSeverity(c.failOn)
		if err != nil {
			return fmt.Errorf("invalid --fail-on value: %w", err)
		}
		c.threshold = sev
	}
	return nil
}

func finalizeScan(findings []schema.Finding, pol *policy.Policy, c commonScanFlags, stdout, stderr io.Writer) int {
	if pol == nil {
		loaded, err := policy.LoadOptionalPolicy(c.path, c.policy)
		if err != nil {
			fmt.Fprintf(stderr, "policy error: %v\n", err)
			return exitErr
		}
		pol = loaded
	}

	if strings.TrimSpace(c.diffBase) != "" {
		changed, err := secrets.ChangedFilesSince(c.path, c.diffBase)
		if err != nil {
			fmt.Fprintf(stderr, "diff-base error: %v\n", err)
			return exitErr
		}
		findings = policy.FilterFindingsByChangedFiles(c.path, findings, changed)
	}

	filtered, _ := policy.ApplyPolicy(findings, pol, time.Now().UTC())

	if strings.TrimSpace(c.baseline) != "" {
		baseSet, err := policy.LoadBaseline(c.baseline)
		if err != nil {
			fmt.Fprintf(stderr, "baseline error: %v\n", err)
			return exitErr
		}
		filtered, _ = policy.FilterBaseline(filtered, baseSet)
	}

	if strings.TrimSpace(c.writeBaseline) != "" {
		if err := policy.WriteBaseline(c.writeBaseline, filtered); err != nil {
			fmt.Fprintf(stderr, "write-baseline error: %v\n", err)
			return exitErr
		}
	}

	rep := schema.NewReport(filtered, time.Now().UTC())

	if strings.TrimSpace(c.output) != "" {
		if dir := filepath.Dir(c.output); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(stderr, "create output directory error: %v\n", err)
				return exitErr
			}
		}
		f, err := os.Create(c.output)
		if err != nil {
			fmt.Fprintf(stderr, "create output file error: %v\n", err)
			return exitErr
		}
		writeErr := report.WriteReport(f, rep, c.outFormat)
		closeErr := f.Close()
		if writeErr != nil {
			fmt.Fprintf(stderr, "write report error: %v\n", writeErr)
			return exitErr
		}
		if closeErr != nil {
			fmt.Fprintf(stderr, "close output file error: %v\n", closeErr)
			return exitErr
		}
	} else {
		if err := report.WriteReport(stdout, rep, c.outFormat); err != nil {
			fmt.Fprintf(stderr, "write report error: %v\n", err)
			return exitErr
		}
	}

	if rep.HasThresholdBreach(c.threshold) {
		return exitBreach
	}
	return exitOK
}

func runScanSecrets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan-secrets", flag.ContinueOnError)
	var c commonScanFlags
	var entropy float64
	var workers int
	var staged bool
	var gitHistory int

	bindCommonFlags(fs, &c)
	fs.Float64Var(&entropy, "entropy", secrets.DefaultMinEntropy, "Shannon entropy threshold")
	fs.IntVar(&workers, "workers", 0, "parallel worker count (default runtime.NumCPU)")
	fs.BoolVar(&staged, "staged", false, "also scan staged git changes")
	fs.IntVar(&gitHistory, "git-history", 0, "scan last N git commits for leaked secrets")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if err := validateCommonFlags(fs, &c); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitErr
	}

	opts := secrets.ScanOptions{EntropyThreshold: entropy, Workers: workers}
	findings, err := secrets.ScanPath(c.path, opts)
	if err != nil {
		fmt.Fprintf(stderr, "scan-secrets error: %v\n", err)
		return exitErr
	}
	if staged {
		stagedHits, err := secrets.ScanGitStaged(c.path, opts)
		if err != nil {
			fmt.Fprintf(stderr, "scan-secrets staged error: %v\n", err)
			return exitErr
		}
		findings = append(findings, stagedHits...)
	}
	if strings.TrimSpace(c.diffBase) != "" {
		diffHits, err := secrets.ScanGitDiffBase(c.path, c.diffBase, opts)
		if err != nil {
			fmt.Fprintf(stderr, "scan-secrets diff-base error: %v\n", err)
			return exitErr
		}
		findings = append(findings, diffHits...)
	}
	if gitHistory > 0 {
		histHits, err := secrets.ScanGitHistory(c.path, gitHistory, opts)
		if err != nil {
			fmt.Fprintf(stderr, "scan-secrets history error: %v\n", err)
			return exitErr
		}
		findings = append(findings, histHits...)
	}
	return finalizeScan(findings, nil, c, stdout, stderr)
}

func runScanDeps(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan-deps", flag.ContinueOnError)
	var c commonScanFlags
	var offlineDB string
	var online bool
	var osvURL string
	var timeoutSec int
	var noCache bool
	var cacheDir string

	bindCommonFlags(fs, &c)
	fs.StringVar(&offlineDB, "offline-db", "", "path to offline OSV advisory JSON file")
	fs.BoolVar(&online, "online", false, "query live api.osv.dev batch endpoint")
	fs.StringVar(&osvURL, "osv-url", deps.DefaultOSVBaseURL, "OSV API base URL")
	fs.IntVar(&timeoutSec, "timeout", 15, "OSV HTTP timeout in seconds")
	fs.BoolVar(&noCache, "no-cache", false, "disable local OSV disk response cache")
	fs.StringVar(&cacheDir, "cache-dir", "", "override OSV advisory disk cache directory")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if err := validateCommonFlags(fs, &c); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitErr
	}

	pol, err := policy.LoadOptionalPolicy(c.path, c.policy)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return exitErr
	}

	comps, findings, err := deps.InventoryFromPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-deps inventory error: %v\n", err)
		return exitErr
	}

	var denied []string
	if pol != nil {
		denied = pol.DeniedLicenses
	}
	findings = append(findings, deps.AuditLicenses(comps, denied)...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+10)*time.Second)
	defer cancel()

	vulnFindings, err := deps.AuditDependencies(ctx, comps, deps.OSVOptions{
		Online:        online,
		BaseURL:       osvURL,
		Timeout:       time.Duration(timeoutSec) * time.Second,
		OfflineDBPath: offlineDB,
		CacheDir:      cacheDir,
		NoCache:       noCache,
	})
	if err != nil {
		fmt.Fprintf(stderr, "scan-deps OSV error: %v\n", err)
		return exitErr
	}
	findings = append(findings, vulnFindings...)
	return finalizeScan(findings, pol, c, stdout, stderr)
}

func runSBOM(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	var targetPath, outPath string
	fs.StringVar(&targetPath, "path", ".", "project root directory")
	fs.StringVar(&outPath, "output", "", "write CycloneDX 1.5 JSON to file")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	pathExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "path" {
			pathExplicit = true
		}
	})
	if fs.NArg() > 1 || (pathExplicit && fs.NArg() > 0) {
		fmt.Fprintf(stderr, "unexpected extra positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitErr
	}
	if !pathExplicit && fs.NArg() == 1 {
		targetPath = fs.Arg(0)
	}

	comps, _, err := deps.InventoryFromPath(targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "sbom inventory error: %v\n", err)
		return exitErr
	}
	sbomJSON, err := deps.GenerateCycloneDX(targetPath, comps)
	if err != nil {
		fmt.Fprintf(stderr, "sbom generation error: %v\n", err)
		return exitErr
	}
	if strings.TrimSpace(outPath) != "" {
		if dir := filepath.Dir(outPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(stderr, "create sbom dir error: %v\n", err)
				return exitErr
			}
		}
		if err := os.WriteFile(outPath, []byte(sbomJSON+"\n"), 0o644); err != nil {
			fmt.Fprintf(stderr, "write sbom file error: %v\n", err)
			return exitErr
		}
		return exitOK
	}
	fmt.Fprintln(stdout, sbomJSON)
	return exitOK
}

func runScanIaC(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan-iac", flag.ContinueOnError)
	var c commonScanFlags
	bindCommonFlags(fs, &c)

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if err := validateCommonFlags(fs, &c); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitErr
	}

	findings, err := iac.ScanPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-iac error: %v\n", err)
		return exitErr
	}
	return finalizeScan(findings, nil, c, stdout, stderr)
}

func runScanCI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan-ci", flag.ContinueOnError)
	var c commonScanFlags
	bindCommonFlags(fs, &c)

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if err := validateCommonFlags(fs, &c); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitErr
	}

	findings, err := ciworkflow.ScanPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-ci error: %v\n", err)
		return exitErr
	}
	return finalizeScan(findings, nil, c, stdout, stderr)
}

func runScanRepo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan-repo", flag.ContinueOnError)
	var c commonScanFlags
	var offlineDB string
	var online bool
	var osvURL string
	var entropy float64
	var gitHistory int
	var noCache bool
	var cacheDir string

	bindCommonFlags(fs, &c)
	fs.StringVar(&offlineDB, "offline-db", "", "path to offline OSV advisory JSON file")
	fs.BoolVar(&online, "online", false, "query live api.osv.dev batch endpoint")
	fs.StringVar(&osvURL, "osv-url", deps.DefaultOSVBaseURL, "OSV API base URL")
	fs.Float64Var(&entropy, "entropy", secrets.DefaultMinEntropy, "Shannon entropy threshold")
	fs.IntVar(&gitHistory, "git-history", 0, "scan last N git commits for leaked history secrets")
	fs.BoolVar(&noCache, "no-cache", false, "disable local OSV disk response cache")
	fs.StringVar(&cacheDir, "cache-dir", "", "override OSV advisory disk cache directory")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if err := validateCommonFlags(fs, &c); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitErr
	}

	pol, err := policy.LoadOptionalPolicy(c.path, c.policy)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return exitErr
	}

	var allFindings []schema.Finding
	secOpts := secrets.ScanOptions{EntropyThreshold: entropy}
	secFindings, err := secrets.ScanPath(c.path, secOpts)
	if err != nil {
		fmt.Fprintf(stderr, "scan-repo secrets error: %v\n", err)
		return exitErr
	}
	allFindings = append(allFindings, secFindings...)

	if strings.TrimSpace(c.diffBase) != "" {
		diffHits, err := secrets.ScanGitDiffBase(c.path, c.diffBase, secOpts)
		if err != nil {
			fmt.Fprintf(stderr, "scan-repo diff-base error: %v\n", err)
			return exitErr
		}
		allFindings = append(allFindings, diffHits...)
	}

	if gitHistory > 0 {
		histHits, err := secrets.ScanGitHistory(c.path, gitHistory, secOpts)
		if err != nil {
			fmt.Fprintf(stderr, "scan-repo git history error: %v\n", err)
			return exitErr
		}
		allFindings = append(allFindings, histHits...)
	}

	comps, invFindings, err := deps.InventoryFromPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-repo deps error: %v\n", err)
		return exitErr
	}
	allFindings = append(allFindings, invFindings...)

	var denied []string
	if pol != nil {
		denied = pol.DeniedLicenses
	}
	allFindings = append(allFindings, deps.AuditLicenses(comps, denied)...)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	vulnFindings, err := deps.AuditDependencies(ctx, comps, deps.OSVOptions{
		Online:        online,
		BaseURL:       osvURL,
		Timeout:       15 * time.Second,
		OfflineDBPath: offlineDB,
		CacheDir:      cacheDir,
		NoCache:       noCache,
	})
	if err != nil {
		fmt.Fprintf(stderr, "scan-repo OSV error: %v\n", err)
		return exitErr
	}
	allFindings = append(allFindings, vulnFindings...)

	iacFindings, err := iac.ScanPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-repo iac error: %v\n", err)
		return exitErr
	}
	allFindings = append(allFindings, iacFindings...)

	ciFindings, err := ciworkflow.ScanPath(c.path)
	if err != nil {
		fmt.Fprintf(stderr, "scan-repo ci error: %v\n", err)
		return exitErr
	}
	allFindings = append(allFindings, ciFindings...)

	if pol != nil && len(pol.CustomRules) > 0 {
		customHits, err := policy.EvaluateCustomRules(c.path, pol)
		if err != nil {
			fmt.Fprintf(stderr, "scan-repo custom rules error: %v\n", err)
			return exitErr
		}
		allFindings = append(allFindings, customHits...)
	}

	return finalizeScan(allFindings, pol, c, stdout, stderr)
}

func runInstallHook(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	var repoPath, failOn string
	var force, uninstall bool
	fs.StringVar(&repoPath, "path", ".", "git repository path")
	fs.StringVar(&failOn, "fail-on", "high", "pre-commit fail-on severity threshold")
	fs.BoolVar(&force, "force", false, "overwrite an existing unmanaged pre-commit hook")
	fs.BoolVar(&uninstall, "uninstall", false, "remove a raksa-pipeguard managed pre-commit hook")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() == 1 {
		repoPath = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintf(stderr, "unexpected extra positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return exitErr
	}

	sev, err := schema.ParseSeverity(failOn)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --fail-on value: %v\n", err)
		return exitErr
	}

	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--git-path", "hooks")
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(stderr, "install-hook failed to locate git hooks directory in %q: %v (%s)\n", repoPath, err, strings.TrimSpace(string(out)))
		return exitErr
	}
	hooksDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(repoPath, hooksDir)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")

	existing, readErr := os.ReadFile(hookPath)
	exists := readErr == nil

	if uninstall {
		if !exists {
			fmt.Fprintf(stdout, "No pre-commit hook found at %s\n", hookPath)
			return exitOK
		}
		if !strings.Contains(string(existing), hookMarker) {
			fmt.Fprintf(stderr, "refusing to remove %s: hook is not managed by raksa-pipeguard\n", hookPath)
			return exitErr
		}
		if err := os.Remove(hookPath); err != nil {
			fmt.Fprintf(stderr, "remove pre-commit hook error: %v\n", err)
			return exitErr
		}
		fmt.Fprintf(stdout, "Removed managed pre-commit hook: %s\n", hookPath)
		return exitOK
	}

	if exists && !force && !strings.Contains(string(existing), hookMarker) {
		fmt.Fprintf(stderr, "pre-commit hook already exists at %s; pass --force to overwrite\n", hookPath)
		return exitErr
	}

	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "create hooks dir error: %v\n", err)
		return exitErr
	}

	script := fmt.Sprintf(`#!/usr/bin/env sh
%s
set -eu
if command -v raksa-pipeguard >/dev/null 2>&1; then
  exec raksa-pipeguard scan-secrets --path . --staged --fail-on %s --format table
fi
echo "raksa-pipeguard not found in PATH; install binary or uninstall via 'raksa-pipeguard install-hook --uninstall'" >&2
exit 1
`, hookMarker, string(sev))

	if err := os.WriteFile(hookPath, []byte(script), 0o755); err != nil {
		fmt.Fprintf(stderr, "write pre-commit hook error: %v\n", err)
		return exitErr
	}
	fmt.Fprintf(stdout, "Installed pre-commit secret-scanning hook at %s (fail-on: %s)\n", hookPath, string(sev))
	return exitOK
}

func runRules(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	var formatStr, moduleFilter string
	fs.StringVar(&formatStr, "format", "table", "output format: table or json")
	fs.StringVar(&moduleFilter, "module", "", "optional module filter: secrets, deps, iac, ci, policy")

	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}

	catalog := schema.RuleCatalog()
	var filtered []schema.RuleInfo
	for _, r := range catalog {
		if moduleFilter == "" || strings.EqualFold(r.Module, moduleFilter) {
			filtered = append(filtered, r)
		}
	}

	switch strings.ToLower(strings.TrimSpace(formatStr)) {
	case "json":
		raw, err := json.MarshalIndent(map[string]any{
			"schema_version": schema.SchemaVersion,
			"tool":           schema.ToolName,
			"total":          len(filtered),
			"rules":          filtered,
		}, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "marshal rules error: %v\n", err)
			return exitErr
		}
		fmt.Fprintln(stdout, string(raw))
		return exitOK
	case "table":
		fmt.Fprintf(stdout, "%-9s %-8s %-9s %-10s %s\n", "RULE ID", "MODULE", "SEVERITY", "D3FEND", "TITLE")
		fmt.Fprintf(stdout, "%-9s %-8s %-9s %-10s %s\n", "-------", "------", "--------", "------", "-----")
		for _, r := range filtered {
			fmt.Fprintf(stdout, "%-9s %-8s %-9s %-10s %s\n", r.RuleID, r.Module, r.DefaultSeverity, r.MitreD3FEND, r.Title)
		}
		fmt.Fprintf(stdout, "\nTotal rules: %d\n", len(filtered))
		return exitOK
	default:
		fmt.Fprintf(stderr, "invalid --format %q: expected table or json\n", formatStr)
		return exitErr
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "output version metadata as JSON")
	if code, ok := parseFlagsWithHelp(fs, args, stdout, stderr); !ok {
		return code
	}
	if asJSON {
		raw, _ := json.MarshalIndent(map[string]string{
			"tool":           schema.ToolName,
			"version":        schema.Version,
			"schema_version": schema.SchemaVersion,
			"layer":          schema.LayerDevSecOps,
		}, "", "  ")
		fmt.Fprintln(stdout, string(raw))
		return exitOK
	}
	fmt.Fprintf(stdout, "%s v%s (schema %s, layer %s)\n", schema.ToolName, schema.Version, schema.SchemaVersion, schema.LayerDevSecOps)
	return exitOK
}
