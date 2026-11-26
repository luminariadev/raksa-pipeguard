# raksa-pipeguard

[![CI](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-4c1.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CycloneDX 1.5](https://img.shields.io/badge/CycloneDX-1.5-2ea44f.svg)](https://cyclonedx.org/)
[![SPDX 2.3](https://img.shields.io/badge/SPDX-2.3-0e8a16.svg)](https://spdx.dev/)
[![MCP](https://img.shields.io/badge/MCP-9%20tools-6f42c1.svg)](#mcp-server-integration-raksa-pipeguard-mcp)

Fast, zero-bloat DevSecOps & CI/CD security gate written in Go (`Layer 4` of the Raksa Security Suite).

`raksa-pipeguard` consolidates pre-commit, PR-diff, container image tarball, and pipeline gates into a single `7.68 MiB` static binary and `9.99 MB` distroless container image: parallel secret detection (working tree, staged diff, PR diff-base, and Git commit history), 10-format dependency inventory with SPDX license auditing and CycloneDX 1.5 / SPDX 2.3 SBOMs + `sbom-diff` (offline DB + parallel TTL-cached OSV.dev, CISA KEV, and FIRST EPSS lookups), daemonless Docker/OCI tarball scanning (`scan-image`), multi-cloud Dockerfile / Kubernetes / Terraform static linters, GitHub Actions & GitLab CI workflow hardening, custom organization regex policies, deterministic baselines and remediation patches (`fix-preview`), SARIF 2.1.0 / Markdown reporting, and a 9-tool stdio MCP server.

## Key Capabilities (`v0.3.0`)

- **33 Built-In Security Rules (`PIPE-001` through `PIPE-501`)**: Mapped to OWASP CI/CD Top 10, OWASP ASVS, CIS Benchmarks, SLSA, SPDX License Compliance, CISA KEV / EPSS, and MITRE D3FEND techniques (`D3-KM`, `D3-SBOM`, `D3-CH`, `D3-NI`, `D3-IV`).
- **Parallel Secret, Staged & PR Diff-Base Scanner (`PIPE-001`..`PIPE-006`)**: Combines cloud/SaaS/VCS signatures (AWS, GCP, Azure, GitHub, GitLab, npm, PyPI, RubyGems, DigitalOcean, Cloudflare, Vault, Databricks, Hugging Face, Stripe, SendGrid, Twilio, Mailgun, Shopify, Slack/Discord webhooks, Telegram, JWTs, DB URIs) with Shannon entropy scoring, context-aware unlabeled assignment detection, placeholder filtering, safe redaction (`abcd***REDACTED***wxyz`), and `git` inspection (`--staged`, `--diff-base`, `--git-history`, `GIT_TERMINAL_PROMPT=0`).
- **10 Lockfile/Manifest Formats, CycloneDX 1.5 & SPDX 2.3 SBOMs, `sbom-diff`, Licenses & OSV/KEV/EPSS (`PIPE-101`..`PIPE-106`)**: Inventories `go.mod`/`go.sum`, `package.json` (lockfile + manifest fallback), `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.toml`/`Cargo.lock`, `requirements.txt`, `pyproject.toml`/`poetry.lock`/`uv.lock`, `composer.json`/`composer.lock`, and `pom.xml`; exports CycloneDX 1.5 and SPDX 2.3 JSON; compares BOM snapshots with `sbom-diff`; flags prohibited copyleft licenses (`AGPL`/`GPL`/`SSPL`/`BUSL`); queries `https://api.osv.dev` in parallel (8 workers + 6h disk TTL cache + `fixed_version` extraction); and escalates CISA KEV or high-EPSS CVEs to critical `PIPE-106`.
- **Daemonless Container Image Tarball Scanner (`scan-image`)**: Pure-Go reader for Docker `save` (`manifest.json`) and OCI layout (`index.json`) archives without a Docker daemon, auditing runtime `User` (`PIPE-201`), baked `Env` secrets (`PIPE-203`), ordered layer whiteouts, Alpine `apk` and Debian/Distroless `dpkg` packages, SPDX licenses, and OSV/KEV/EPSS advisories.
- **Multi-Cloud IaC Linters & Deterministic Remediation (`PIPE-201`..`PIPE-306`, `fix-preview`)**: Audits Dockerfiles (`ARG`-expanded `FROM` tags, `USER`, `ENV`/`ARG` secrets, `curl|sh` / `-k`, `chmod 777`, `EXPOSE 22`/`HEALTHCHECK`), Kubernetes manifests (Deployments, StatefulSets, DaemonSets, Jobs, and `CronJob`s including `initContainers`/`ephemeralContainers`), and Terraform HCL with two-pass `var.*`/`local.*` expansion across AWS (`PIPE-304`), GCP (`PIPE-305`), and Azure (`PIPE-306`), plus deterministic unified hardening diffs via `fix-preview`.
- **GitHub Actions & GitLab CI Supply-Chain Auditor (`PIPE-401`..`PIPE-408`)**: Detects `pull_request_target` untrusted PR head checkouts, `${{ github.event.* }}` injection in `run:` scripts and `actions/github-script` `with.script`, untrusted writes to `$GITHUB_ENV`/`$GITHUB_PATH`, unsafe `workflow_run` artifact execution, `permissions: write-all` or missing `permissions:`, unpinned third-party actions, privileged `docker:dind` without TLS, GitLab hardcoded secrets/log leaks, `:latest` images, and unpinned/HTTP remote `include:` templates.
- **Enterprise Policy, Custom Rules (`PIPE-501`), Baselines & Markdown PR Reports**: `.pipeguard.yml` enforces fail-closed waivers (`reason` + future `expires_on`), `denied_licenses`, and regex-validated `custom_rules`, while `--baseline`, `--write-baseline`, `--diff-base`, and `--format markdown` streamline PR review gating.
- **Managed Git Pre-Commit Hook (`install-hook`) & 9-Tool Stdio MCP Server**: Installs or uninstalls managed `.git/hooks/pre-commit` secret gates and exposes all scanners, container image auditing, and deterministic patch suggestions over line-bounded (`2 MiB`) JSON-RPC 2.0 MCP stdio.

## Architecture

```text
+-----------------------------------------------------------------------------+
|                        raksa-pipeguard CLI / MCP / CI                       |
| scan-secrets | scan-deps | scan-image | sbom | sbom-diff | scan-iac | fix   |
| scan-ci      | scan-repo | install-hook      | rules     | mcp      | ver   |
+-----------------------------------------------------------------------------+
      |              |              |              |              |
      v              v              v              v              v
+-----------+  +-----------+  +-----------+  +-----------+  +-----------+
| secrets   |  | deps      |  | image     |  | iac / fix |  | ciworkflow|
| Diff/Git/ |  | CDX1.5 /  |  | Docker/OCI|  | Dockerfile|  | GH Actions|
| Entropy   |  | SPDX 2.3  |  | tarballs  |  | K8s / TF  |  | GitLab CI |
+-----------+  | OSV/KEV/  |  | apk/dpkg  |  | diffs     |  +-----------+
               | EPSS      |  +-----------+  +-----------+
               +-----------+
                     |
                     v
      +-----------------------------------------------------------------+
      | policy (waivers, custom_rules, baseline)                        |
      | schema (Finding v1 + Posture Score 0-100 + 33 PIPE-* rules)     |
      | report (table | json | SARIF 2.1.0 | markdown)                  |
      +-----------------------------------------------------------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for component design decisions and trust boundaries.

## Installation

### From Source / `go install`

Requires Go `1.24` or newer (`go 1.24` declared in `go.mod`):

```bash
go install github.com/luminariadev/raksa-pipeguard/cmd/raksa-pipeguard@v0.3.0
```

Or build locally with stripped symbols (`7.68 MiB` static binary):

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o raksa-pipeguard ./cmd/raksa-pipeguard
```

### Prebuilt Release Archives

Download platform binaries and `SHA256SUMS.txt` from the GitHub Releases page (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`).

### Container Image (Distroless Non-Root, `9.99 MB`)

```bash
docker build -t raksa-pipeguard:v0.3.0 .
docker run --rm -v "$PWD:/workspace:ro" raksa-pipeguard:v0.3.0 scan-repo --path /workspace --format table
```

## Quick Start

### Unified Repository, Image & Fix Gates

```bash
# Scan a hardened baseline (exit code 0, score 100/100 A+)
raksa-pipeguard scan-repo testdata/hardened --fail-on low --format table

# Record an audited baseline snapshot cleanly
raksa-pipeguard scan-repo --path . --write-baseline .pipeguard-baseline.json --fail-on none

# Gate pull requests with OSV + CISA KEV + FIRST EPSS and PR Markdown output
raksa-pipeguard scan-repo --path . --diff-base origin/main --online --online-kev --online-epss --format markdown

# Inspect a saved Docker/OCI container tarball without a running Docker daemon
raksa-pipeguard scan-image --path app-image.tar --online --online-kev --format table

# Export SPDX 2.3 JSON SBOM and diff against a prior build
raksa-pipeguard sbom --path . --format spdx --output sbom-new.spdx.json
raksa-pipeguard sbom-diff --old sbom-prev.spdx.json --new sbom-new.spdx.json

# Preview deterministic unified hardening patches
raksa-pipeguard fix-preview --path Dockerfile

# Install pre-commit staged secret protection in local repo
raksa-pipeguard install-hook --path . --fail-on high
```

Observed output on `testdata/hardened`:

```text
raksa-pipeguard v0.3.0 | layer: devsecops | score: 100/100 (A+) | total: 0 (critical: 0, high: 0, medium: 0, low: 0, info: 0)
No security findings detected.
```

### Subcommand Reference (13 Subcommands)

| Subcommand | Purpose | Key Flags |
| --- | --- | --- |
| `scan-repo` | Run all scanners, licenses, custom rules, KEV/EPSS enrichment, baseline/diff-base, and posture scoring | `--path`, `--offline-db`, `--online`, `--kev-db`, `--online-kev`, `--online-epss`, `--epss-threshold`, `--no-cache`, `--cache-dir`, `--git-history`, `--diff-base`, `--baseline`, `--write-baseline`, `--policy`, `--format`, `--fail-on`, `--output` |
| `scan-secrets` | Scan workspace files, staged diff, PR diff-base, and Git commit history | `--path`, `--entropy`, `--workers`, `--staged`, `--diff-base`, `--git-history`, `--baseline`, `--format`, `--fail-on` |
| `scan-deps` | Audit lockfiles/manifests, SPDX licenses, offline/cached OSV.dev, CISA KEV, and FIRST EPSS advisories | `--path`, `--offline-db`, `--online`, `--kev-db`, `--online-kev`, `--online-epss`, `--epss-threshold`, `--no-cache`, `--cache-dir`, `--osv-url`, `--timeout`, `--baseline`, `--format`, `--fail-on` |
| `scan-image` | Audit Docker save or OCI layout container tarballs daemonlessly (User, Env secrets, `apk`/`dpkg`, OSV/KEV/EPSS) | `--path`, `--offline-db`, `--online`, `--kev-db`, `--online-kev`, `--online-epss`, `--epss-threshold`, `--no-cache`, `--policy`, `--baseline`, `--format`, `--fail-on`, `--output` |
| `sbom` | Generate deterministic CycloneDX 1.5 or SPDX 2.3 JSON SBOM with license metadata | `--path`, `--format` (`cyclonedx` \| `spdx`), `--output` |
| `sbom-diff` | Compare two CycloneDX 1.5 or SPDX 2.3 SBOM snapshots for component adds, removals, version updates, and license drift | `--old`, `--new`, `--format` (`table` \| `json`), `--output` |
| `scan-iac` | Lint Dockerfiles (`ARG` expansion), Kubernetes YAML (`CronJob`/`initContainers`), and multi-cloud Terraform HCL | `--path`, `--policy`, `--baseline`, `--format`, `--fail-on`, `--output` |
| `scan-ci` | Audit GitHub Actions (`.github/workflows/*.yml`, `github-script`, `GITHUB_ENV`, `workflow_run`) & GitLab CI (`.gitlab-ci.yml`) | `--path`, `--policy`, `--baseline`, `--format`, `--fail-on`, `--output` |
| `fix-preview` | Generate deterministic hardening patches and unified diffs for Dockerfiles, Kubernetes YAML, and GitHub Actions | `--path`, `--kind`, `--format` (`diff` \| `json`), `--output` |
| `install-hook` | Install or uninstall managed `.git/hooks/pre-commit` secret check | `--path`, `--fail-on`, `--force`, `--uninstall` |
| `rules` | List all 33 `PIPE-*` rules with MITRE D3FEND IDs | `--format` (`table` \| `json`), `--module` (`secrets` \| `deps` \| `iac` \| `ci` \| `policy`) |
| `mcp` | Launch stdio JSON-RPC 2.0 MCP server (9 tools) | reads stdin / writes stdout |
| `version` | Print tool, schema version (`1.0`), and layer (`devsecops`) | `--json` |

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Clean run or no findings meet/exceed `--fail-on` threshold |
| `1` | CLI usage, I/O, network, hook, or invalid/expired `.pipeguard.yml` policy error |
| `2` | Security gate breached (`>= --fail-on` severity finding remains after waivers/baseline) |

## Rule Catalog (`PIPE-001` to `PIPE-501`)

| Rule ID | Module | Default Severity | Standard | MITRE D3FEND | Title |
| --- | --- | --- | --- | --- | --- |
| `PIPE-001` | `secrets` | `critical` | OWASP CI/CD-SEC-6 | `D3-KM` | Hardcoded cloud provider access key or credential detected |
| `PIPE-002` | `secrets` | `critical` | OWASP CI/CD-SEC-6 | `D3-KM` | Hardcoded VCS or package registry token detected |
| `PIPE-003` | `secrets` | `critical` | OWASP ASVS 6.4.1 | `D3-KM` | Private cryptographic key material embedded in repository |
| `PIPE-004` | `secrets` | `high` | OWASP ASVS 2.10.4 | `D3-KM` | Hardcoded SaaS token, JWT, or authenticated DB URI detected |
| `PIPE-005` | `secrets` | `high` | OWASP CI/CD-SEC-6 | `D3-KM` | High-entropy generic secret assignment detected |
| `PIPE-006` | `secrets` | `critical` | OWASP CI/CD-SEC-6 | `D3-KM` | Exposed secret discovered in Git history or staged diff |
| `PIPE-101` | `deps` | `high` | OWASP CI/CD-SEC-3 | `D3-SBOM` | Critical or High OSV/CVE vulnerability in project dependency |
| `PIPE-102` | `deps` | `medium` | OWASP CI/CD-SEC-3 | `D3-SBOM` | Medium or Low OSV/CVE vulnerability in project dependency |
| `PIPE-103` | `deps` | `medium` | SLSA Build L2 | `D3-SBOM` | Unpinned wildcard, latest, or VCS dependency version |
| `PIPE-104` | `deps` | `low` | SLSA Build L2 | `D3-SBOM` | Missing dependency lockfile or integrity verification |
| `PIPE-105` | `deps` | `medium` | SPDX License Compliance | `D3-SBOM` | Prohibited or restricted copyleft dependency license detected |
| `PIPE-106` | `deps` | `critical` | CISA KEV / EPSS | `D3-SBOM` | Known exploited (CISA KEV) or high-EPSS vulnerability in dependency |
| `PIPE-201` | `iac` | `high` | CIS Docker 4.1 | `D3-CH` | Dockerfile runs final stage as root user |
| `PIPE-202` | `iac` | `medium` | CIS Docker 4.7 | `D3-CH` | Dockerfile base image uses mutable `:latest` or unpinned tag |
| `PIPE-203` | `iac` | `high` | CIS Docker 4.10 | `D3-KM` | Dockerfile embeds sensitive secret in `ENV` or `ARG` |
| `PIPE-204` | `iac` | `high` | OWASP CI/CD-SEC-4 | `D3-CH` | Dockerfile pipes remote script to shell or uses insecure `ADD` URL |
| `PIPE-205` | `iac` | `medium` | CIS Docker 4.8 | `D3-CH` | Dockerfile invokes `sudo`, `chmod 777`, or grants setuid privileges |
| `PIPE-206` | `iac` | `low` | CIS Docker 4.6 | `D3-CH` | Dockerfile exposes SSH port 22 or lacks `HEALTHCHECK` for service port |
| `PIPE-301` | `iac` | `critical` | CIS Kubernetes 5.2 | `D3-NI` | Kubernetes pod runs privileged or shares host namespaces |
| `PIPE-302` | `iac` | `high` | CIS Kubernetes 5.2.6 | `D3-CH` | Kubernetes container lacks non-root or capability-drop hardening |
| `PIPE-303` | `iac` | `medium` | CIS Kubernetes 5.2 | `D3-CH` | Kubernetes container lacks `readOnlyRootFilesystem` or resource limits |
| `PIPE-304` | `iac` | `high` | CIS Cloud Benchmark | `D3-CH` | Terraform IaC exposes management ports, public S3 ACL, or unencrypted storage |
| `PIPE-305` | `iac` | `high` | CIS GCP Benchmark | `D3-CH` | Terraform GCP firewall or storage IAM exposes management ports or public access |
| `PIPE-306` | `iac` | `high` | CIS Azure Benchmark | `D3-CH` | Terraform Azure NSG or storage account weakens network or HTTPS safeguards |
| `PIPE-401` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-CH` | GitHub Actions `pull_request_target` checks out untrusted PR head code |
| `PIPE-402` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-IV` | GitHub Actions workflow interpolates untrusted event expression in shell run |
| `PIPE-403` | `ci` | `high` | SLSA Build L2 | `D3-CH` | GitHub Actions workflow uses `write-all` or omits explicit permissions |
| `PIPE-404` | `ci` | `medium` | SLSA Source / Build L3 | `D3-SBOM` | GitHub Actions uses unpinned third-party action or mutable branch reference |
| `PIPE-405` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-CH` | GitLab CI runs privileged insecure DinD or pipes remote script to shell |
| `PIPE-406` | `ci` | `high` | OWASP CI/CD-SEC-6 | `D3-KM` | GitLab CI hardcodes sensitive variable or exposes credentials in script logs |
| `PIPE-407` | `ci` | `medium` | SLSA Build L2 | `D3-SBOM` | GitLab CI uses unpinned `:latest` image or mutable remote include ref |
| `PIPE-408` | `ci` | `high` | OWASP CI/CD-SEC-4 | `D3-IV` | GitHub Actions writes untrusted input to GITHUB_ENV/PATH or executes workflow_run artifacts |
| `PIPE-501` | `policy` | `high` | Enterprise Custom Policy | `D3-CH` | Custom organization security policy rule violation detected |

## Enterprise Policy (`.pipeguard.yml`)

`raksa-pipeguard` automatically loads `<target>/.pipeguard.yml` if present, or uses `--policy <file>`. Suppressions fail closed without a `reason` or once `expires_on` passes, and custom regex rules are compiled at load time:

```yaml
min_severity: low

denied_licenses:
  - AGPL
  - GPL
  - SSPL
  - BUSL

suppressions:
  - rule_id: "PIPE-206"
    target_contains: "worker/Dockerfile"
    reason: "Queue worker exposes no HTTP port and uses process supervision"
    expires_on: "2027-06-30"

custom_rules:
  - id: "ORG-REG-001"
    title: "Disallow unapproved legacy internal container registry"
    severity: high
    pattern: "registry\\.legacy\\.internal"
    path_glob: "*.yml"
    remediation: "Migrate container image references to ghcr.io/org-verified."
```

See [examples/pipeguard-policy.yml](examples/pipeguard-policy.yml).

## Reusable GitHub Action (`action.yml`)

Add DevSecOps gating, PR diff scoping, and SARIF Code Scanning upload to any repository (see [examples/github-workflow.yml](examples/github-workflow.yml)):

```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  pipeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Pin to the full 40-character release commit SHA in strict SLSA L3 environments.
      - name: Run Raksa PipeGuard Gate
        uses: luminariadev/raksa-pipeguard@v0.3.0
        with:
          path: .
          mode: repo
          format: sarif
          fail-on: high
          output: pipeguard.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pipeguard.sarif
```

## MCP Server Integration (`raksa-pipeguard mcp`)

Connect AI coding assistants or IDE agents directly to `raksa-pipeguard` over stdio JSON-RPC 2.0:

```json
{
  "mcpServers": {
    "raksa-pipeguard": {
      "command": "raksa-pipeguard",
      "args": ["mcp"]
    }
  }
}
```

Registered MCP tools (9):

1. `pipeguard_list_rules`: Return cataloged `PIPE-*` rules (optionally filtered by module).
2. `pipeguard_scan_secrets`: Scan workspace files, PR diff-base (`diff_base`), and optional Git commit history.
3. `pipeguard_scan_deps`: Audit 10 lockfile/manifest formats, SPDX licenses, and offline/cached OSV.dev, CISA KEV, and FIRST EPSS advisories.
4. `pipeguard_generate_sbom`: Export a deterministic CycloneDX 1.5 or SPDX 2.3 JSON SBOM with license metadata.
5. `pipeguard_scan_iac`: Audit Dockerfile (`ARG`-expanded tags), Kubernetes YAML (`CronJob`/`initContainers`), or multi-cloud Terraform HCL by path or inline snippet.
6. `pipeguard_scan_ci_workflow`: Audit GitHub Actions (`.github/workflows/*.yml`, `github-script`, `GITHUB_ENV`, `workflow_run`) and GitLab CI (`.gitlab-ci.yml`) pipelines by path or inline YAML.
7. `pipeguard_scan_repo`: Run full Layer 4 DevSecOps gate across all modules, custom rules, KEV/EPSS enrichment, baseline suppression, PR diff scoping, Markdown/SARIF/JSON output, and posture scoring.
8. `pipeguard_scan_image`: Inspect Docker save and OCI layout container tarballs daemonlessly for root `User`, baked `Env` secrets, Alpine `apk` / Debian `dpkg` packages, SPDX licenses, and OSV/KEV/EPSS advisories.
9. `pipeguard_suggest_fix`: Generate deterministic hardening patches and unified diffs for Dockerfiles, Kubernetes YAML, and GitHub Actions workflows.

## Measured Performance (`v0.3.0`)

Benchmarks measured on `windows/amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`) against `v0.3.0` (`7.68 MiB` static binary, `9.99 MB` distroless image):

| Benchmark / Workload | Latency | Throughput / Allocations |
| --- | --- | --- |
| `BenchmarkGenerateSBOM` | `8,986 ns/op` | `5,772 B/op`, `19 allocs/op` |
| `BenchmarkScanGitLabCI` | `31,310 ns/op` | `20,437 B/op`, `205 allocs/op` |
| `BenchmarkScanCI` | `35,986 ns/op` | `20,866 B/op`, `236 allocs/op` |
| `BenchmarkScanIaC` | `36,858 ns/op` | `21,280 B/op`, `264 allocs/op` |
| `BenchmarkScanSecrets` | `113,528 ns/op` | `195 B/op`, `1 allocs/op` |
| `scan-image` (`golang:1.26-alpine` `242.72 MB` tarball) | `211 ms` | `PIPE-201` + 9 Alpine `apk` findings |
| `scan-image` (`raksa-pipeguard:v0.3.0` distroless tarball) | `377 ms` | `100/100 (A+)`, 0 findings |
| Live persistent MCP stdio 50-call burst (`pipeguard_scan_repo`) | `avg 3.00 ms` | `333.5 scans/sec` (`149.94 ms` total) |
| Live persistent MCP stdio 50-call burst (`pipeguard_list_rules`) | `avg 0.36 ms` | `18 ms` total across 52 JSON-RPC messages |

## Scope & Boundaries

`raksa-pipeguard` is built as a fast, deterministic DevSecOps CLI gate, GitHub Action, and local MCP server rather than a hosted runtime CNAPP platform:

- Static IaC analysis evaluates multi-line Terraform HCL blocks, Kubernetes YAML, and Dockerfiles deterministically without invoking `terraform plan`, dynamic OPA/Rego plugins, or cross-module state graphs.
- Vulnerability checks match declared packages and extracted Alpine/Debian OS packages against OSV, CISA KEV, and FIRST EPSS without source-level call-graph reachability analysis.
- Secret detection runs strictly read-only on files, diffs, and container image `Env` configs without probing external provider APIs to validate live credential status.

## Raksa Security Suite

`raksa-pipeguard` shares **Raksa Finding Schema v1** (`schema_version = "1.0"`) across the modular Raksa ecosystem:

- **Layer 1 (`network-defense`)**: [raksa-netguard](https://github.com/luminariadev/raksa-netguard) (Go) - Exposed port audit and real-time firewall/log anomaly detection.
- **Layer 2 (`host-hardening`)**: [raksa-hostguard](https://github.com/luminariadev/raksa-hostguard) (Rust) - Signed parallel SHA-256 FIM, Linux/SSH/Docker CIS hardening, and MCP server.
- **Layer 3 (`web-defense`)**: [raksa-webshield](https://github.com/luminariadev/raksa-webshield) (TypeScript + Go) - Web & API security auditor, semantic SQLi/XSS WAF sidecar, TypeScript SDK, and MCP server.
- **Layer 4 (`devsecops`)**: `raksa-pipeguard` (Go) - This repository.
- **Layer 5 (`malware-ioc`, planned)**: `raksa-iocscan` (Python) - YARA, hash reputation, and entropy anomaly scanner.
- **Layer 6 (`observability-siem`, planned)**: `raksa-siem` (Python + Go) - Log normalizer, correlation engine, and alert router.

## License

MIT License. See [LICENSE](LICENSE).
