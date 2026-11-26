# raksa-pipeguard

[![CI](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa-pipeguard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-4c1.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CycloneDX 1.5](https://img.shields.io/badge/CycloneDX-1.5-2ea44f.svg)](https://cyclonedx.org/)
[![MCP](https://img.shields.io/badge/MCP-7%20tools-6f42c1.svg)](#mcp-server-integration-raksa-pipeguard-mcp)

Fast, zero-bloat DevSecOps & CI/CD security gate written in Go (`Layer 4` of the Raksa Security Suite).

`raksa-pipeguard` consolidates pre-commit, PR-diff, and pipeline gates into a single `7.27 MB` static binary and `9.54 MB` distroless container image: parallel secret detection (working tree, staged diff, PR diff-base, and Git commit history), 10-format dependency inventory with SPDX license auditing and CycloneDX 1.5 SBOMs (offline DB + parallel TTL-cached OSV.dev lookups), Dockerfile / Kubernetes / Terraform static linters, GitHub Actions & GitLab CI workflow hardening, custom organization regex policies, deterministic baselines, SARIF 2.1.0 reporting, and a 7-tool stdio MCP server.

## Key Capabilities (`v0.2.0`)

- **29 Built-In Security Rules (`PIPE-001` through `PIPE-501`)**: Mapped to OWASP CI/CD Top 10, OWASP ASVS, CIS Benchmarks, SLSA, SPDX License Compliance, and MITRE D3FEND techniques (`D3-KM`, `D3-SBOM`, `D3-CH`, `D3-NI`, `D3-IV`).
- **Parallel Secret, Staged & PR Diff-Base Scanner (`PIPE-001`..`PIPE-006`)**: Combines cloud/SaaS/VCS signatures (AWS, GCP, Azure, GitHub, GitLab, npm, PyPI, RubyGems, DigitalOcean, Cloudflare, Vault, Databricks, Hugging Face, Stripe, SendGrid, Twilio, Mailgun, Shopify, Slack/Discord webhooks, Telegram, JWTs, DB URIs) with Shannon entropy scoring, placeholder filtering, safe redaction (`abcd***REDACTED***wxyz`), and `git` inspection (`--staged`, `--diff-base`, `--git-history`, `GIT_TERMINAL_PROMPT=0`).
- **10 Lockfile/Manifest Formats, CycloneDX 1.5 SBOM, Licenses & Cached OSV (`PIPE-101`..`PIPE-105`)**: Inventories `go.mod`/`go.sum`, `package.json`/`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.toml`/`Cargo.lock`, `requirements.txt`, `pyproject.toml`/`poetry.lock`/`uv.lock`, `composer.json`/`composer.lock`, and `pom.xml`, exports CycloneDX 1.5 JSON with SPDX license metadata, flags prohibited copyleft licenses (`AGPL`/`GPL`/`SSPL`/`BUSL`), and queries `https://api.osv.dev` in parallel (8 workers + 6h disk TTL cache + `fixed_version` extraction).
- **IaC & Container Hardening Linters (`PIPE-201`..`PIPE-304`)**: Audits multi-stage Dockerfiles (`USER`, pinned base tags, `ENV`/`ARG` secrets, `curl|sh`, `chmod 777`, `EXPOSE 22`/`HEALTHCHECK`), Kubernetes manifests (`privileged`, `hostNetwork`/`hostPID`, `runAsNonRoot`, `allowPrivilegeEscalation`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem`, limits), and Terraform HCL (public SSH/RDP ingress `0.0.0.0/0`, public S3 ACLs, unencrypted volumes).
- **GitHub Actions & GitLab CI Supply-Chain Auditor (`PIPE-401`..`PIPE-407`)**: Detects `pull_request_target` untrusted PR head checkouts, `${{ github.event.* }}` shell injection inside `run:`, `permissions: write-all` or missing `permissions:`, unpinned third-party actions, privileged `docker:dind` without TLS (`DOCKER_TLS_CERTDIR: ""`), GitLab hardcoded secrets/log leaks, `:latest` images, and unpinned/HTTP remote `include:` templates.
- **Enterprise Policy, Custom Rules (`PIPE-501`) & Deterministic Baselines**: `.pipeguard.yml` enforces fail-closed waivers (`reason` + future `expires_on`), `denied_licenses`, and regex-validated `custom_rules`, while `--baseline` / `--write-baseline` and `--diff-base` let teams fail CI strictly on newly introduced risks.
- **Managed Git Pre-Commit Hook (`install-hook`) & 7-Tool Stdio MCP Server**: Installs or uninstalls managed `.git/hooks/pre-commit` secret gates and exposes all scanners over line-bounded (`2 MiB`) JSON-RPC 2.0 MCP stdio.

## Architecture

```text
+-----------------------------------------------------------------------------+
|                        raksa-pipeguard CLI / MCP / CI                       |
|  scan-secrets | scan-deps | sbom | scan-iac | scan-ci | scan-repo | hook    |
+-----------------------------------------------------------------------------+
        |                  |                  |                   |
        v                  v                  v                   v
+---------------+  +---------------+  +---------------+   +---------------+
| secrets       |  | deps          |  | iac           |   | ciworkflow    |
| Worker pool   |  | 10 formats,   |  | Dockerfile,   |   | GitHub Actions|
| Diff/Git/Entr |  | CDX1.5 + OSV  |  | K8s YAML, HCL |   | & GitLab CI   |
+---------------+  +---------------+  +---------------+   +---------------+
        |                  |                  |                   |
        +------------------+--------+---------+-------------------+
                                    |
                                    v
             +---------------------------------------------+
             | policy (waivers, custom_rules, baseline)    |
             | schema (Finding v1 + Posture Score 0-100)   |
             | report (table | json | SARIF 2.1.0)         |
             +---------------------------------------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for component design decisions and trust boundaries.

## Installation

### From Source / `go install`

Requires Go `1.24` or newer (`go 1.24` declared in `go.mod`):

```bash
go install github.com/luminariadev/raksa-pipeguard/cmd/raksa-pipeguard@v0.2.0
```

Or build locally with stripped symbols:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o raksa-pipeguard ./cmd/raksa-pipeguard
```

### Prebuilt Release Archives

Download platform binaries and `SHA256SUMS.txt` from the GitHub Releases page (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`).

### Container Image (Distroless Non-Root, 9.54 MB)

```bash
docker build -t raksa-pipeguard:v0.2.0 .
docker run --rm -v "$PWD:/workspace:ro" raksa-pipeguard:v0.2.0 scan-repo --path /workspace --format table
```

## Quick Start

### Unified Repository Gate (`scan-repo`)

```bash
# Scan a hardened baseline (exit code 0, score 100/100 A+)
raksa-pipeguard scan-repo testdata/hardened --fail-on low --format table

# Record an audited baseline snapshot cleanly
raksa-pipeguard scan-repo --path . --write-baseline .pipeguard-baseline.json --fail-on none

# Gate pull requests only on newly introduced or modified files vs main
raksa-pipeguard scan-repo --path . --diff-base origin/main --online --format sarif --output pipeguard.sarif

# Install pre-commit staged secret protection in local repo
raksa-pipeguard install-hook --path . --fail-on high
```

Observed output on `testdata/hardened`:

```text
raksa-pipeguard v0.2.0 | layer: devsecops | score: 100/100 (A+) | total: 0 (critical: 0, high: 0, medium: 0, low: 0, info: 0)
No security findings detected.
```

### Subcommand Reference (10 Subcommands)

| Subcommand | Purpose | Key Flags |
| --- | --- | --- |
| `scan-repo` | Run all scanners, licenses, custom rules, baseline/diff-base, and posture scoring | `--path`, `--offline-db`, `--online`, `--no-cache`, `--cache-dir`, `--git-history`, `--diff-base`, `--baseline`, `--write-baseline`, `--policy`, `--format`, `--fail-on`, `--output` |
| `scan-secrets` | Scan workspace files, staged diff, PR diff-base, and Git commit history | `--path`, `--entropy`, `--workers`, `--staged`, `--diff-base`, `--git-history`, `--baseline`, `--format`, `--fail-on` |
| `scan-deps` | Audit lockfiles/manifests, SPDX licenses, and offline/cached OSV.dev advisories | `--path`, `--offline-db`, `--online`, `--no-cache`, `--cache-dir`, `--osv-url`, `--timeout`, `--baseline`, `--format`, `--fail-on` |
| `sbom` | Generate deterministic CycloneDX 1.5 JSON SBOM with license metadata | `--path`, `--output` |
| `scan-iac` | Lint Dockerfiles, Kubernetes YAML, and Terraform HCL | `--path`, `--policy`, `--baseline`, `--format`, `--fail-on`, `--output` |
| `scan-ci` | Audit GitHub Actions (`.github/workflows/*.yml`) & GitLab CI (`.gitlab-ci.yml`) | `--path`, `--policy`, `--baseline`, `--format`, `--fail-on`, `--output` |
| `install-hook` | Install or uninstall managed `.git/hooks/pre-commit` secret check | `--path`, `--fail-on`, `--force`, `--uninstall` |
| `rules` | List all 29 `PIPE-*` rules with MITRE D3FEND IDs | `--format` (`table` \| `json`), `--module` (`secrets` \| `deps` \| `iac` \| `ci` \| `policy`) |
| `mcp` | Launch stdio JSON-RPC 2.0 MCP server (7 tools) | reads stdin / writes stdout |
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
| `PIPE-401` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-CH` | GitHub Actions `pull_request_target` checks out untrusted PR head code |
| `PIPE-402` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-IV` | GitHub Actions workflow interpolates untrusted event expression in shell run |
| `PIPE-403` | `ci` | `high` | SLSA Build L2 | `D3-CH` | GitHub Actions workflow uses `write-all` or omits explicit permissions |
| `PIPE-404` | `ci` | `medium` | SLSA Source / Build L3 | `D3-SBOM` | GitHub Actions uses unpinned third-party action or mutable branch reference |
| `PIPE-405` | `ci` | `critical` | OWASP CI/CD-SEC-4 | `D3-CH` | GitLab CI runs privileged insecure DinD or pipes remote script to shell |
| `PIPE-406` | `ci` | `high` | OWASP CI/CD-SEC-6 | `D3-KM` | GitLab CI hardcodes sensitive variable or exposes credentials in script logs |
| `PIPE-407` | `ci` | `medium` | SLSA Build L2 | `D3-SBOM` | GitLab CI uses unpinned `:latest` image or mutable remote include ref |
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
        uses: luminariadev/raksa-pipeguard@v0.2.0
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

Registered MCP tools (7):

1. `pipeguard_list_rules`: Return cataloged `PIPE-*` rules (optionally filtered by module).
2. `pipeguard_scan_secrets`: Scan workspace files, PR diff-base (`diff_base`), and optional Git commit history.
3. `pipeguard_scan_deps`: Audit 10 lockfile/manifest formats, SPDX licenses, and offline/TTL-cached `api.osv.dev` advisories.
4. `pipeguard_generate_sbom`: Export a deterministic CycloneDX 1.5 JSON SBOM with license metadata.
5. `pipeguard_scan_iac`: Audit Dockerfile, Kubernetes YAML, or Terraform HCL by path or inline snippet.
6. `pipeguard_scan_ci_workflow`: Audit GitHub Actions (`.github/workflows/*.yml`) and GitLab CI (`.gitlab-ci.yml`) pipelines by path or inline YAML.
7. `pipeguard_scan_repo`: Run full Layer 4 DevSecOps gate across all modules, custom rules, baseline suppression, PR diff scoping, and posture scoring.

## Measured Performance (`v0.2.0`)

Benchmarks measured on `windows/amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`) against `v0.2.0`:

| Benchmark / Workload | Latency | Throughput / Allocations |
| --- | --- | --- |
| `BenchmarkGenerateSBOM` | `9,944 ns/op` | `5,772 B/op`, `19 allocs/op` |
| `BenchmarkScanGitLabCI` | `33,424 ns/op` | `20,429 B/op`, `205 allocs/op` |
| `BenchmarkScanCI` | `34,153 ns/op` | `20,853 B/op`, `236 allocs/op` |
| `BenchmarkScanIaC` | `39,962 ns/op` | `21,280 B/op`, `264 allocs/op` |
| `BenchmarkScanSecrets` | `111,500 ns/op` | `199 B/op`, `1 allocs/op` |
| Live `--online` OSV.dev (`testdata/vulnerable`, 12 CVEs w/ `fixed_version`) | Cold: `2,043.1 ms` / Warm cache: `737.7 ms` | 8-worker detail pool + 6h disk TTL cache |
| Live persistent MCP stdio 50-call burst (`pipeguard_scan_repo`) | `avg 2.50 ms` (`p95 3.38 ms`) | `334.2 scans/sec` (`149.6 ms` total) |

## Raksa Security Suite

| Layer | Repository | Focus | Language |
| --- | --- | --- | --- |
| Layer 1 | [`raksa-recon`](https://github.com/luminariadev/raksa-recon) | External Attack Surface & Reconnaissance | Go |
| Layer 2 | [`raksa-netwatch`](https://github.com/luminariadev/raksa-netwatch) | Host, Firewall & Socket Auditing | Python / Linux |
| Layer 3 | [`raksa-webshield`](https://github.com/luminariadev/raksa-webshield) | Web & API DAST Scanner, Sidecar WAF & TS SDK | TypeScript / Go |
| Layer 4 | [`raksa-pipeguard`](https://github.com/luminariadev/raksa-pipeguard) | DevSecOps Secret, SBOM, IaC & CI/CD Gate | Go |

## License

MIT License. See [LICENSE](LICENSE).
