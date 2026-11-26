# raksa-pipeguard

Fast, zero-bloat DevSecOps & CI/CD security gate written in Go (`Layer 4` of the Raksa Security Suite).

`raksa-pipeguard` consolidates pre-commit and pipeline checks into a single `7 MB` static binary and `9.27 MB` distroless container image: parallel secret detection (working tree, staged diff, and Git commit history), multi-ecosystem lockfile and CycloneDX 1.5 SBOM auditing (offline DB or OSV.dev), Dockerfile / Kubernetes / Terraform static linters, GitHub Actions workflow hardening, fail-closed `.pipeguard.yml` waivers, SARIF 2.1.0 reporting, and a 7-tool stdio MCP server.

## Key Capabilities

- **24 Built-In Security Rules (`PIPE-001` through `PIPE-404`)**: Mapped to OWASP CI/CD Top 10, OWASP ASVS, CIS Benchmarks, SLSA, and MITRE D3FEND techniques (`D3-KM`, `D3-SBOM`, `D3-CH`, `D3-NI`, `D3-IV`).
- **Parallel Secret & Git History Scanner (`PIPE-001`..`PIPE-006`)**: Combines high-precision provider/URI signatures with Shannon entropy scoring, placeholder filtering, safe redaction (`abcd***REDACTED***wxyz`), and `git log` / `git diff --cached` inspection (`GIT_TERMINAL_PROMPT=0`).
- **Multi-Ecosystem Lockfiles, CycloneDX 1.5 SBOM & OSV Audit (`PIPE-101`..`PIPE-104`)**: Inventories `go.mod`/`go.sum`, `package.json`/`package-lock.json`, `Cargo.toml`/`Cargo.lock`, and `requirements.txt`, exports deterministic CycloneDX 1.5 JSON, and audits against local advisory bundles or `https://api.osv.dev/v1/querybatch`.
- **IaC & Container Hardening Linters (`PIPE-201`..`PIPE-304`)**: Audits multi-stage Dockerfiles (`USER`, pinned base tags, `ENV`/`ARG` secrets, `curl|sh`, `chmod 777`, `EXPOSE 22`/`HEALTHCHECK`), Kubernetes manifests (`privileged`, `hostNetwork`/`hostPID`, `runAsNonRoot`, `allowPrivilegeEscalation`, `capabilities.drop: [ALL]`, `readOnlyRootFilesystem`, limits), and Terraform HCL (public SSH/RDP ingress `0.0.0.0/0`, public S3 ACLs, unencrypted volumes).
- **GitHub Actions Supply-Chain Auditor (`PIPE-401`..`PIPE-404`)**: Detects `pull_request_target` untrusted PR head checkouts, `${{ github.event.* }}` shell injection inside `run:`, `permissions: write-all` or missing `permissions:`, and unpinned third-party actions or mutable `@main`/`@master` refs.
- **Fail-Closed `.pipeguard.yml` Policy Engine**: Every rule suppression requires an explicit `reason` and rejects malformed or expired `expires_on` (`YYYY-MM-DD`) dates instead of silently ignoring stale exceptions.
- **Posture Scoring & Triple Reporting**: Computes a `0-100` posture score (`A+` through `F`) under Raksa Finding Schema v1 (`layer: "devsecops"`), exporting ANSI-sanitized CLI tables, structured JSON, and GitHub Code Scanning SARIF `2.1.0`.
- **7-Tool Stdio MCP Server**: Exposes every scanner over newline-delimited JSON-RPC 2.0 with a `2 MiB` frame limit for autonomous IDE and agent-driven pipeline remediation.

## Architecture

```text
+-----------------------------------------------------------------------------+
|                        raksa-pipeguard CLI / MCP / CI                       |
|   scan-secrets | scan-deps | sbom | scan-iac | scan-ci | scan-repo | mcp    |
+-----------------------------------------------------------------------------+
        |                  |                  |                   |
        v                  v                  v                   v
+---------------+  +---------------+  +---------------+   +---------------+
| secrets       |  | deps          |  | iac           |   | ciworkflow    |
| Worker pool   |  | Go/Node/Rust/ |  | Dockerfile,   |   | GitHub Actions|
| Entropy + git |  | PyPI + CDX1.5 |  | K8s YAML, HCL |   | YAML AST      |
+---------------+  +---------------+  +---------------+   +---------------+
        |                  |                  |                   |
        +------------------+--------+---------+-------------------+
                                    |
                                    v
             +---------------------------------------------+
             | policy (.pipeguard.yml fail-closed waivers) |
             | schema (Finding v1 + Posture Score 0-100)   |
             | report (table | json | SARIF 2.1.0)         |
             +---------------------------------------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for component design decisions and trust boundaries.

## Installation

### From Source / `go install`

Requires Go `1.24` or newer (`go 1.24` declared in `go.mod`):

```bash
go install github.com/luminariadev/raksa-pipeguard/cmd/raksa-pipeguard@v0.1.0
```

Or build locally with stripped symbols:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o raksa-pipeguard ./cmd/raksa-pipeguard
```

### Prebuilt Release Archives

Download platform binaries and `SHA256SUMS.txt` from the GitHub Releases page (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`).

### Container Image (Distroless Non-Root, 9.27 MB)

```bash
docker build -t raksa-pipeguard:v0.1.0 .
docker run --rm -v "$PWD:/workspace:ro" raksa-pipeguard:v0.1.0 scan-repo --path /workspace --format table
```

## Quick Start

### Unified Repository Gate (`scan-repo`)

```bash
# Scan a hardened baseline (exit code 0, score 100/100 A+)
raksa-pipeguard scan-repo --path testdata/hardened --fail-on low --format table

# Scan with offline advisory bundle, waiver policy, and SARIF 2.1.0 output (exit code 2 on breach)
raksa-pipeguard scan-repo \
  --path testdata/vulnerable \
  --offline-db testdata/vulnerable/offline_osv.json \
  --policy testdata/vulnerable/policy_suppress.yml \
  --format sarif \
  --output pipeguard.sarif
```

Observed output on `testdata/hardened`:

```text
raksa-pipeguard v0.1.0 | layer: devsecops | score: 100/100 (A+) | total: 0 (critical: 0, high: 0, medium: 0, low: 0, info: 0)
No security findings detected.
```

Observed summary on `testdata/vulnerable` with `policy_suppress.yml` (which waives `PIPE-206` with future expiry):

```text
raksa-pipeguard v0.1.0 | layer: devsecops | score: 0/100 (F) | total: 23 (critical: 4, high: 10, medium: 8, low: 1, info: 0)
```

### Subcommand Reference

| Subcommand | Purpose | Key Flags |
| --- | --- | --- |
| `scan-repo` | Run all four DevSecOps scanners, waivers, and posture scoring | `--path`, `--offline-db`, `--online`, `--git-history`, `--policy`, `--format`, `--fail-on`, `--output` |
| `scan-secrets` | Scan workspace files, staged diff, and Git commit history | `--path`, `--entropy`, `--workers`, `--staged`, `--git-history`, `--format`, `--fail-on` |
| `scan-deps` | Audit lockfiles/manifests offline or via OSV.dev batch API | `--path`, `--offline-db`, `--online`, `--osv-url`, `--timeout`, `--format`, `--fail-on` |
| `sbom` | Generate deterministic CycloneDX 1.5 JSON SBOM | `--path`, `--output` |
| `scan-iac` | Lint Dockerfiles, Kubernetes YAML, and Terraform HCL | `--path`, `--policy`, `--format`, `--fail-on`, `--output` |
| `scan-ci` | Audit `.github/workflows/*.yml` CI/CD pipelines | `--path`, `--policy`, `--format`, `--fail-on`, `--output` |
| `rules` | List all 24 `PIPE-*` rules with MITRE D3FEND IDs | `--format` (`table` \| `json`), `--module` (`secrets` \| `deps` \| `iac` \| `ci`) |
| `mcp` | Launch stdio JSON-RPC 2.0 MCP server (7 tools) | reads stdin / writes stdout |
| `version` | Print tool, schema version (`1.0`), and layer (`devsecops`) | `--json` |

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Clean run or no findings meet/exceed `--fail-on` threshold |
| `1` | CLI usage, I/O, network, or invalid/expired `.pipeguard.yml` policy error |
| `2` | Security gate breached (`>= --fail-on` severity finding remains after waivers) |

## Rule Catalog (`PIPE-001` to `PIPE-404`)

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

## Fail-Closed Waiver Policy (`.pipeguard.yml`)

`raksa-pipeguard` automatically loads `<target>/.pipeguard.yml` if present, or uses `--policy <file>`. Suppression entries MUST provide `rule_id` and `reason`, and reject invalid or expired `expires_on` dates:

```yaml
min_severity: low

suppressions:
  - rule_id: "PIPE-206"
    target_contains: "worker/Dockerfile"
    reason: "Queue worker exposes no HTTP port and uses process supervision"
    expires_on: "2027-06-30"
```

See [examples/pipeguard-policy.yml](examples/pipeguard-policy.yml).

## Reusable GitHub Action (`action.yml`)

Add DevSecOps gating and SARIF Code Scanning upload to any repository (see [examples/github-workflow.yml](examples/github-workflow.yml)):

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
        uses: luminariadev/raksa-pipeguard@v0.1.0
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
2. `pipeguard_scan_secrets`: Scan workspace files and optional Git commit history for credentials.
3. `pipeguard_scan_deps`: Audit lockfiles and dependencies using an offline advisory file or live `api.osv.dev`.
4. `pipeguard_generate_sbom`: Export a deterministic CycloneDX 1.5 JSON SBOM.
5. `pipeguard_scan_iac`: Audit Dockerfile, Kubernetes YAML, or Terraform HCL by path or inline snippet.
6. `pipeguard_scan_ci_workflow`: Audit `.github/workflows/*.yml` files or inline YAML workflows.
7. `pipeguard_scan_repo`: Run full Layer 4 DevSecOps gate across all modules with policy waivers and score/grade summary.

## Measured Performance

Go microbenchmarks collected on `windows/amd64` (`11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz`) via `go test -run '^$' -bench . -benchmem ./...`:

| Benchmark / Workload | Latency | Memory / Allocs |
| --- | --- | --- |
| `BenchmarkGenerateSBOM` | `10,524 ns/op` | `5,675 B/op`, `19 allocs/op` |
| `BenchmarkScanCI` | `37,599 ns/op` | `20,858 B/op`, `236 allocs/op` |
| `BenchmarkScanIaC` | `41,032 ns/op` | `21,280 B/op`, `264 allocs/op` |
| `BenchmarkScanSecrets` | `58,225 ns/op` | `194 B/op`, `1 allocs/op` |
| Live 9-message MCP stdio session (all 7 tools + `initialize` + `tools/list`) | `22.59 ms` total wall clock | Single cold-started Go binary |

## Raksa Security Suite

| Layer | Repository | Focus | Language |
| --- | --- | --- | --- |
| Layer 1 | [`raksa-recon`](https://github.com/luminariadev/raksa-recon) | External Attack Surface & Reconnaissance | Go |
| Layer 2 | [`raksa-netwatch`](https://github.com/luminariadev/raksa-netwatch) | Host, Firewall & Socket Auditing | Python / Linux |
| Layer 3 | [`raksa-webshield`](https://github.com/luminariadev/raksa-webshield) | Web & API DAST Scanner, Sidecar WAF & TS SDK | TypeScript |
| Layer 4 | [`raksa-pipeguard`](https://github.com/luminariadev/raksa-pipeguard) | DevSecOps Secret, SBOM, IaC & CI/CD Gate | Go |

## License

MIT License. See [LICENSE](LICENSE).
