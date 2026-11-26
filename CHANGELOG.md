# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.3.0] - 2026-11-27

### Added

- **4 New Enterprise Rules (33 total, `PIPE-001`..`PIPE-501`)**:
  - `PIPE-106`: Upgrades dependency and container OS vulnerabilities matched in the CISA Known Exploited Vulnerabilities (KEV) catalog or meeting configurable FIRST EPSS exploit probability thresholds (`>= 0.50` by default) to `critical` priority.
  - `PIPE-305`: Terraform GCP CIS checks for public firewall ingress (`0.0.0.0/0` / `::/0` on SSH/RDP/management ports), public storage IAM bindings (`allUsers` / `allAuthenticatedUsers`), uniform bucket-level access, and public Cloud SQL instances.
  - `PIPE-306`: Terraform Azure CIS checks for open NSG inbound rules (`*` / `0.0.0.0/0` / `Internet` on management ports), public blob access, and disabled HTTPS-only storage enforcement.
  - `PIPE-408`: GitHub Actions untrusted writes to `$GITHUB_ENV` / `$GITHUB_PATH` and privileged `workflow_run` execution after untrusted artifact downloads.
- **Pure-Go Container Image Tarball Scanner (`scan-image` / `pipeguard_scan_image`)**: Inspects Docker save (`manifest.json`) and OCI layout (`index.json`) container tarballs without requiring a Docker daemon, auditing root runtime users (`PIPE-201`), baked `Env` credentials (`PIPE-203`), ordered overlay whiteouts, Alpine `apk` and Debian/Distroless `dpkg` (`status` / `status.d/*`) package inventories, SPDX license compliance, and OSV/KEV/EPSS advisories.
- **SPDX 2.3 JSON SBOM & `sbom-diff`**: Added `--format spdx` alongside CycloneDX 1.5 in `sbom` / `pipeguard_generate_sbom`, plus the `sbom-diff` subcommand comparing added, removed, version-changed, and license-changed components across both CycloneDX 1.5 and SPDX 2.3 files.
- **Markdown PR Reporter & Deterministic Remediation Engine (`fix-preview` / `pipeguard_suggest_fix`)**: Added `--format markdown` (`md`) for PR-ready Markdown tables and deterministic hardening patches with unified diffs across Dockerfiles, Kubernetes YAML, and GitHub Actions workflows.
- **9-Tool MCP Server & Updated `action.yml`**: Registered `pipeguard_scan_image` and `pipeguard_suggest_fix`, and added `mode: image`, `format: markdown`, `kev-db`, `online-kev`, and `online-epss` inputs.

### Fixed & Improved

- **Adversarial Bypass Closures (6/6 Hardened)**:
  - Context-aware high-entropy detection for unlabeled secret keys (`MY_CRED=...`) inside `.env`/config targets (`PIPE-005`).
  - Kubernetes `CronJob` (`spec.jobTemplate`) and `initContainers` / `ephemeralContainers` inspection (`PIPE-301`..`PIPE-303`).
  - Two-pass Terraform HCL `var.*` and `local.*` resolution across AWS, GCP, and Azure resources (`PIPE-304`..`PIPE-306`).
  - Dockerfile `ARG` interpolation in `FROM` base image resolution (`PIPE-202`) and `curl -k` / `wget --no-check-certificate` detection (`PIPE-204`).
  - GitHub Actions `actions/github-script` `with.script` untrusted `${{ github.event.* }}` expression injection (`PIPE-402`).
  - Manifest-only `package.json` dependency extraction fallback when `package-lock.json` is absent.

## [0.2.0] - 2026-11-26

### Added

- **5 New Enterprise Rules (29 total, `PIPE-001`..`PIPE-501`)**:
  - `PIPE-105`: SPDX dependency license compliance check against configurable denied license families (`AGPL`, `GPL`, `SSPL`, `BUSL` by default).
  - `PIPE-405`, `PIPE-406`, `PIPE-407`: Native GitLab CI (`.gitlab-ci.yml` / `.gitlab-ci.yaml`) security auditor for insecure privileged `docker:dind` TLS disablement, `curl|sh` scripts, hardcoded sensitive variables or log secret leaks, `:latest` images, and unpinned/unencrypted `include:` templates.
  - `PIPE-501`: Custom organization regex security policies defined via `custom_rules` in `.pipeguard.yml` with path glob scoping and audit-validated compilation.
- **6 New Dependency Lockfile & Manifest Formats**: `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `composer.lock` / `composer.json`, and `pom.xml` / `pyproject.toml`, plus SPDX license fields in generated CycloneDX 1.5 SBOMs.
- **Baseline & PR Diff-Base Gating**: Added `--baseline`, `--write-baseline` (deterministic SHA-256 fingerprints), and `--diff-base <git-ref>` across CLI (`scan-repo`, `scan-secrets`, etc.), MCP tools (`baseline_path`, `diff_base`), and composite `action.yml`.
- **Managed Git Hook Installer (`install-hook`)**: 10th CLI subcommand to install or cleanly uninstall (`--uninstall`) POSIX `.git/hooks/pre-commit` staged secret checks.
- **12+ New Secret Provider Signatures**: Azure Storage `AccountKey`, DigitalOcean, Cloudflare, HashiCorp Vault, Databricks, Hugging Face, model inference keys, RubyGems, SendGrid, Twilio, Mailgun, Shopify, Telegram bot tokens, and Slack/Discord webhook URLs.

### Fixed & Improved

- **Parallel Cached OSV.dev Auditor**: Deduplicated `/v1/vulns/<id>` lookups using an 8-worker bounded pool with a 6-hour disk TTL cache (`--cache-dir` / `--no-cache`) and package-matched `fixed_version` extraction, cutting cold online lookup latency roughly 2x and warm queries nearly 3x faster.
- **Expanded `PIPE-005` Keyword Coverage**: Added `service_token`, `api_token`, `bot_token`, `bearer_token`, `refresh_token`, `session_token`, `jwt_secret`, `webhook_secret`, `session_secret`, `encryption_key`, `master_key`, `hmac_secret`, and `oauth_secret`.
- **Consistent CLI Flag Parsing**: Reorders flags passed after a positional target path (`raksa-pipeguard scan-repo path --format json`) and rejects unexpected extra positional arguments with exit `1`.

## [0.1.0] - 2026-11-26

### Added

- Unified Raksa Finding Schema v1 (`layer: "devsecops"`, 24 `PIPE-001` through `PIPE-404` rules) with deterministic posture scoring (`0-100`, grades `A+` through `F`) and MITRE D3FEND mappings.
- Fail-closed `.pipeguard.yml` suppression policy engine requiring explicit justification (`reason`) and rejecting malformed or expired ISO dates (`expires_on`).
- Output reporters for ANSI-sanitized terminal tables, structured JSON, and GitHub Code Scanning SARIF `2.1.0`.
- Parallel working-tree, staged-diff, and git commit history secret scanner (`PIPE-001` through `PIPE-006`) using provider signatures, Shannon entropy analysis, and safe value redaction.
- Multi-ecosystem dependency inventory (`go.mod`/`go.sum`, `package.json`/`package-lock.json`, `Cargo.toml`/`Cargo.lock`, `requirements.txt`), deterministic CycloneDX `1.5` JSON SBOM exporter, and offline/OSV.dev vulnerability auditor (`PIPE-101` through `PIPE-104`).
- Static security linters for multi-stage Dockerfiles (`PIPE-201` through `PIPE-206`), Kubernetes YAML workloads (`PIPE-301` through `PIPE-303`), and Terraform HCL definitions (`PIPE-304`).
- GitHub Actions workflow auditor (`PIPE-401` through `PIPE-404`) detecting `pull_request_target` head checkout risks, shell expression injection, `write-all` / missing permissions, and unpinned actions.
- Line-bounded stdio JSON-RPC 2.0 MCP server (`2 MiB` frame guard) exposing 7 tools for autonomous IDE and CI remediation.
- CLI (`raksa-pipeguard`) with 9 subcommands, distroless `nonroot` container image (`Dockerfile`), composite GitHub Action (`action.yml`), CI/release workflows, and starter templates in `examples/`.
