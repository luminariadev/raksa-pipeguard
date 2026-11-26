# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

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
