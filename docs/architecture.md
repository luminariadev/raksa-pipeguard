# raksa-pipeguard Architecture

`raksa-pipeguard` is the Layer 4 (`devsecops`) component of the Raksa Blue Team and DevSecOps suite. Delivered as a single zero-CGO static Go binary and 9.x MB distroless container, it consolidates CI/CD supply-chain defense into one deterministic gate emitting Raksa Finding Schema v1 (`0-100 / A+..F` posture score) and SARIF 2.1.0.

## Pipeline Architecture

```text
                      [ Local Repository / CI Workspace / Git ]
         +-----------------+----------------+---------------+----------------+
         |                 |                |               |                |
         v                 v                v               v                |
  +-------------+   +-------------+  +-------------+  +-------------+        |
  | Secrets &   |   | Lockfiles & |  | IaC Linters |  | CI Workflow |        |
  | Git History |   | CycloneDX   |  | Dockerfile  |  | Auditor     |        |
  | (PIPE-001.. |   | + OSV.dev   |  | K8s / TF    |  | (PIPE-401.. |        |
  |  PIPE-006)  |   | (PIPE-101..) | | (PIPE-201..)|  |  PIPE-404)  |        |
  +------+------+   +------+------+  +------+------+  +------+------+        |
         |                 |                |                |               |
         +-----------------+--------+-------+----------------+               |
                                    |                                        |
                                    v                                        |
                         +--------------------+                              |
                         | .pipeguard.yml     | (Mandatory reason +          |
                         | Policy Waiver Gate |  fail-closed expires_on)     |
                         +---------+----------+                              |
                                   |                                         |
                                   v                                         |
                         +--------------------+                              |
                         | Raksa Schema v1    | (Posture Score 0-100 / A+..F)|
                         +---+------+-----+---+                              |
                             |      |     |                                  |
                             v      v     v                                  |
                         [Table] [JSON] [SARIF 2.1.0] <--- stdio MCP (7 tools)
```

## Module Responsibilities

- `cmd/raksa-pipeguard/`: CLI entrypoint (`scan-secrets`, `scan-deps`, `sbom`, `scan-iac`, `scan-ci`, `scan-repo`, `rules`, `mcp`, `version`) with pipeline exit codes (`0` clean, `1` error, `2` findings >= `--fail-on`).
- `internal/schema/`: Raksa Finding Schema v1 (`Report`, `PostureScore`, `Finding`, `Summary`) and built-in 24-rule catalog (`PIPE-001`..`PIPE-404`) mapped to OWASP CI/CD Top 10, SLSA, CIS Benchmarks, and MITRE D3FEND.
- `internal/policy/`: YAML/JSON `.pipeguard.yml` waiver engine enforcing audit reasons and fail-closed `expires_on` dates (`YYYY-MM-DD`).
- `internal/secrets/`: Bounded parallel worker-pool secret scanner (`ShannonEntropy` + high-confidence patterns + placeholder filtering + `MaskSecret` redaction) and Git `--staged` / `--git-history` diff scanner.
- `internal/deps/`: Multi-ecosystem lockfile/manifest parser (`Go`, `npm`, `Cargo`, `PyPI`), zero-dep CycloneDX 1.5 JSON SBOM generator, and offline/online OSV vulnerability matcher (`api.osv.dev/v1/querybatch`).
- `internal/iac/`: Static multi-stage Dockerfile linter (`PIPE-201`..`PIPE-206`), Kubernetes YAML workload linter (`PIPE-301`..`PIPE-303`), and Terraform HCL linter (`PIPE-304`).
- `internal/ciworkflow/`: GitHub Actions workflow supply-chain auditor (`pull_request_target`, `${{ github.event.* }}` script injection, `permissions`, and third-party SHA pinning).
- `internal/report/`: ANSI-sanitized table (showing score/grade), JSON Schema v1, and SARIF 2.1.0 serializers.
- `internal/mcp/`: Line-bounded `stdio` JSON-RPC 2.0 MCP server exposing 7 defensive `pipeguard_*` tools.
