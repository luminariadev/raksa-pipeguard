# raksa-pipeguard Defensive Threat Model

`raksa-pipeguard` operates as a defensive shift-left audit engine for source trees, dependency lockfiles, container definitions, infrastructure manifests, and CI/CD workflows.

## Trust Boundaries & Hardening Controls

1. **Zero Secret Echo / Log Leakage**:
   - Detected credentials in working trees, `--staged` diffs, or `--git-history` are masked through `MaskSecret` before hitting `Finding.Evidence`, CLI tables, JSON reports, SARIF files, or MCP responses. Raw token bodies are never emitted.
2. **Bounded I/O & Binary Safety**:
   - Secret, lockfile, IaC, and workflow scanners skip `.git`, `node_modules`, `target`, `dist`, and `vendor`, skip binary files containing NUL bytes, and reject oversized inputs (`2 MiB` secret cap / `4 MiB` lockfile cap / `2 MiB` MCP line cap) to prevent memory exhaustion in CI runners.
3. **Fail-Closed Policy Waivers**:
   - Every suppression in `.pipeguard.yml` must document an audit `reason`. Optional `expires_on` dates (`YYYY-MM-DD`) fail closed once expired so temporary exceptions automatically re-open CI gates.
4. **Offline-First & Explicit Opt-In Egress**:
   - Dependency scanning and SBOM generation work 100% offline by default. Queries to `https://api.osv.dev/v1/querybatch` happen only when `--online` (or MCP `online: true`) is explicitly passed, over bounded TLS timeouts, sending only package coordinates and versions (no source code, repo paths, or environment variables).
5. **Argument-Safe Subprocess Execution**:
   - `--staged` and `--git-history` invoke `git` via fixed `exec.Command("git", ...)` argument vectors inside validated directory paths with `GIT_TERMINAL_PROMPT=0` rather than shell interpolation.
6. **Terminal ANSI Sanitization**:
   - Repository file names, rule metadata, and evidence extracted from untrusted PR branches are stripped of ANSI escape sequences (`ESC [`, `ESC ]`) before rendering CLI tables.
