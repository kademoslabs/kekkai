# `kekkai doctor` Command Spec

## Purpose
- Provide a single preflight check for local scanner/tool readiness.
- Prevent avoidable scan failures in CI and developer machines.

## Command
```bash
kekkai doctor
```

## Flags
- `--json`: output machine-readable JSON diagnostics.
- `--strict`: return non-zero exit code when core requirements are missing.

## Checks
- Docker daemon availability (`docker info` via backend check).
- Native tool availability/version detection for:
  - `trivy`
  - `semgrep`
  - `gitleaks`
  - `falco` (optional runtime scanner)
  - `zap-cli` (optional native ZAP mode)

## Exit Codes
- `0`: diagnostics completed successfully.
- `1` with `--strict`: one or more core requirements missing.
  - Core strict set: `docker`, `trivy`, `semgrep`, `gitleaks`.

## Non-goals (current version)
- Does not install missing tools automatically.
- Does not verify network reachability to external registries.
- Does not validate cloud credentials or DefectDojo auth.
