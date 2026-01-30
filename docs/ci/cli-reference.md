# Kekkai CLI Reference

Complete command reference for the Kekkai CLI.

---

## Global Options

```
kekkai --version    Show version number
kekkai --help       Show help message
```

---

## Commands

### `kekkai` (no arguments)

When run without arguments, Kekkai either initializes a new configuration (if none exists) or displays the dashboard.

```bash
kekkai
```

---

### `kekkai init`

Initialize Kekkai configuration and directories.

```bash
kekkai init [OPTIONS]
```

#### Options

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to config file (default: `~/.config/kekkai/config.toml`) |
| `--force` | Overwrite existing configuration |

#### Examples

```bash
# Initialize with defaults
kekkai init

# Initialize with custom config path
kekkai init --config ./my-kekkai.toml

# Reinitialize (overwrite existing)
kekkai init --force
```

---

### `kekkai scan`

Run security scanners on a repository.

```bash
kekkai scan [OPTIONS]
```

#### Core Options

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to config file |
| `--repo PATH` | Path to repository to scan (default: current directory) |
| `--run-dir PATH` | Override run output directory |
| `--run-id ID` | Override run ID (3-64 chars, alphanumeric with `._-`) |
| `--scanners LIST` | Comma-separated list of scanners (e.g., `trivy,semgrep,gitleaks`) |

#### DefectDojo Integration

| Flag | Description |
|------|-------------|
| `--import-dojo` | Import results to local DefectDojo |
| `--dojo-url URL` | DefectDojo base URL |
| `--dojo-api-key KEY` | DefectDojo API key |

#### ZAP DAST Scanner

| Flag | Description |
|------|-------------|
| `--target-url URL` | Target URL for ZAP DAST scanning (required if `zap` in scanners) |
| `--allow-private-ips` | Allow ZAP to scan private/internal IPs (**DANGEROUS**) |

#### Falco Runtime Security

| Flag | Description |
|------|-------------|
| `--enable-falco` | Enable Falco runtime security (Linux-only, experimental) |

#### CI Mode & Policy Enforcement

| Flag | Description |
|------|-------------|
| `--ci` | Enable CI mode: fail on policy violations (default: critical/high) |
| `--fail-on LEVELS` | Severity levels to fail on (e.g., `critical,high` or `medium`) |
| `--output PATH` | Path for policy result JSON output |

#### GitHub PR Comments

| Flag | Description |
|------|-------------|
| `--pr-comment` | Post findings as GitHub PR review comments |
| `--github-token TOKEN` | GitHub token (or set `GITHUB_TOKEN` env var) |
| `--pr-number NUM` | PR number to comment on (auto-detected in GitHub Actions) |
| `--github-repo REPO` | GitHub repository (`owner/repo`, auto-detected in GitHub Actions) |
| `--max-comments NUM` | Maximum PR comments to post (default: 50) |
| `--comment-severity LEVEL` | Minimum severity for PR comments (default: medium) |

#### Examples

```bash
# Basic scan with default scanners
kekkai scan

# Scan specific repository
kekkai scan --repo ./my-project

# Run specific scanners only
kekkai scan --scanners trivy,semgrep

# CI mode with custom failure threshold
kekkai scan --ci --fail-on critical,high,medium

# Scan and post PR comments
kekkai scan --pr-comment --github-token "$GITHUB_TOKEN"

# Import results to DefectDojo
kekkai scan --import-dojo --dojo-url http://localhost:8080 --dojo-api-key "$DOJO_KEY"

# ZAP DAST scan
kekkai scan --scanners zap --target-url https://staging.example.com
```

---

### `kekkai dojo`

Manage local DefectDojo stack.

#### `kekkai dojo up`

Start the local DefectDojo stack.

```bash
kekkai dojo up [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--compose-dir PATH` | Directory for compose files |
| `--project-name NAME` | Docker Compose project name |
| `--port PORT` | HTTP port for the UI (default: 8080) |
| `--tls-port PORT` | HTTPS port for the UI (default: 8443) |
| `--wait` | Wait for UI readiness before returning |
| `--open` | Open the UI in a browser after starting |

#### `kekkai dojo down`

Stop the local DefectDojo stack and remove volumes.

```bash
kekkai dojo down [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--compose-dir PATH` | Directory for compose files |
| `--project-name NAME` | Docker Compose project name |

#### `kekkai dojo status`

Show stack status for all services.

```bash
kekkai dojo status [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--compose-dir PATH` | Directory for compose files |
| `--project-name NAME` | Docker Compose project name |

#### `kekkai dojo open`

Open the local DefectDojo UI in a browser.

```bash
kekkai dojo open [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--compose-dir PATH` | Directory for compose files |
| `--port PORT` | HTTP port for the UI |

#### Examples

```bash
# Start DefectDojo and wait for readiness
kekkai dojo up --wait

# Start on custom port
kekkai dojo up --port 9000 --wait --open

# Check service status
kekkai dojo status

# Stop and clean up
kekkai dojo down
```

---

### `kekkai threatflow`

Generate AI-powered threat model for a repository.

```bash
kekkai threatflow [OPTIONS]
```

#### Options

| Flag | Description |
|------|-------------|
| `--repo PATH` | Path to repository to analyze |
| `--output-dir PATH` | Output directory for artifacts |
| `--model-mode MODE` | LLM backend: `local` (default), `openai`, `anthropic`, or `mock` |
| `--model-path PATH` | Path to local model file (for local mode) |
| `--api-key KEY` | API key for remote LLM (prefer env var) |
| `--model-name NAME` | Specific model name to use |
| `--max-files NUM` | Maximum files to analyze (default: 500) |
| `--timeout SECS` | Timeout in seconds for model calls (default: 300) |
| `--no-redact` | Disable secret redaction (**NOT RECOMMENDED**) |
| `--no-sanitize` | Disable prompt injection sanitization (**NOT RECOMMENDED**) |

#### Examples

```bash
# Analyze current directory with local model
kekkai threatflow

# Analyze specific repo with OpenAI
kekkai threatflow --repo ./my-app --model-mode openai --api-key "$OPENAI_API_KEY"

# Use Anthropic Claude
kekkai threatflow --model-mode anthropic --api-key "$ANTHROPIC_API_KEY"

# Custom output directory
kekkai threatflow --output-dir ./threat-reports
```

#### Security Notes

- **Local mode** (default): Code never leaves your machine
- **Remote modes** (openai, anthropic): Code is sent to external APIs
- Secret redaction is enabled by default to prevent credential leakage
- Prompt sanitization prevents injection attacks in LLM prompts

---

### `kekkai triage`

Interactively triage security findings using a terminal UI.

```bash
kekkai triage [OPTIONS]
```

#### Options

| Flag | Description |
|------|-------------|
| `--input PATH` | Path to findings JSON file (from scan output) |
| `--output PATH` | Path for `.kekkaiignore` output (default: `.kekkaiignore`) |

#### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` / `↓` | Move to next finding |
| `k` / `↑` | Move to previous finding |
| `f` | Mark as false positive |
| `c` | Mark as confirmed |
| `d` | Mark as deferred |
| `Ctrl+S` | Save decisions |
| `q` | Quit |

#### Examples

```bash
# Triage findings from latest scan
kekkai triage --input ~/.kekkai/runs/latest/findings.json

# Custom output path
kekkai triage --input ./findings.json --output ./my-ignores.txt
```

---

### `kekkai fix`

Generate AI-powered code fixes for security findings.

```bash
kekkai fix [OPTIONS]
```

#### Options

| Flag | Description |
|------|-------------|
| `--input PATH` | Path to scan results JSON (Semgrep format) [required] |
| `--repo PATH` | Repository path (default: current directory) |
| `--output-dir PATH` | Output directory for diffs and audit log |
| `--dry-run` | Preview fixes without applying (default: True) |
| `--apply` | Apply fixes to files (requires explicit flag) |
| `--model-mode MODE` | LLM backend: local, openai, anthropic, mock |
| `--api-key KEY` | API key for remote LLM (prefer `KEKKAI_FIX_API_KEY` env var) |
| `--model-name NAME` | Specific model name to use |
| `--max-fixes N` | Maximum fixes per run (default: 10) |
| `--timeout SECONDS` | LLM call timeout (default: 120) |
| `--no-backup` | Disable backup creation when applying |

#### Examples

```bash
# Preview fixes (dry run)
kekkai fix --input ./semgrep-results.json --repo ./my-app

# Apply fixes with backups
kekkai fix --input ./semgrep-results.json --repo ./my-app --apply

# Use OpenAI for fix generation
export KEKKAI_FIX_API_KEY=sk-...
kekkai fix --input ./results.json --model-mode openai --model-name gpt-4o

# Limit number of fixes
kekkai fix --input ./results.json --max-fixes 5
```

See [Fix Engine Guide](../triage/fix-engine.md) for detailed documentation.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error or policy passed with warnings |
| `2` | Policy violation (findings exceed thresholds) |
| `3` | Scan error (scanner failed to execute) |

---

## Environment Variables

All configuration options can be set via environment variables with the `KEKKAI_` prefix.

| Variable | Description |
|----------|-------------|
| `KEKKAI_REPO_PATH` | Default repository path |
| `KEKKAI_RUN_BASE_DIR` | Base directory for run outputs |
| `KEKKAI_RUN_DIR` | Override specific run directory |
| `KEKKAI_RUN_ID` | Override run ID |
| `KEKKAI_TIMEOUT_SECONDS` | Scanner timeout |
| `KEKKAI_DOJO_URL` | DefectDojo base URL |
| `KEKKAI_DOJO_API_KEY` | DefectDojo API key |
| `KEKKAI_DOJO_COMPOSE_DIR` | DefectDojo compose directory |
| `KEKKAI_DOJO_PROJECT_NAME` | Docker Compose project name |
| `KEKKAI_DOJO_PORT` | DefectDojo HTTP port |
| `KEKKAI_DOJO_TLS_PORT` | DefectDojo HTTPS port |
| `KEKKAI_ZAP_TARGET_URL` | ZAP target URL |
| `KEKKAI_ENABLE_FALCO` | Enable Falco (`1` to enable) |
| `KEKKAI_THREATFLOW_MODE` | ThreatFlow model mode |
| `KEKKAI_THREATFLOW_MODEL_PATH` | ThreatFlow local model path |
| `KEKKAI_THREATFLOW_API_KEY` | ThreatFlow API key |
| `KEKKAI_THREATFLOW_MODEL_NAME` | ThreatFlow model name |
| `KEKKAI_FIX_API_KEY` | API key for fix engine LLM |
| `GITHUB_TOKEN` | GitHub token for PR comments |
| `GITHUB_REPOSITORY` | GitHub repository (auto-detected in Actions) |
| `GITHUB_EVENT_PATH` | GitHub event path (auto-detected in Actions) |

See [Configuration Guide](../config/configuration.md) for complete configuration reference.

---

## See Also

- [Configuration Guide](../config/configuration.md) - Config file format and options
- [CI Integration Guide](ci-integration.md) - CI/CD setup
- [Troubleshooting](../troubleshooting/troubleshooting.md) - Common issues and solutions
