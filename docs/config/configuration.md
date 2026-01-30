# Kekkai Configuration Guide

Complete reference for configuring Kekkai via config files and environment variables.

---

## Configuration Precedence

Kekkai loads configuration in the following order (later sources override earlier):

1. **Default values** - Built-in defaults
2. **Config file** - `~/.config/kekkai/config.toml` (or custom path)
3. **Environment variables** - `KEKKAI_*` prefixed variables
4. **CLI flags** - Command-line arguments

---

## Config File Location

By default, Kekkai looks for configuration at:

- **Linux/macOS**: `~/.config/kekkai/config.toml`
- **Windows**: `%APPDATA%\kekkai\config.toml`

Use `--config PATH` to specify a custom location.

---

## Config File Format

Kekkai uses TOML format for configuration.

### Minimal Configuration

```toml
# ~/.config/kekkai/config.toml

repo_path = "."
run_base_dir = "~/.kekkai/runs"
timeout_seconds = 900
env_allowlist = ["PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE"]
```

### Complete Configuration

```toml
# Kekkai Configuration
# All values can be overridden via environment variables (KEKKAI_*) or CLI flags.

# Path to repository to scan (default: current directory)
repo_path = "."

# Base directory for scan outputs
run_base_dir = "~/.kekkai/runs"

# Timeout for scanner execution (seconds)
timeout_seconds = 900

# Environment variables passed to scanners
env_allowlist = ["PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE"]

# Scanners to run (default: all three)
scanners = ["trivy", "semgrep", "gitleaks"]

# DefectDojo integration
[dojo]
enabled = false
base_url = "http://localhost:8080"
api_key = ""  # Use KEKKAI_DOJO_API_KEY env var instead
product_name = "Kekkai Scans"
engagement_name = "Default Engagement"

# ZAP DAST scanner
[zap]
enabled = false
target_url = ""  # Required when enabled
allow_private_ips = false  # DANGEROUS: only enable for internal testing
allowed_domains = []
timeout_seconds = 900

# Falco runtime security (Linux-only, experimental)
[falco]
enabled = false
rules_file = ""
timeout_seconds = 300

# Policy enforcement for CI mode
[policy]
fail_on_critical = true
fail_on_high = true
fail_on_medium = false
fail_on_low = false
fail_on_info = false
max_critical = 0   # Fail if any critical findings
max_high = 0       # Fail if any high findings
max_medium = -1    # -1 = no limit
max_low = -1
max_info = -1
max_total = -1

# ThreatFlow threat modeling
[threatflow]
enabled = false
model_mode = "local"  # local, openai, anthropic, mock
model_path = ""       # Path to local model
api_key = ""          # Use KEKKAI_THREATFLOW_API_KEY env var instead
api_base = ""         # Custom API endpoint
model_name = ""       # Specific model name
max_files = 500
timeout_seconds = 300
redact_secrets = true
sanitize_content = true
warn_on_injection = true

# Pipeline steps (custom pre-scan commands)
# [[pipeline]]
# name = "lint"
# args = ["npm", "run", "lint"]
```

---

## Configuration Sections

### Core Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `repo_path` | string | `"."` | Path to repository to scan |
| `run_base_dir` | string | `~/.kekkai/runs` | Base directory for scan outputs |
| `timeout_seconds` | int | `900` | Timeout for scanner execution |
| `env_allowlist` | list | See below | Environment variables passed to scanners |
| `scanners` | list | `["trivy", "semgrep", "gitleaks"]` | Scanners to run |

**Default env_allowlist:**
```toml
env_allowlist = ["PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE"]
```

### DefectDojo Settings `[dojo]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable automatic import |
| `base_url` | string | `http://localhost:8080` | DefectDojo URL |
| `api_key` | string | `""` | API key (use env var) |
| `product_name` | string | `Kekkai Scans` | Product name in DefectDojo |
| `engagement_name` | string | `Default Engagement` | Engagement name |

### ZAP Settings `[zap]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable ZAP scanner |
| `target_url` | string | `""` | Target URL (required) |
| `allow_private_ips` | bool | `false` | Allow scanning private IPs |
| `allowed_domains` | list | `[]` | Allowed domains for scanning |
| `timeout_seconds` | int | `900` | ZAP scan timeout |

### Falco Settings `[falco]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Falco (Linux-only) |
| `rules_file` | string | `""` | Custom rules file path |
| `timeout_seconds` | int | `300` | Falco timeout |

### Policy Settings `[policy]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `fail_on_critical` | bool | `true` | Fail on critical findings |
| `fail_on_high` | bool | `true` | Fail on high findings |
| `fail_on_medium` | bool | `false` | Fail on medium findings |
| `fail_on_low` | bool | `false` | Fail on low findings |
| `fail_on_info` | bool | `false` | Fail on info findings |
| `max_critical` | int | `0` | Max critical findings allowed |
| `max_high` | int | `0` | Max high findings allowed |
| `max_medium` | int | `-1` | Max medium findings (-1 = unlimited) |
| `max_low` | int | `-1` | Max low findings (-1 = unlimited) |
| `max_info` | int | `-1` | Max info findings (-1 = unlimited) |
| `max_total` | int | `-1` | Max total findings (-1 = unlimited) |

### ThreatFlow Settings `[threatflow]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable ThreatFlow |
| `model_mode` | string | `local` | LLM backend mode |
| `model_path` | string | `""` | Path to local model |
| `api_key` | string | `""` | API key for remote LLM |
| `api_base` | string | `""` | Custom API endpoint |
| `model_name` | string | `""` | Specific model name |
| `max_files` | int | `500` | Max files to analyze |
| `timeout_seconds` | int | `300` | Model call timeout |
| `redact_secrets` | bool | `true` | Redact secrets before LLM |
| `sanitize_content` | bool | `true` | Sanitize prompt injection |
| `warn_on_injection` | bool | `true` | Warn on injection patterns |

### Pipeline Steps `[[pipeline]]`

Run custom commands before scanning:

```toml
[[pipeline]]
name = "install"
args = ["npm", "install"]

[[pipeline]]
name = "build"
args = ["npm", "run", "build"]
```

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Step name for logging |
| `args` | list | Command and arguments |

---

## Environment Variables

All configuration can be set via environment variables with the `KEKKAI_` prefix.

### Core Variables

| Variable | Config Key | Description |
|----------|------------|-------------|
| `KEKKAI_REPO_PATH` | `repo_path` | Repository path |
| `KEKKAI_RUN_BASE_DIR` | `run_base_dir` | Run output base directory |
| `KEKKAI_RUN_DIR` | - | Override specific run directory |
| `KEKKAI_RUN_ID` | - | Override run ID |
| `KEKKAI_TIMEOUT_SECONDS` | `timeout_seconds` | Scanner timeout |
| `KEKKAI_ENV_ALLOWLIST` | `env_allowlist` | Comma-separated list |

### DefectDojo Variables

| Variable | Description |
|----------|-------------|
| `KEKKAI_DOJO_URL` | DefectDojo base URL |
| `KEKKAI_DOJO_API_KEY` | DefectDojo API key |
| `KEKKAI_DOJO_COMPOSE_DIR` | Compose files directory |
| `KEKKAI_DOJO_PROJECT_NAME` | Docker Compose project name |
| `KEKKAI_DOJO_PORT` | HTTP port |
| `KEKKAI_DOJO_TLS_PORT` | HTTPS port |

### Scanner Variables

| Variable | Description |
|----------|-------------|
| `KEKKAI_ZAP_TARGET_URL` | ZAP target URL |
| `KEKKAI_ENABLE_FALCO` | Enable Falco (`1` to enable) |

### ThreatFlow Variables

| Variable | Description |
|----------|-------------|
| `KEKKAI_THREATFLOW_MODE` | Model mode |
| `KEKKAI_THREATFLOW_MODEL_PATH` | Local model path |
| `KEKKAI_THREATFLOW_API_KEY` | API key for remote LLM |
| `KEKKAI_THREATFLOW_MODEL_NAME` | Model name |

### GitHub Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub token for PR comments |
| `GITHUB_REPOSITORY` | Repository (owner/repo) |
| `GITHUB_EVENT_PATH` | Event JSON path (Actions) |

---

## Example Configurations

### CI/CD Configuration

```toml
# Strict CI configuration
repo_path = "."
timeout_seconds = 600
scanners = ["trivy", "semgrep", "gitleaks"]

[policy]
fail_on_critical = true
fail_on_high = true
fail_on_medium = true
fail_on_low = false
max_critical = 0
max_high = 0
max_medium = 5
```

### Development Configuration

```toml
# Local development with DefectDojo
repo_path = "."
run_base_dir = "./scan-results"
timeout_seconds = 900

[dojo]
enabled = true
base_url = "http://localhost:8080"
product_name = "My Project"

[policy]
fail_on_critical = true
fail_on_high = false
fail_on_medium = false
```

### Enterprise Configuration

```toml
# Enterprise with all features
repo_path = "."
timeout_seconds = 1200
scanners = ["trivy", "semgrep", "gitleaks", "zap"]

[dojo]
enabled = true
base_url = "https://dojo.internal.company.com"
product_name = "Enterprise App"

[zap]
enabled = true
target_url = "https://staging.company.com"
allowed_domains = ["staging.company.com", "api.staging.company.com"]

[policy]
fail_on_critical = true
fail_on_high = true
fail_on_medium = true
max_total = 100

[threatflow]
enabled = true
model_mode = "local"
redact_secrets = true
```

---

## Security Best Practices

1. **Never commit API keys** - Use environment variables for secrets
2. **Use local models when possible** - Prevents code from leaving your network
3. **Keep secret redaction enabled** - Prevents accidental credential exposure
4. **Review policy settings** - Ensure thresholds match your security requirements
5. **Restrict env_allowlist** - Only pass necessary environment variables

---

## See Also

- [CLI Reference](../ci/cli-reference.md) - Command-line options
- [CI Integration Guide](../ci/ci-integration.md) - CI/CD setup
- [Troubleshooting](../troubleshooting/troubleshooting.md) - Common issues
