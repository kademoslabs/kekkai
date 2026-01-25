# CI Mode: Policy Enforcement

Use `kekkai scan --ci` to enforce security policies in CI/CD pipelines.

## Quick Start

```bash
# Run scan with CI mode (fails on critical/high findings)
kekkai scan --ci --scanners trivy,semgrep,gitleaks

# Custom severity threshold (fail on medium or higher)
kekkai scan --fail-on medium --scanners trivy

# Output results to custom location
kekkai scan --ci --output /tmp/policy-result.json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Pass - no policy violations |
| 1    | Fail - policy violations found |
| 2    | Error - scan or configuration error |

## Policy Configuration

### CLI Options

- `--ci` - Enable CI mode with default policy (fail on critical/high)
- `--fail-on <severity>` - Fail on specified severity and above
- `--output <path>` - Write policy result JSON to custom path

### Config File

Add to `kekkai.toml`:

```toml
[policy]
fail_on_critical = true
fail_on_high = true
fail_on_medium = false
fail_on_low = false
fail_on_info = false
max_critical = 0
max_high = 0
max_medium = -1  # -1 = unlimited
max_total = -1   # total findings limit
```

### Severity Cascade

When using `--fail-on`, higher severities are automatically included:

| Flag | Fails on |
|------|----------|
| `--fail-on critical` | Critical only |
| `--fail-on high` | Critical, High |
| `--fail-on medium` | Critical, High, Medium |
| `--fail-on low` | Critical, High, Medium, Low |
| `--fail-on info` | All severities |

## Output Format

The policy result JSON contains:

```json
{
  "passed": false,
  "exit_code": 1,
  "violations": [
    {
      "severity": "critical",
      "count": 2,
      "threshold": 0,
      "message": "Found 2 critical findings (max allowed: 0)"
    }
  ],
  "counts": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 3,
    "info": 1,
    "unknown": 0
  },
  "scan_errors": []
}
```

## CI/CD Examples

### GitHub Actions

```yaml
- name: Run Kekkai Scan
  run: kekkai scan --ci --scanners trivy,semgrep,gitleaks
  continue-on-error: false
```

### GitLab CI

```yaml
security-scan:
  script:
    - kekkai scan --ci --scanners trivy,semgrep,gitleaks
  allow_failure: false
```

### CircleCI

```yaml
- run:
    name: Security Scan
    command: kekkai scan --ci --scanners trivy,semgrep,gitleaks
```

### Docker in CI (No Python Installation Required)

For environments without Python, use the Docker wrapper:

**GitHub Actions:**
```yaml
- name: Build Kekkai Image
  run: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .

- name: Security Scan
  run: |
    docker run --rm -v "$PWD:/workspace:ro" -w /workspace \
      kademoslabs/kekkai:latest scan --repo /workspace --ci
```

**GitLab CI:**
```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .
    - docker run --rm -v "$CI_PROJECT_DIR:/workspace:ro" -w /workspace
        kademoslabs/kekkai:latest scan --repo /workspace --ci
```

**CircleCI:**
```yaml
- setup_remote_docker
- run:
    name: Build Kekkai Image
    command: docker build -t kademoslabs/kekkai:latest -f apps/kekkai/Dockerfile .
- run:
    name: Security Scan
    command: |
      docker run --rm -v "$PWD:/workspace:ro" -w /workspace \
        kademoslabs/kekkai:latest scan --repo /workspace --ci
```

See [Docker Usage Guide](docker-usage.md) for security model and advanced usage.

## Best Practices

1. **Start strict, loosen if needed** - Begin with `--ci` (critical/high only)
2. **Use consistent policies** - Configure in `kekkai.toml` for reproducibility
3. **Review violations** - Check `policy-result.json` for details
4. **Don't ignore scan errors** - Exit code 2 indicates something is broken
