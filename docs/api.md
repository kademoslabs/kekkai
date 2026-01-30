# Kekkai Python API Reference

Use Kekkai programmatically in Python applications.

---

## Installation

```bash
pip install kekkai-cli
```

---

## Quick Start

```python
from pathlib import Path
from kekkai.scanners import ScanContext, TrivyScanner, SemgrepScanner, GitleaksScanner

# Create scan context
ctx = ScanContext(
    repo_path=Path("./my-project"),
    output_dir=Path("./scan-results"),
    run_id="my-scan-001",
    commit_sha="abc123",
    timeout_seconds=900,
)

# Run a scanner
scanner = TrivyScanner()
result = scanner.run(ctx)

# Process results
if result.success:
    for finding in result.findings:
        print(f"{finding.severity}: {finding.title}")
else:
    print(f"Scan failed: {result.error}")
```

---

## Core Components

### ScanContext

Context object passed to all scanners.

```python
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ScanContext:
    repo_path: Path          # Path to repository to scan
    output_dir: Path         # Directory for scan outputs
    run_id: str              # Unique run identifier
    commit_sha: str | None   # Git commit SHA (optional)
    timeout_seconds: int     # Scanner timeout
```

**Example:**

```python
from pathlib import Path
from kekkai.scanners import ScanContext

ctx = ScanContext(
    repo_path=Path("/home/user/myproject"),
    output_dir=Path("/tmp/kekkai-results"),
    run_id="scan-20240115-001",
    commit_sha="a1b2c3d4e5f6",
    timeout_seconds=600,
)
```

### Finding

Represents a security finding from a scanner.

```python
@dataclass
class Finding:
    id: str                  # Unique finding identifier
    title: str               # Finding title/summary
    severity: str            # critical, high, medium, low, info
    description: str         # Detailed description
    file_path: str | None    # Affected file path
    line_start: int | None   # Starting line number
    line_end: int | None     # Ending line number
    scanner: str             # Scanner that found it
    rule_id: str | None      # Scanner rule ID
    cwe: str | None          # CWE identifier
    cvss: float | None       # CVSS score
    remediation: str | None  # Suggested fix
    metadata: dict           # Additional scanner-specific data
```

**Example:**

```python
finding = Finding(
    id="TRIVY-CVE-2023-1234",
    title="Flask Remote Code Execution",
    severity="critical",
    description="Flask < 2.3.0 is vulnerable to RCE",
    file_path="requirements.txt",
    line_start=5,
    line_end=5,
    scanner="trivy",
    rule_id="CVE-2023-1234",
    cwe="CWE-94",
    cvss=9.8,
    remediation="Upgrade Flask to 2.3.0 or later",
    metadata={"package": "flask", "installed_version": "2.0.0"},
)
```

### ScanResult

Result object returned by scanners.

```python
@dataclass
class ScanResult:
    scanner: str             # Scanner name
    success: bool            # Whether scan completed
    findings: list[Finding]  # List of findings
    error: str | None        # Error message if failed
    duration_ms: int         # Execution time in milliseconds
    output_path: Path | None # Path to raw output file
```

---

## Scanners

### Available Scanners

| Scanner | Class | Purpose |
|---------|-------|---------|
| Trivy | `TrivyScanner` | Vulnerability scanning (SCA) |
| Semgrep | `SemgrepScanner` | Code analysis (SAST) |
| Gitleaks | `GitleaksScanner` | Secret detection |
| ZAP | `ZapScanner` | Dynamic analysis (DAST) |
| Falco | `FalcoScanner` | Runtime security |

### Using Scanners

```python
from kekkai.scanners import (
    TrivyScanner,
    SemgrepScanner,
    GitleaksScanner,
    ScanContext,
    SCANNER_REGISTRY,
)

# Direct instantiation
trivy = TrivyScanner()
semgrep = SemgrepScanner()
gitleaks = GitleaksScanner()

# Or use registry
scanner_cls = SCANNER_REGISTRY["trivy"]
scanner = scanner_cls()

# Run scan
result = scanner.run(ctx)
```

### Scanner Registry

```python
from kekkai.scanners import SCANNER_REGISTRY, OPTIONAL_SCANNERS

# Core scanners (always available)
print(SCANNER_REGISTRY.keys())
# dict_keys(['trivy', 'semgrep', 'gitleaks'])

# Optional scanners (require additional setup)
print(OPTIONAL_SCANNERS.keys())
# dict_keys(['zap', 'falco'])
```

### Creating Custom Scanners

```python
from kekkai.scanners.base import Scanner, ScanContext, ScanResult, Finding

class MyScanner(Scanner):
    name = "myscanner"

    def run(self, ctx: ScanContext) -> ScanResult:
        findings = []

        # Your scanning logic here
        # ...

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            error=None,
            duration_ms=1000,
            output_path=None,
        )
```

---

## Policy Evaluation

### PolicyConfig

Configure policy rules for CI mode.

```python
from kekkai.policy import PolicyConfig, evaluate_policy, default_ci_policy

# Default CI policy (fail on critical/high)
policy = default_ci_policy()

# Custom policy
policy = PolicyConfig(
    fail_on_critical=True,
    fail_on_high=True,
    fail_on_medium=False,
    fail_on_low=False,
    fail_on_info=False,
    max_critical=0,   # Any critical = fail
    max_high=5,       # Allow up to 5 high
    max_medium=-1,    # No limit
    max_low=-1,
    max_info=-1,
    max_total=-1,
)
```

### Evaluating Policy

```python
from kekkai.policy import evaluate_policy, PolicyConfig

# Collect findings from scans
all_findings = []
for result in scan_results:
    all_findings.extend(result.findings)

# Evaluate policy
policy = PolicyConfig(fail_on_critical=True, fail_on_high=True)
result = evaluate_policy(all_findings, policy, scan_errors=[])

print(f"Passed: {result.passed}")
print(f"Exit code: {result.exit_code}")
print(f"Violations: {result.violations}")
print(f"Counts: {result.counts}")

# Write JSON output
result.write_json(Path("./policy-result.json"))
```

### PolicyResult

```python
@dataclass
class PolicyResult:
    passed: bool                  # Overall pass/fail
    exit_code: int                # 0=pass, 2=violation, 3=error
    counts: FindingCounts         # Counts by severity
    violations: list[Violation]   # Policy violations
    scan_errors: list[str]        # Scanner errors
```

---

## DefectDojo Integration

### Importing Results

```python
from kekkai.dojo_import import DojoConfig, import_results_to_dojo

# Configure Dojo connection
config = DojoConfig(
    base_url="http://localhost:8080",
    api_key="your-api-key",
    product_name="My Product",
    engagement_name="Security Scan",
)

# Import scan results
import_results = import_results_to_dojo(
    config=config,
    results=scan_results,
    scanners={"trivy": trivy_scanner},
    run_id="scan-001",
    commit_sha="abc123",
)

for result in import_results:
    if result.success:
        print(f"Created: {result.findings_created}, Closed: {result.findings_closed}")
    else:
        print(f"Import failed: {result.error}")
```

### Managing Dojo Stack

```python
from kekkai import dojo

# Start DefectDojo
env = dojo.compose_up(
    compose_root=dojo.compose_dir(),
    project_name="kekkai-dojo",
    port=8080,
    tls_port=8443,
    wait=True,
    open_browser=False,
)

print(f"Admin password: {env['DD_ADMIN_PASSWORD']}")

# Check status
statuses = dojo.compose_status(
    compose_root=dojo.compose_dir(),
    project_name="kekkai-dojo",
)
for s in statuses:
    print(f"{s.name}: {s.state} ({s.health})")

# Stop and clean up
dojo.compose_down(
    compose_root=dojo.compose_dir(),
    project_name="kekkai-dojo",
)
```

---

## ThreatFlow API

### Running Threat Analysis

```python
from pathlib import Path
from kekkai.threatflow import ThreatFlow, ThreatFlowConfig

# Configure ThreatFlow
config = ThreatFlowConfig(
    model_mode="local",          # local, openai, anthropic, mock
    model_path="/path/to/model.gguf",
    max_files=500,
    timeout_seconds=300,
    redact_secrets=True,
    sanitize_content=True,
)

# Run analysis
tf = ThreatFlow(config=config)
result = tf.analyze(
    repo_path=Path("./my-project"),
    output_dir=Path("./threat-model"),
)

if result.success:
    print(f"Files processed: {result.files_processed}")
    print(f"Threats found: {len(result.artifacts.threats)}")

    # Access threat details
    for threat in result.artifacts.threats:
        print(f"- {threat.title} ({threat.risk_level})")
else:
    print(f"Analysis failed: {result.error}")
```

---

## GitHub Integration

### Posting PR Comments

```python
from kekkai.github import GitHubConfig, post_pr_comments

config = GitHubConfig(
    token="ghp_xxxxx",
    owner="myorg",
    repo="myrepo",
    pr_number=123,
)

result = post_pr_comments(
    findings=all_findings,
    config=config,
    max_comments=50,
    min_severity="medium",
)

if result.success:
    print(f"Posted {result.comments_posted} comments")
    print(f"Review URL: {result.review_url}")
else:
    print(f"Errors: {result.errors}")
```

---

## Configuration API

### Loading Configuration

```python
from pathlib import Path
from kekkai.config import load_config, ConfigOverrides

# Load from default path
config = load_config(Path("~/.config/kekkai/config.toml").expanduser())

# Load with overrides
overrides = ConfigOverrides(
    repo_path=Path("./my-project"),
    timeout_seconds=1200,
)
config = load_config(
    Path("~/.config/kekkai/config.toml").expanduser(),
    overrides=overrides,
)

# Access configuration
print(f"Repo: {config.repo_path}")
print(f"Timeout: {config.timeout_seconds}")
print(f"Scanners: {config.scanners}")
```

---

## Utility Functions

### Finding Deduplication

```python
from kekkai.scanners import dedupe_findings

# Remove duplicate findings
unique_findings = dedupe_findings(all_findings)
```

### Path Utilities

```python
from kekkai.paths import app_base_dir, config_path, ensure_dir

# Get base directory
base = app_base_dir()  # ~/.kekkai

# Get config path
cfg = config_path()  # ~/.config/kekkai/config.toml

# Ensure directory exists
ensure_dir(Path("./output"))
```

---

## Error Handling

```python
from kekkai.scanners import ScanContext, TrivyScanner

try:
    scanner = TrivyScanner()
    result = scanner.run(ctx)

    if not result.success:
        # Scanner completed but with errors
        print(f"Scan error: {result.error}")
    else:
        # Process findings
        for f in result.findings:
            process_finding(f)

except RuntimeError as e:
    # Scanner failed to execute
    print(f"Scanner failed: {e}")
except TimeoutError as e:
    # Scanner timed out
    print(f"Scanner timeout: {e}")
```

---

## Complete Example

```python
#!/usr/bin/env python3
"""Complete Kekkai scanning pipeline example."""

from pathlib import Path
from kekkai.scanners import (
    ScanContext,
    TrivyScanner,
    SemgrepScanner,
    GitleaksScanner,
    dedupe_findings,
)
from kekkai.policy import PolicyConfig, evaluate_policy

def main():
    # Setup
    repo_path = Path("./my-project")
    output_dir = Path("./scan-results")
    output_dir.mkdir(exist_ok=True)

    ctx = ScanContext(
        repo_path=repo_path,
        output_dir=output_dir,
        run_id="example-scan",
        commit_sha=None,
        timeout_seconds=600,
    )

    # Run scanners
    scanners = [TrivyScanner(), SemgrepScanner(), GitleaksScanner()]
    all_findings = []

    for scanner in scanners:
        print(f"Running {scanner.name}...")
        result = scanner.run(ctx)

        if result.success:
            findings = dedupe_findings(result.findings)
            all_findings.extend(findings)
            print(f"  Found {len(findings)} findings")
        else:
            print(f"  Failed: {result.error}")

    # Evaluate policy
    policy = PolicyConfig(
        fail_on_critical=True,
        fail_on_high=True,
    )
    policy_result = evaluate_policy(all_findings, policy, [])

    # Report
    print(f"\nTotal findings: {len(all_findings)}")
    print(f"Policy passed: {policy_result.passed}")

    if not policy_result.passed:
        print("Violations:")
        for v in policy_result.violations:
            print(f"  - {v.message}")
        return 2

    return 0

if __name__ == "__main__":
    exit(main())
```

---

## See Also

- [CLI Reference](cli-reference.md) - Command-line usage
- [Configuration Guide](configuration.md) - Config options
- [CI Integration Guide](ci-integration.md) - CI/CD setup
