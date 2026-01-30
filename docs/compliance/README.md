# Compliance Mapping & Reporting

Kekkai maps security findings to compliance framework controls and generates audit-ready reports.

## Supported Frameworks

| Framework | Version | Controls Mapped |
|-----------|---------|-----------------|
| PCI-DSS | v4.0 | 17 requirements |
| SOC 2 | Type II | 15 criteria |
| OWASP | Top 10 2025 | 10 categories |
| OWASP Agentic AI | Top 10 2025 | 10 categories |
| HIPAA | Security Rule | 15 safeguards |

## Quick Start

```bash
# Run a scan
kekkai scan --repo ./my-app --scanners trivy,semgrep,gitleaks

# Generate HTML report with compliance mapping
kekkai report --input ~/.kekkai/runs/run-YYYYMMDD-HHMMSS/findings.json --format html

# Generate all report formats
kekkai report --input ./scan-results.json --format all --output ./reports/
```

## CLI Reference

```bash
kekkai report [OPTIONS]

Options:
  --input PATH           Path to scan results JSON (required)
  --output PATH          Output directory (default: current directory)
  --format FORMAT        Report format: html, pdf, compliance, json, all (default: html)
  --frameworks LIST      Comma-separated frameworks (default: all)
  --min-severity LEVEL   Minimum severity: critical,high,medium,low,info (default: info)
  --title TEXT           Report title
  --organization TEXT    Organization name for header
  --project TEXT         Project name for header
  --no-executive-summary Exclude executive summary section
  --no-timeline          Exclude remediation timeline section
```

## Report Formats

### HTML Report (`--format html`)

Full security report with:
- Executive summary with risk score
- Severity breakdown
- Compliance framework impact
- Findings detail with context
- Remediation timeline

### PDF Report (`--format pdf`)

Same content as HTML, formatted for printing/distribution.

> **Note:** Requires `weasyprint` package. Falls back to HTML if not available.
> Install with: `pip install weasyprint`

### Compliance Matrix (`--format compliance`)

Focused compliance view showing:
- Control-by-control status (Compliant/At Risk/Non-Compliant)
- Findings count per control
- Severity breakdown per control
- Framework coverage summary

### JSON Report (`--format json`)

Machine-readable format for automation:

```json
{
  "metadata": {
    "generated_at": "2026-01-30T12:00:00Z",
    "generator_version": "1.0.5",
    "findings_count": 42,
    "content_hash": "abc123..."
  },
  "executive_summary": {
    "total_findings": 42,
    "risk_level": "High",
    "risk_percentage": 65
  },
  "compliance_summary": {
    "PCI-DSS": 8,
    "SOC2": 6,
    "OWASP": 5,
    "OWASP-Agentic": 2,
    "HIPAA": 4
  },
  "findings": [...]
}
```

## Compliance Framework Details

### PCI-DSS v4.0

Mapped requirements include:
- **6.2.4** - Software engineering techniques (injection prevention)
- **6.3.1** - Security vulnerability management (CVEs)
- **8.3** - Strong authentication requirements
- **3.5/4.2** - Cryptographic protection

### SOC 2 Trust Services Criteria

Mapped criteria include:
- **CC6.1** - Logical and physical access controls
- **CC6.6** - Security events detection
- **CC7.1** - Vulnerability management
- **PI1.2** - Input validation

### OWASP Top 10 2025

Updated from 2021 with significant changes. All ten categories are mapped:

| ID | Name | Notes |
|----|------|-------|
| A01:2025 | Broken Access Control | Now includes SSRF |
| A02:2025 | Security Misconfiguration | Moved up from #5 |
| A03:2025 | Software Supply Chain Failures | **NEW** - replaces Vulnerable Components |
| A04:2025 | Cryptographic Failures | Moved down from #2 |
| A05:2025 | Injection | Moved down from #3 |
| A06:2025 | Insecure Design | Moved down from #4 |
| A07:2025 | Authentication Failures | Renamed |
| A08:2025 | Software or Data Integrity Failures | Stable |
| A09:2025 | Security Logging and Alerting Failures | Minor rename |
| A10:2025 | Mishandling of Exceptional Conditions | **NEW** |

**Key changes from 2021:**
- SSRF (old A10) merged into Broken Access Control (A01)
- "Vulnerable Components" expanded to "Software Supply Chain Failures" (A03)
- New category for error/exception handling (A10)

### OWASP Agentic AI Top 10 (December 2025)

Security risks specific to autonomous AI agents. All ten categories are mapped:

| ID | Name | Description |
|----|------|-------------|
| AA01:2025 | Agent Goal Hijack | Attackers alter agent objectives via prompt injection |
| AA02:2025 | Tool Misuse & Exploitation | Agents use tools in unsafe/unintended ways |
| AA03:2025 | Identity & Privilege Abuse | Agents inherit/escalate excessive privileges |
| AA04:2025 | Agentic Supply Chain Vulnerabilities | Compromised plugins, external agents |
| AA05:2025 | Unexpected Code Execution | Agents generate/execute code unsafely |
| AA06:2025 | Memory & Context Poisoning | Attackers corrupt agent memory systems |
| AA07:2025 | Insecure Inter-Agent Communication | Spoofing/tampering in multi-agent systems |
| AA08:2025 | Cascading Failures | Small errors propagate to system-wide failures |
| AA09:2025 | Human-Agent Trust Exploitation | Users over-trust agent recommendations |
| AA10:2025 | Rogue Agents | Compromised agents act maliciously |

> **Note:** Agentic AI mappings apply to findings from AI/LLM scanners or findings
> with AI-related content (prompt injection, LLM, agent, etc.).

### HIPAA Security Rule

Technical safeguards mapped:
- **164.312(a)(1)** - Access Control
- **164.312(a)(2)(iv)** - Encryption and Decryption
- **164.312(b)** - Audit Controls
- **164.312(d)** - Person/Entity Authentication
- **164.312(e)(1)** - Transmission Security

## Mapping Methodology

Findings are mapped using:

1. **CWE ID** (Primary) - Direct mapping from CWE to framework controls
2. **Rule ID Patterns** - Scanner rule patterns matched to controls
3. **CVE Presence** - CVEs map to supply chain/vulnerability management controls
4. **Scanner Type** - Agentic AI mappings filtered by scanner type

### Example Mapping Flow

```
Finding: SQL Injection (CWE-89)
    ↓
OWASP: A05:2025 (Injection)
PCI-DSS: 6.2.4 (Software engineering techniques)
SOC2: PI1.2 (Input Validation)
HIPAA: N/A (no direct mapping)
OWASP-Agentic: N/A (not AI-related)
```

```
Finding: Prompt Injection (scanner: llm)
    ↓
OWASP: A05:2025 (Injection)
OWASP-Agentic: AA01:2025 (Agent Goal Hijack)
```

## Disclaimer

> **Important:** This compliance mapping is advisory only. It does not constitute a compliance certification or audit opinion. Organizations must conduct formal assessments with qualified auditors for official compliance determinations.

## Examples

### Generate report with custom title

```bash
kekkai report \
  --input ./results.json \
  --format html \
  --title "Q1 2026 Security Assessment" \
  --organization "Acme Corp" \
  --project "payment-service"
```

### Filter to high severity only

```bash
kekkai report \
  --input ./results.json \
  --format compliance \
  --min-severity high \
  --frameworks PCI-DSS,OWASP
```

### Generate JSON for CI/CD integration

```bash
kekkai report \
  --input ./results.json \
  --format json \
  --output ./artifacts/

# Use in CI pipeline
jq '.executive_summary.risk_level' ./artifacts/report.json
```

## Programmatic Usage

```python
from kekkai.report import generate_report, ReportConfig, ReportFormat
from kekkai.scanners.base import Finding, Severity

findings = [
    Finding(
        scanner="semgrep",
        title="SQL Injection",
        severity=Severity.HIGH,
        description="SQL injection vulnerability",
        cwe="CWE-89",
    ),
]

config = ReportConfig(
    formats=[ReportFormat.HTML, ReportFormat.JSON],
    frameworks=["PCI-DSS", "OWASP", "OWASP-Agentic"],
    min_severity="medium",
)

result = generate_report(findings, output_dir=Path("./reports"), config=config)

print(f"Generated {len(result.output_files)} files")
for path in result.output_files:
    print(f"  - {path}")
```

## References

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [OWASP Agentic AI Top 10](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [PCI-DSS v4.0](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/resources/landing/trust-services-criteria)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
