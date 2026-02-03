<p align="center">
  <img src="https://raw.githubusercontent.com/kademoslabs/assets/main/logos/kekkai-slim.png" alt="Kekkai CLI Logo" width="250"/>
</p>

<p align="center"><strong>Stop parsing JSON. Security triage in your terminal.</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/kademoslabs/kekkai/docker-publish.yml?logo=github"/>
  <img src="https://img.shields.io/circleci/build/github/kademoslabs/kekkai?logo=circleci"/>
  <img src="https://img.shields.io/pypi/v/kekkai-cli?pypiBaseUrl=https%3A%2F%2Fpypi.org&logo=pypi"/>
</p>

---

# Kekkai

**Interactive security triage in the terminal.**

Kekkai is a small open-source CLI that wraps existing security scanners (Trivy, Semgrep, Gitleaks) and focuses on the part that tends to be slow and frustrating: reviewing and triaging results.

Running scanners is easy. Interpreting noisy output, dealing with false positives, and making CI usable is not. Kekkai exists to make that part tolerable..

![Hero GIF](https://raw.githubusercontent.com/kademoslabs/assets/main/screenshots/kekkai-start.gif)

---

## What it does

- Runs Trivy (dependencies), Semgrep (code), and Gitleaks (secrets)
- Normalizes their outputs into a single report format
- Provides an interactive terminal UI for reviewing findings
- Lets you mark findings as false positives and persist decisions locally
- Supports CI mode with severity-based failure thresholds

Kekkai does not replace scanners or introduce proprietary detection logic. It sits on top of existing tools and focuses on workflow and UX.

---

## Quick Start

> Requires Docker and Python 3.12

### 1. Install

```bash
pipx install kekkai-cli
```

### 2. Scan

```bash
kekkai scan
# Runs Trivy (CVEs), Semgrep (code), Gitleaks (secrets)
# Outputs unified kekkai-report.json
```

### 3. Triage

```bash
kekkai triage
# Interactive TUI to review findings with keyboard navigation
```

No signup, no cloud service required.

---

## Why Kekkai?

| Problem | Kekkai Solution |
|---------|-----------------|
| **Juggling 3+ tools** | One CLI for Trivy, Semgrep, Gitleaks |
| **Reading JSON logs** | Interactive terminal UI |
| **Installing scanners** | Auto-pulls Docker containers |
| **Parsing different formats** | Unified `kekkai-report.json` |
| **False positives** | Mark and ignore with `.kekkaiignore` |
| **CI/CD integration** | `kekkai scan --ci --fail-on high` |

---

## Features

### Interactive Triage TUI

Stop reading JSON. Use keyboard navigation to review findings, mark false positives, and generate ignore files.

```bash
kekkai triage
```

**Controls:**
- `j/k` or `↑/↓`: Navigate findings
- `f`: Mark as false positive
- `c`: Confirm finding
- `d`: Defer/ignore
- `Ctrl+S`: Save decisions
- `q`: Quit

<!-- Screenshot placeholder: ![Triage TUI](https://raw.githubusercontent.com/kademoslabs/assets/main/screenshots/triage-tui.png) -->

[Full Triage Documentation →](docs/triage/README.md)

---

### CI/CD Policy Gate

Break builds on severity thresholds.

Kekkai can be used as a CI gate based on severity thresholds.

```bash
# Fail on any critical or high findings
kekkai scan --ci --fail-on high

# Fail only on critical
kekkai scan --ci --fail-on critical
```

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings exceed threshold |
| 2 | Scanner error |

**GitHub Actions Example:**

```yaml
- name: Security Scan
  run: |
    pipx install kekkai-cli
    kekkai scan --ci --fail-on high
```

[Full CI Documentation →](docs/ci/ci-mode.md)

---

### GitHub PR Comments

Get security feedback directly in pull requests.

```bash
export GITHUB_TOKEN="ghp_..."
kekkai scan --pr-comment
```
---

### Unified Scanning

Run industry-standard scanners without installing them individually. Each scanner runs in an isolated Docker container.

```bash
kekkai scan                          # Scan current directory
kekkai scan --repo /path/to/project  # Scan specific path
kekkai scan --output results.json    # Custom output path
```

**Scanners Included:**
| Scanner | Finds | Image |
|---------|-------|-------|
| Trivy | CVEs in dependencies | `aquasec/trivy:latest` |
| Semgrep | Code vulnerabilities | `semgrep/semgrep:latest` |
| Gitleaks | Hardcoded secrets | `zricethezav/gitleaks:latest` |

**Container Security:**
- Read-only filesystem
- No network access
- Memory limited (2GB)
- No privilege escalation

---

#### Design choices

- Local-first: no SaaS required, runs entirely on your machine or CI
- No network access for scanner containers
- Read-only filesystems, memory-limited containers
- Uses existing tools instead of reimplementing scanners
- Terminal-first UX instead of dashboards

---

## Optional features

These are opt-in and not required for basic use:

### Local-First AI Threat Modeling

Generate STRIDE threat models with AI that runs on **your machine**. No API keys. No cloud.

```bash
# Ollama (recommended - easy setup, privacy-preserving)
ollama pull mistral
kekkai threatflow --repo . --model-mode ollama --model-name mistral

# Output: THREATS.md with attack surface analysis and Mermaid.js diagrams
```

**Supports:**
- Ollama (recommended)
- Local GGUF models (llama.cpp)
- OpenAI/Anthropic (if you trust them with your code)

[Full Local-First AI Threat Modeling Documentation →](docs/threatflow/README.md)

---

### DefectDojo Integration

Spin up a vulnerability management dashboard locally if you need it.

```bash
kekkai dojo up --wait    # Start DefectDojo
kekkai upload            # Import scan results
```

**What You Get:**
- DefectDojo web UI at `http://localhost:8080`
- Automatic credential generation
- Pre-configured for Kekkai imports

[DefectDojo Quick Start →](docs/dojo/dojo-quickstart.md)

---

### AI-Powered Fix Engine

Generate code patches for findings (experimental).

```bash
kekkai fix --input scan-results.json --apply
```

---

### Compliance Reporting

Map findings to PCI-DSS, OWASP, HIPAA, SOC 2.

```bash
kekkai report --input scan-results.json --format pdf --frameworks PCI-DSS,OWASP
```

---

## What this is not

- Not a replacement for commercial AppSec platforms
- Not a new scanner or detection engine
- Not optimized for large enterprises (yet)
- Not a hosted service

Right now, Kekkai is aimed at individual developers and small teams who already run scanners but want better triage and less noise.

---

## Security

Kekkai is designed with security as a core principle:

- **Container Isolation**: Scanners run in hardened Docker containers
- **No Network Access**: Containers cannot reach external networks
- **Local-First AI**: run entirely on your machine
- **SLSA Level 3**: Release artifacts include provenance attestations
- **Signed Images**: Docker images are Cosign-signed

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/README.md#installation-methods) | All installation methods |
| [ThreatFlow](docs/threatflow/README.md) | AI threat modeling setup |
| [Triage TUI](docs/triage/README.md) | Interactive finding review |
| [CI Mode](docs/ci/ci-mode.md) | Pipeline integration |
| [DefectDojo](docs/dojo/dojo-quickstart.md) | Optional vulnerability management |
| [Security](docs/security/slsa-provenance.md) | SLSA provenance verification |

---

## Roadmap (short-term)

1. Persistent triage state across runs (baselines)
2. “New findings only” diffs
3. Better PR-level workflows
4. Cleaner reporting for small teams

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache-2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center"><i>Built by <a href="https://kademos.org">Kademos Labs</a></i></p>
