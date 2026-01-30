<p align="center">
  <img src="https://raw.githubusercontent.com/kademoslabs/assets/main/logos/kekkai-slim.png" alt="Kekkai CLI Logo" width="250"/>
</p>

<p align="center"><strong>Security orchestration at developer speed.</strong></p>
<p align="center"><i>One tool for the entire AppSec lifecycle: Predict, Detect, Triage, Manage.</i></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/kademoslabs/kekkai/docker-publish.yml?logo=github"/>
  <img src="https://img.shields.io/circleci/build/github/kademoslabs/kekkai?logo=circleci"/>
  <img src="https://img.shields.io/pypi/v/kekkai-cli?pypiBaseUrl=https%3A%2F%2Fpypi.org&logo=pypi"/>
</p>

---

# Kekkai

Stop juggling security tools. **Kekkai orchestrates your entire AppSec lifecycle** — from AI-powered threat modeling to vulnerability management — in a single CLI.

![Hero GIF](https://raw.githubusercontent.com/kademoslabs/assets/main/screenshots/kekkai-demo.gif)

---

## The Five Pillars

| Pillar | Feature | Command | Description |
|--------|---------|---------|-------------|
| 🔮 **Predict** | AI Threat Modeling | `kekkai threatflow` | Generate STRIDE threat models before writing code |
| 🔍 **Detect** | Unified Scanning | `kekkai scan` | Run Trivy, Semgrep, Gitleaks in isolated containers |
| ✅ **Triage** | Interactive Review | `kekkai triage` | Review findings in a terminal UI, mark false positives |
| 🚦 **Gate** | CI/CD Policy | `kekkai scan --ci` | Break builds on severity thresholds |
| 📊 **Manage** | DefectDojo | `kekkai dojo up` | Spin up vulnerability management in 60 seconds |

---

## Quick Start (60 Seconds)

### 1. Install

```bash
pipx install kekkai-cli
```

### 2. Predict (Threat Model)

```bash
kekkai threatflow --repo . --model-mode local
# Generates THREATS.md with STRIDE analysis and Data Flow Diagram
```

### 3. Detect (Scan)

```bash
kekkai scan
# Runs Trivy (CVEs), Semgrep (code), Gitleaks (secrets)
# Outputs unified kekkai-report.json
```

### 4. Triage (Review)

```bash
kekkai triage
# Interactive TUI to accept, reject, or ignore findings
```

### 5. Manage (DefectDojo)

```bash
kekkai dojo up --wait
kekkai upload
# Full vulnerability management platform + automated import
```

---

## Why Kekkai?

| Capability | Manual Approach | Kekkai |
|------------|-----------------|--------|
| **Tooling** | Install/update 5+ tools individually | One binary, auto-pulls scanner containers |
| **Output** | Parse 5 different JSON formats | Unified `kekkai-report.json` |
| **Threat Modeling** | Expensive consultants or whiteboarding | AI-generated `THREATS.md` locally |
| **DefectDojo** | 200-line docker-compose + debugging | `kekkai dojo up` (one command) |
| **Triage** | Read JSON files manually | Interactive terminal UI |
| **CI/CD** | Complex bash scripts | `kekkai scan --ci --fail-on high` |
| **PR Feedback** | Manual security review comments | Auto-comments on GitHub PRs |

---

## Feature Deep Dives

### 🔮 ThreatFlow — AI-Powered Threat Modeling

Generate STRIDE-aligned threat models and Mermaid.js Data Flow Diagrams from your codebase.

```bash
# Ollama (recommended - easy setup, privacy-preserving)
ollama pull mistral
kekkai threatflow --repo . --model-mode ollama --model-name mistral

# Local GGUF model (requires llama-cpp-python)
kekkai threatflow --repo . --model-mode local --model-path ./mistral-7b.gguf

# Remote API (faster, requires API key)
export KEKKAI_THREATFLOW_API_KEY="sk-..."
kekkai threatflow --repo . --model-mode openai
```

**Output:** `THREATS.md` containing:
- Attack surface analysis
- STRIDE threat classification
- Mermaid.js architecture diagram
- Recommended mitigations

[Full ThreatFlow Documentation →](docs/threatflow/README.md)

---

### 🔍 Unified Scanning

Run industry-standard scanners without installing them individually. Each scanner runs in an isolated Docker container with security hardening.

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

### ✅ Interactive Triage TUI

Stop reading JSON. Review security findings in your terminal.

```bash
kekkai triage
```

**Features:**
- Navigate findings with keyboard
- Mark as: Accept, Reject, False Positive, Ignore
- Filter by severity, scanner, or status
- Persist decisions in `.kekkai-ignore`
- Export triaged results

<!-- Screenshot placeholder: ![Triage TUI](https://raw.githubusercontent.com/kademoslabs/assets/main/screenshots/triage-tui.png) -->

[Full Triage Documentation →](docs/triage/README.md)

---

### 🚦 CI/CD Policy Gate

Automate security enforcement in your pipelines.

```bash
# Fail on any critical or high findings
kekkai scan --ci --fail-on high

# Fail only on critical
kekkai scan --ci --fail-on critical

# Custom threshold: fail on 5+ medium findings
kekkai scan --ci --fail-on medium --max-findings 5
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

### 📊 DefectDojo Integration

Spin up a complete vulnerability management platform locally.

```bash
kekkai dojo up --wait    # Start DefectDojo (Nginx, Postgres, Redis, Celery)
kekkai dojo status       # Check service health
kekkai upload            # Import scan results
kekkai dojo down         # Stop and clean up (removes volumes)
```

**What You Get:**
- DefectDojo web UI at `http://localhost:8080`
- Automatic credential generation
- Pre-configured for Kekkai imports
- Clean teardown (no orphaned volumes)

[Full Dojo Documentation →](docs/dojo/dojo.md)

---

### 🔔 GitHub PR Comments

Get security feedback directly in pull requests.

```bash
export GITHUB_TOKEN="ghp_..."
kekkai scan --github-comment
```

Kekkai will:
1. Run all scanners
2. Post findings as PR review comments
3. Annotate specific lines with inline comments

---

## Installation

### pipx (Recommended)

Isolated environment, no conflicts with system Python.

```bash
pipx install kekkai-cli
```

### Homebrew (macOS/Linux)

```bash
brew install kademoslabs/tap/kekkai
```

### Scoop (Windows)

```bash
scoop bucket add kademoslabs https://github.com/kademoslabs/scoop-bucket
scoop install kekkai
```

### Docker (No Python Required)

```bash
docker pull kademoslabs/kekkai:latest
alias kekkai='docker run --rm -v "$(pwd):/repo" kademoslabs/kekkai:latest'
```

### pip (Traditional)

```bash
pip install kekkai-cli
```

---

## Enterprise Features — Kekkai Portal

For teams that need centralized management, **Kekkai Portal** provides:

| Feature | Description |
|---------|-------------|
| **SAML 2.0 SSO** | Integrate with Okta, Azure AD, Google Workspace ([Setup Guide](docs/portal/saml-setup.md)) |
| **Role-Based Access Control** | Fine-grained permissions per team/project ([RBAC Guide](docs/portal/rbac.md)) |
| **Multi-Tenant Architecture** | Isolated environments per organization ([Architecture](docs/portal/multi-tenant.md)) |
| **Aggregated Dashboards** | Centralized view of all CLI scan results |
| **Audit Logging** | Cryptographically signed compliance trails |

**Upgrade Path:**
- CLI users can sync results to Portal: `kekkai upload` ([Sync Guide](docs/portal/cli-sync.md))
- Portal provides dashboards for security managers
- Self-hosted or Kademos-managed options ([Deployment Guide](docs/portal/deployment.md))

[Contact us for Portal access →](mailto:sales@kademos.org)

---

## Security

Kekkai is designed with security as a core principle:

- **Container Isolation**: Scanners run in hardened Docker containers
- **No Network Access**: Containers cannot reach external networks
- **Local-First AI**: ThreatFlow can run entirely on your machine
- **SLSA Level 3**: Release artifacts include provenance attestations
- **Signed Images**: Docker images are Cosign-signed

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/README.md#installation-methods) | All installation methods |
| [ThreatFlow](docs/threatflow/README.md) | AI threat modeling setup |
| [Dojo Quick Start](docs/dojo/dojo-quickstart.md) | DefectDojo in 5 minutes |
| [CI Mode](docs/ci/ci-mode.md) | Pipeline integration |
| [Portal](docs/portal/README.md) | Enterprise features overview |
| [Portal SSO](docs/portal/saml-setup.md) | SAML 2.0 SSO configuration |
| [Portal RBAC](docs/portal/rbac.md) | Role-based access control |
| [Portal Deployment](docs/portal/deployment.md) | Self-hosted deployment |
| [Security](docs/security/slsa-provenance.md) | SLSA provenance verification |

---

## CI/CD Status

[![Kekkai Security Scan](https://github.com/kademoslabs/kekkai/actions/workflows/kekkai-pr-scan.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/kekkai-pr-scan.yml)
[![Docker Image Publish](https://github.com/kademoslabs/kekkai/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/docker-publish.yml)
[![Docker Security Scan](https://github.com/kademoslabs/kekkai/actions/workflows/docker-security-scan.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/docker-security-scan.yml)
[![Cross-Platform Tests](https://github.com/kademoslabs/kekkai/actions/workflows/test-cross-platform.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/test-cross-platform.yml)
[![Release with SLSA Provenance](https://github.com/kademoslabs/kekkai/actions/workflows/release-slsa.yml/badge.svg)](https://github.com/kademoslabs/kekkai/actions/workflows/release-slsa.yml)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache-2.0 — See [LICENSE](LICENSE) for details.

---

<p align="center"><i>Built by <a href="https://kademos.org">Kademos Labs</a></i></p>
