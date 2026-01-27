# 🛡️ Kekkai v1.0.0 - Initial Release

**Security that moves at developer speed.**

Kekkai is a local-first AppSec orchestration tool that unifies vulnerability scanning, threat modeling, and security operations in a single CLI.

## ⚡ Highlights

- **One-Command Security Scanning** - Run Trivy, Semgrep, Gitleaks, ZAP, and Falco with `kekkai scan`
- **DefectDojo Orchestration** - Launch a complete vulnerability management platform with `kekkai dojo up`
- **AI-Powered Threat Modeling** - Generate STRIDE threat models with `kekkai threatflow`
- **Enterprise Security** - SSO/SAML 2.0, RBAC, and cryptographically signed audit logs
- **CI/CD Integration** - Policy enforcement with exit codes (`--ci --fail-on high`)
- **Multi-Platform Distribution** - pipx, Homebrew, Docker, Scoop, and Chocolatey support

## 🚀 Quick Start

```bash
# Install via pipx (recommended)
pipx install kekkai

# Scan your project
cd your-repo && kekkai scan

# Launch DefectDojo
kekkai dojo up --wait --open

# Generate threat model
kekkai threatflow --repo . --model-mode local
```

## 📦 Installation Options

| Platform | Method | Command |
|----------|--------|---------|
| **Python** | pipx | `pipx install kekkai` |
| **macOS/Linux** | Homebrew | `brew install kademoslabs/tap/kekkai` |
| **Windows** | Scoop | `scoop install kademoslabs/kekkai` |
| **Windows** | Chocolatey | `choco install kekkai` |
| **Docker** | Docker | `docker run kademoslabs/kekkai:latest` |

## ✨ Core Features

### Security Scanning
- **SAST**: Semgrep for static code analysis
- **SCA**: Trivy for dependency vulnerabilities
- **Secrets**: Gitleaks for credential detection
- **DAST**: ZAP for runtime web application scanning
- **Runtime**: Falco for container security monitoring
- **Unified Output**: Single deduplicated JSON report

### DefectDojo Integration
- One-command deployment with Docker orchestration
- Automated product/engagement creation
- Bulk finding imports with deduplication
- Production hardening (backup/restore, monitoring, upgrades)

### Threat Modeling (ThreatFlow)
- AI-powered STRIDE analysis
- Automatic data flow diagram generation
- Local LLM support for privacy
- Markdown output for version control

### Enterprise Features (Portal)
- SAML 2.0 SSO with replay protection
- Role-Based Access Control (RBAC)
- Cryptographically signed audit logs
- Multi-tenant support

### CI/CD & Distribution
- Policy enforcement with configurable severity thresholds
- Exit codes for build breaking
- Automated distribution triggers
- Cross-platform CI/CD testing infrastructure
- Docker Hub publishing with security scanning

## 📚 Documentation

- [Installation Guide](docs/README.md#installation-methods)
- [DefectDojo Quick Start](docs/dojo/dojo-quickstart.md)
- [CI/CD Integration](docs/ci/ci-mode.md)
- [ThreatFlow Guide](docs/threatflow/README.md)
- [Operations Guide](docs/ops/)

## 🔧 What's New in v1.0.0

This is the initial stable release of Kekkai, combining:
- Core scanning capabilities (m1-m5)
- DefectDojo orchestration (m4)
- ThreatFlow threat modeling (m9)
- Enterprise hardening (m8)
- CI/CD policy enforcement (m6)
- Production operations (m10)
- Multi-platform distribution (m1-m5 latest)
- Automated distribution system
- Cross-platform CI/CD testing

## 🙏 Acknowledgments

Built by [Kademos Labs](https://kademos.org) for security teams and developers.

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Full Changelog**: https://github.com/kademoslabs/kekkai/commits/v1.0.0
