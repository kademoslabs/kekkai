# Kekkai Documentation

User-facing documentation for Kekkai CLI and related features.

---

## Quick Links

### Core Documentation

Essential guides for using Kekkai:

- **[CLI Reference](cli-reference.md)** — Complete command reference with all flags
- **[Configuration Guide](configuration.md)** — Config file format and environment variables
- **[CI/CD Integration](ci-integration.md)** — GitHub Actions, GitLab CI, CircleCI setup
- **[Troubleshooting](troubleshooting.md)** — Common issues and solutions
- **[Python API](api.md)** — Programmatic usage documentation

### Kekkai Dojo (DefectDojo Orchestration)

Run a local DefectDojo vulnerability management platform with one command.

- **[Quick Start Guide](dojo/dojo-quickstart.md)** — Get started in 5 minutes
- **[Complete Guide](dojo/dojo.md)** — Full command reference and configuration
- **[Security Guide](dojo/dojo-security.md)** — Threat model and best practices
- **[Troubleshooting](dojo/dojo-troubleshooting.md)** — Common issues and solutions

### CI/CD

Use Kekkai in CI/CD pipelines to fail builds on security findings and automate distribution.

- **[CI Mode Guide](ci/ci-mode.md)** — Policy enforcement with exit codes
- **[Docker Usage](ci/docker-usage.md)** — Docker image and wrapper
- **[Homebrew Maintenance](ci/homebrew-maintenance.md)** — Homebrew tap updates
- **[Automated Distributions](ci/automated-distributions.md)** — Automated distribution trigger system

### Portal (Hosted Dashboard)

Multi-tenant hosted security dashboard with authenticated uploads.

- **[Portal Guide](portal/README.md)** — Setup, API reference, and configuration

### ThreatFlow (AI-Powered Threat Modeling)

Generate STRIDE-aligned threat models from your codebase.

- **[ThreatFlow Guide](threatflow/README.md)** — Setup and usage guide

### Regulon (Compliance Checker) — Extracted

> **Note:** Regulon has been extracted to its own repository for independent development and versioning.
> See [github.com/kademoslabs/regulon](https://github.com/kademoslabs/regulon) for the standalone project.

### Operations (Production Hardening)

Production-ready operations for backup, monitoring, and upgrades.

- **[Backup & Restore Guide](ops/backup-restore.md)** — Automated backup and restore procedures
- **[Upgrade Runbook](ops/upgrade-runbook.md)** — Safe upgrade procedures with rollback
- **[Monitoring Guide](ops/monitoring.md)** — Alerts, metrics, and centralized logging
- **[Incident Response](ops/incident-response.md)** — Incident classification and response

### Getting Started

New to Kekkai? Start here:

1. **Install Kekkai** - Choose your installation method below
2. Read the [main README](../README.md) for project overview
3. Read the [CLI Reference](cli-reference.md) to learn all commands
4. Check the [Configuration Guide](configuration.md) for setup options
5. Follow the [Dojo Quick Start](dojo/dojo-quickstart.md) to run DefectDojo locally
6. Set up CI with the [CI/CD Integration Guide](ci-integration.md)

---

## Installation Methods

Kekkai supports multiple installation methods to fit your workflow:

| Method | Best For | Command |
|--------|----------|---------|
| **pipx** | Isolated Python environments, recommended for local development | `pipx install kekkai-cli` |
| **Homebrew** | macOS/Linux users who prefer native package managers | `brew install kademoslabs/tap/kekkai` |
| **Scoop** | Windows users who prefer command-line package managers | `scoop install kademoslabs/kekkai` |
| **Docker** | CI/CD pipelines, no local Python installation required | `./scripts/kekkai-docker --help` |
| **pip** | Traditional Python environments | `pip install kekkai-cli` |

### Detailed Installation Guides

- **pipx**: See [main README](../README.md#installation) for quick setup
- **Docker**: See [Docker Usage Guide](ci/docker-usage.md) for security model and CI integration
- **Homebrew**: See [Homebrew Maintenance](ci/homebrew-maintenance.md) for tap details
- **Scoop**: See [Windows Installation Guide](installation/windows.md) for Windows-specific setup
- **Windows**: See [Scoop Integration](ci/scoop-integration.md) for technical details

### Which Method Should I Use?

- **For local development**: Use **pipx** for isolated, clean environments
- **For macOS/Linux systems**: Use **Homebrew** for native package management
- **For Windows systems**: Use **Scoop** for easy command-line installation
- **For CI/CD**: Use **Docker** for reproducible, sandboxed execution
- **For traditional Python projects**: Use **pip** if managing dependencies manually

---

## Documentation Structure

```
docs/
├── README.md                    # This file
├── cli-reference.md             # Complete CLI command reference
├── configuration.md             # Config file and env var documentation
├── ci-integration.md            # CI/CD integration guides
├── troubleshooting.md           # Common issues and solutions
├── api.md                       # Python API reference
├── ci/
│   ├── ci-mode.md               # CI policy enforcement guide
│   ├── docker-usage.md          # Docker usage guide
│   ├── homebrew-maintenance.md  # Homebrew tap maintenance
│   ├── scoop-integration.md     # Scoop/Windows integration
│   └── automated-distributions.md # Distribution automation
├── installation/
│   └── windows.md               # Windows installation guide
├── dojo/                        # DefectDojo Docs
│   ├── dojo-quickstart.md       # 5-minute quick start
│   ├── dojo.md                  # Complete Dojo guide
│   ├── dojo-security.md         # Security considerations
│   └── dojo-troubleshooting.md  # Common issues and solutions
├── ops/                         # Operations Docs
│   ├── backup-restore.md        # Backup and restore guide
│   ├── upgrade-runbook.md       # Upgrade procedures
│   ├── monitoring.md            # Monitoring and alerting
│   └── incident-response.md     # Incident response procedures
├── portal/                      # Portal Docs
│   └── README.md                # Portal guide
└── threatflow/                  # ThreatFlow Docs
    └── README.md                # ThreatFlow guide
```

---

## Contributing to Docs

To improve these docs:

1. Fork the repository
2. Edit markdown files in `docs/`
3. Test locally by reading in a markdown viewer
4. Submit a pull request

Keep documentation:
- **Concise** — Get to the point quickly
- **Actionable** — Provide clear commands and examples
- **Up-to-date** — Reflect current implementation
- **Accessible** — Assume minimal background knowledge

---

## Support

- **Issues:** [GitHub Issues](https://github.com/kademoslabs/kekkai/issues)
- **Security:** [security@kademos.org](mailto:security@kademos.org)
- **Website:** [kademos.org/kekkai](https://kademos.org/kekkai)

---

## License

Documentation is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Code is licensed under Apache-2.0 (see [LICENSE](../LICENSE)).
