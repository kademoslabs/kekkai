# Changelog

All notable changes to Kekkai will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-01-28

### Fixed
- CircleCI publish_release workflow: added `--repo` flag for gh CLI
- Added artifact verification step before GitHub release creation
- Fixed GH_TOKEN environment variable passing to gh CLI

## [1.0.2] - 2026-01-28

### Changed
- Fixed CI Failures


## [1.0.1] - 2026-01-28

### Changed
- Professional Rich-themed splash screen with branded colors
- New block-style ASCII banner art
- Command menu table and quick tips panel in splash output

## [1.0.0] - 2026-01-27

### Added

#### Core Scanning Features
- Multi-scanner orchestration (Trivy, Semgrep, Gitleaks, ZAP, Falco)
- Unified JSON report output with deduplication
- `kekkai scan` command for one-step security scanning
- Container-based scanner execution (no manual tool installation)

#### DefectDojo Integration
- One-command DefectDojo deployment (`kekkai dojo up`)
- Automated Docker Compose orchestration (Nginx, Postgres, Redis, Celery)
- Bulk finding imports with automatic deduplication
- Product and engagement auto-creation
- Web UI auto-open functionality

#### ThreatFlow (AI Threat Modeling)
- STRIDE-based threat analysis
- Automatic data flow diagram generation
- Local LLM support for privacy-preserving modeling
- `kekkai threatflow` command
- Markdown output for version control

#### Enterprise Security (Portal)
- SAML 2.0 SSO with replay protection
- Role-Based Access Control (RBAC)
- Cryptographically signed audit logs
- Multi-tenant architecture
- `kekkai-portal` web application

#### CI/CD Integration
- Policy enforcement with severity thresholds
- `--ci` mode with exit codes for build breaking
- `--fail-on` flag for configurable failure conditions
- Docker wrapper script for containerized CI execution
- Cross-platform CI/CD testing infrastructure

#### Production Operations
- Automated backup and restore procedures
- Safe upgrade runbooks with rollback capability
- Monitoring and alerting (Prometheus, Grafana)
- Incident response procedures
- Centralized logging

#### Distribution & Packaging
- pipx support (recommended installation method)
- Homebrew tap (kademoslabs/tap)
- Docker Hub publishing with automated builds
- Scoop bucket for Windows
- Chocolatey package support
- Automated distribution trigger system
- Binary mode fallback
- Enhanced Docker Hub publishing with security scanning

#### Documentation
- Comprehensive user documentation
- Quick start guides
- Security best practices
- Troubleshooting guides
- CI/CD integration examples
- Operations runbooks

### Changed
- Extracted Regulon compliance checker to separate repository
- Repository renamed from `kekkai-cli` to `kekkai`
- UI decoupling with Jinja2 templates for better maintainability
- API-first data access patterns

### Technical
- Python 3.12+ requirement
- Type-safe codebase with mypy strict mode
- Comprehensive test suite (unit, integration, e2e)
- Ruff linting and formatting
- Pre-commit hooks for code quality
- CircleCI integration for CI/CD

---

[1.0.0]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.0
