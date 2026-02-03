# Changelog

All notable changes to Kekkai will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-02-02

### BREAKING
- Pivot to developer tool positioning: "The lazy developer's security scanner"
- Removed enterprise marketing (SAML/SSO/RBAC claims for features that don't exist)
- Hidden `kekkai dojo` from help menu and dashboard (still functional via direct invocation)
- De-emphasized DefectDojo integration (now positioned as optional advanced feature)

### Added - Distribution Features
- **Pre-commit hooks** (`.pre-commit-hooks.yaml`): Viral team-wide adoption
  - `kekkai-scan`: Default hook (fail on high/critical)
  - `kekkai-scan-strict`: Stricter hook (fail on medium+)
  - `kekkai-secrets`: Fast secrets-only check with Gitleaks
  - One developer adds it, whole team gets protected automatically
- **`kekkai init --ci`**: Auto-generate GitHub Actions workflow
  - Detects if in Git repository
  - Creates `.github/workflows/kekkai-security.yml` automatically
  - Eliminates YAML writing friction for CI/CD setup
  - Includes PR comments and artifact uploads
- **TUI "Fix with AI" feature** (hotkey: `x`):
  - AI-powered fix generation directly from triage screen
  - Detects Ollama for local-first fixes (no API keys needed)
  - Shows model configuration and fix preview
  - Emphasizes privacy: "No data leaves your machine" with Ollama

### Removed
- `docs/portal/` directory and all enterprise feature documentation
- "Five Pillars" marketing framing from README
- Enterprise feature comparison tables
- Portal references from docs/README.md

### Changed
- README.md completely rewritten with developer-first narrative
- Pre-commit installation prominently featured (viral adoption strategy)
- Emphasized TUI triage and local-first AI as hero features
- pyproject.toml description updated to match new positioning

### Notes
- **No functional code changes** to existing commands: All CLI commands work identically
- **No breaking API changes**: This is a documentation/positioning change only
- Version bump to 2.0.0 follows SemVer: marketing repositioning is a major version change
- Distribution features designed to make Kekkai spread organically

## [1.1.1] - 2026-02-02

### Fixed
- **Triage:** Fixed blank screen when loading raw scanner outputs (Semgrep/Trivy/Gitleaks JSON)
- **Triage:** Added automatic default to latest run directory when `--input` is omitted
- **Upload:** Fixed "Unknown scanner" errors for `*-results.json` files (gitleaks-results, trivy-results, semgrep-results)
- **Upload:** Now uses canonical scanner parsers (eliminates duplicate parsing logic)
- **Upload:** Fixed scanner name mapping for DefectDojo imports (correct scan types now sent)
- **Dojo API:** Fixed potential crash on empty/204 responses (proper response.read() handling)
- **Triage Models:** Made importable without Textual dependency (lazy import for TUI)

### Added
- **Triage:** New `load_findings_from_path()` loader supporting multiple input formats:
  - Native triage JSON (list or `{"findings": [...]}`)
  - Raw scanner outputs (Semgrep, Trivy, Gitleaks)
  - Run directories (aggregates all `*-results.json` files)
- **Security:** Added file size limits (200MB max) to prevent DoS attacks (ASVS V10.3.3)
- **Security:** Enhanced error message sanitization to prevent path disclosure (ASVS V7.4.1)
- **Report:** Added unified report generation command for scan results

### Changed
- **Upload:** Scanner file discovery now prefers `*-results.json` over generic `*.json`
- **Upload:** Scanner name normalization: `gitleaks-results` → `gitleaks`
- **Triage:** Findings are now deduplicated by `scanner:rule_id:file_path:line`

## [1.0.5] - 2026-01-28

### Fixed
- Fixed integration test for non-TTY CLI output
- Added release idempotency in GitHub Actions workflow
- Resolved CI race condition between CircleCI and GitHub Actions
- CircleCI now handles testing only; GitHub Actions manages releases

## [1.0.4] - 2026-01-28

### Fixed
- CI race condition fix (burned release)

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

[1.1.1]: https://github.com/kademoslabs/kekkai/releases/tag/v1.1.1
[1.1.0]: https://github.com/kademoslabs/kekkai/releases/tag/v1.1.0
[1.0.5]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.5
[1.0.4]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.4
[1.0.3]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.3
[1.0.2]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.2
[1.0.1]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.1
[1.0.0]: https://github.com/kademoslabs/kekkai/releases/tag/v1.0.0
