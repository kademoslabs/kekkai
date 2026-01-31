# CI/CD Architecture

Comprehensive guide to Kekkai's CI/CD infrastructure, covering CircleCI, GitHub Actions, and cross-platform testing.

---

## Overview

Kekkai uses a **dual CI system** to provide comprehensive testing and deployment:

- **CircleCI**: Linux testing + deployment pipeline
- **GitHub Actions**: Cross-platform validation (Linux, macOS, Windows)

This architecture ensures:
- Fast feedback on Linux (CircleCI)
- Cross-platform compatibility (GitHub Actions)
- Reliable deployments (CircleCI)
- No duplication between systems

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Pull Request                          │
└─────────────────────────────────────────────────────────────┘
                           │
                 ┌─────────┴──────────┐
                 │                    │
                 ▼                    ▼
    ┌───────────────────┐  ┌──────────────────────┐
    │   GitHub Actions  │  │     CircleCI         │
    │  Cross-Platform   │  │  Fast Linux Check    │
    │                   │  │  (develop branch)    │
    │ • ubuntu-latest   │  │                      │
    │ • windows-latest  │  │ • Lint               │
    │ • macos-latest    │  │ • Type check         │
    │                   │  │ • Unit tests         │
    │ • Unit tests      │  │                      │
    │ • Integration     │  │                      │
    │ • Windows-specific│  │                      │
    │ • Benchmarks      │  │                      │
    └───────────────────┘  └──────────────────────┘
                 │                    │
                 └──────────┬─────────┘
                            ▼
                    ✅ All checks pass
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Merge to main     │
                 └─────────────────────┘
                            │
                 ┌──────────┴──────────┐
                 │                     │
                 ▼                     ▼
    ┌───────────────────┐  ┌──────────────────────┐
    │   GitHub Actions  │  │     CircleCI         │
    │  Full Validation  │  │  Full Linux Suite    │
    │                   │  │                      │
    │ • All platforms   │  │ • Full tests         │
    │ • All tests       │  │ • Build artifacts    │
    │ • Benchmarks      │  │                      │
    └───────────────────┘  └──────────────────────┘
                            │
                            ▼
                    ✅ Ready for release
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Create Tag        │
                 │   (v*.*.*)          │
                 └─────────────────────┘
                            │
                            ▼
                 ┌──────────────────────────────┐
                 │  GitHub Actions ONLY         │
                 │  Release & Distributions     │
                 │                              │
                 │ • PyPI publish (SLSA)        │
                 │ • GitHub release creation    │
                 │ • Homebrew tap update        │
                 │ • Docker Hub publish         │
                 │ • Scoop bucket update        │
                 │ • Chocolatey package publish │
                 └──────────────────────────────┘
                            │
            Note: CircleCI does NOT run on tag pushes
            (main branch already tested before tag)
```

---

## GitHub Actions Workflows

### 1. Cross-Platform Testing (`test-cross-platform.yml`)

**Triggers**:
- Pull requests to `main` or `develop`
- Pushes to `main`
- Manual dispatch

**Matrix**:
- **Platforms**: `ubuntu-latest`, `windows-latest`, `macos-latest`
- **Python**: `3.12`

**Jobs**:

#### test-matrix
Runs on all platforms:
1. Checkout code
2. Setup Python 3.12 with pip cache
3. Install dependencies
4. Run linting (ruff format, ruff check)
5. Run type checking (mypy)
6. Run unit tests with coverage
7. Run Windows-specific tests (Windows only)
8. Run integration tests
9. Run regression tests
10. Upload coverage artifacts

#### benchmark
Runs performance benchmarks on all platforms:
1. Checkout code
2. Setup Python 3.12
3. Install dependencies
4. Run benchmarks
5. Upload benchmark results

#### coverage-report
Aggregates coverage from all platforms:
1. Download all coverage artifacts
2. Display coverage summary

#### all-tests-passed
Final status check for PR merging.

**View**: `.github/workflows/test-cross-platform.yml`

### 2. Docker Security Scan (`docker-security-scan.yml`)

**Triggers**:
- Pull requests modifying Dockerfile, requirements, or src
- Manual dispatch

**Jobs**:
1. Build Docker image
2. Run Trivy vulnerability scan
3. Upload SARIF to GitHub Security
4. Comment PR with results
5. Fail if CRITICAL or HIGH vulnerabilities
6. Generate SBOM

**View**: `.github/workflows/docker-security-scan.yml`

### 3. Trigger Distributions (`trigger-distributions.yml`)

**Triggers**:
- Release published (tags matching `v*.*.*`)
- Manual dispatch

**Jobs**:
1. Extract metadata (version, SHA256)
2. Validate metadata (semver, checksum)
3. Trigger Homebrew tap update
4. Trigger Docker Hub publish
5. Trigger Scoop bucket update
6. Trigger Chocolatey package update
7. Notify success/failure

**View**: `.github/workflows/trigger-distributions.yml`

---

## CircleCI Workflows

### 1. Develop Workflow

**Trigger**: Push to `develop` branch

**Jobs**:
- `test_quick`: Fast checks (lint, type check, unit tests, security)
  - **Note**: VSCode extension tests removed (requires X11/GTK libraries not available in Docker)
  - VSCode tests run in GitHub Actions cross-platform workflow instead

**Purpose**: Fast feedback for development

### 2. Main Workflow

**Trigger**: Push to `main` branch

**Jobs**:
- `test_full`: Full test suite (lint, type check, unit, integration, regression, security)
- `build_release`: Build wheel and sdist (requires test_full)

**Purpose**: Comprehensive validation before release

### 3. Release Workflow

**Status**: **REMOVED** (as of v1.1.0+)

**Rationale**:
- Main branch already fully tested before tag creation
- Eliminates duplication with GitHub Actions release pipeline
- GitHub Actions handles all release publishing (PyPI, Docker, distributions)

**Previous behavior**: Tag push would trigger full CircleCI pipeline + deployment
**Current behavior**: Tag push only triggers GitHub Actions workflows

**View**: `.circleci/config.yml`

---

## Branch Strategy

### develop
- **CircleCI**: Fast checks (`test_quick`)
- **GitHub Actions**: Cross-platform validation on PRs
- **Purpose**: Development and feature branches

### main
- **CircleCI**: Full suite (`test_full`) + build validation
- **GitHub Actions**: Full cross-platform validation
- **Purpose**: Release-ready code

### Tags (v*.*.*)
- **CircleCI**: ~~Full pipeline + deployment~~ **REMOVED** (no longer runs on tags)
- **GitHub Actions**: Complete release pipeline (PyPI, GitHub release, distributions)
- **Purpose**: Official releases
- **Note**: Main branch is fully tested before tag creation, so no CircleCI duplication needed

---

## Test Execution Matrix

| Test Type | CircleCI (Linux) | GitHub Actions (Linux) | GitHub Actions (Windows) | GitHub Actions (macOS) |
|-----------|------------------|------------------------|--------------------------|------------------------|
| Lint & Format | ✅ | ✅ | ✅ | ✅ |
| Type Check | ✅ | ✅ | ✅ | ✅ |
| Unit Tests | ✅ | ✅ | ✅ | ✅ |
| Integration Tests | ✅ | ✅ | ✅ | ✅ |
| Regression Tests | ✅ | ✅ | ✅ | ✅ |
| Windows-Specific | ❌ | ❌ | ✅ | ❌ |
| Performance Benchmarks | ❌ | ✅ | ✅ | ✅ |
| Docker Tests | ✅ | ✅ | ⚠️ Optional | ⚠️ Optional |
| VSCode Extension Tests | ❌ | ✅ | ✅ | ✅ |
| Build Artifacts | ✅ | ❌ | ❌ | ❌ |
| Deployment | ❌ (GitHub Actions) | ✅ (on tags) | ❌ | ❌ |

---

## Deployment Pipeline

### 1. Create Release Tag

```bash
git tag v0.0.1
git push origin v0.0.1
```

### 2. CircleCI Release Workflow

Automatically triggered by tag:

1. **test_full**:
   - Lint, type check, unit, integration, regression, security

2. **build_release**:
   - Build Python wheel (`.whl`)
   - Build source distribution (`.tar.gz`)
   - Generate SBOM (`requirements-frozen.txt`)
   - Calculate SHA256 checksums

3. **publish_release**:
   - Upload artifacts to GitHub Releases
   - Create release notes

### 3. GitHub Actions Distribution Triggers

Automatically triggered after release publication:

1. **extract-metadata**:
   - Extract version from tag
   - Calculate tarball SHA256
   - Validate metadata

2. **trigger-homebrew**:
   - Send repository_dispatch to `homebrew-tap`
   - Payload: `{version, sha256}`

3. **trigger-docker**:
   - Trigger `docker-publish` workflow
   - Input: `{tag: version}`

4. **trigger-scoop**:
   - Send repository_dispatch to `scoop-bucket`
   - Payload: `{version, sha256}`

5. **trigger-chocolatey**:
   - Send repository_dispatch to `chocolatey-packages`
   - Payload: `{version, sha256}`

6. **notify-success/failure**:
   - Log success or create GitHub issue on failure

---

## Local Development Workflow

### Running Tests Locally

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1
make setup

# Run CI checks (same as CircleCI)
make ci-quick  # Fast checks (develop branch)
make ci        # Full suite (main branch)

# Run cross-platform tests (same as GitHub Actions)
make test-matrix

# Run benchmarks
make benchmark
```

### Pre-Commit Checks

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files

# What runs:
# - check-merge-conflict
# - end-of-file-fixer
# - trailing-whitespace
# - check-yaml
# - check-toml
# - detect-private-key
# - ruff (format + lint)
# - mypy (type checking)
```

---

## Debugging CI Failures

### GitHub Actions

```bash
# View workflow runs
gh run list --workflow=test-cross-platform.yml

# View specific run
gh run view RUN_ID

# View logs
gh run view RUN_ID --log

# Re-run failed jobs
gh run rerun RUN_ID --failed
```

### CircleCI

```bash
# View recent runs
gh run list  # (if using CircleCI CLI)

# Or visit: https://app.circleci.com/pipelines/github/kademoslabs/kekkai
```

### Common Issues

**Tests pass locally but fail in CI**:
- Platform-specific behavior (use cross-platform tests)
- Missing dependencies (check requirements/dev.txt)
- Environment variables (check workflow files)

**Docker tests failing**:
- Docker not available in CI runner
- Use `docker_available` fixture to skip

**Timeout errors**:
- Increase timeout in workflow (default: 90s for tests)
- Optimize slow tests

---

## Security Considerations

### Secret Management

**GitHub Secrets** (required):
- `GITHUB_TOKEN`: Automatic, for API access
- `TAP_REPO_TOKEN`: Homebrew tap repository
- `SCOOP_REPO_TOKEN`: Scoop bucket repository
- `CHOCO_REPO_TOKEN`: Chocolatey packages repository
- `COSIGN_PRIVATE_KEY`: Docker image signing
- `COSIGN_PASSWORD`: Cosign key password

**CircleCI Context** (required):
- `github-release`: Contains tokens for GitHub release publishing

### Token Permissions

All tokens should use **fine-grained permissions**:
- `repo` scope (repository access)
- `workflow` scope (workflow dispatch)
- **No** admin or write permissions beyond what's needed

### Rotation Policy

- Rotate tokens every 90 days
- Monitor token usage in security logs
- Revoke immediately if compromised

---

## Performance Optimization

### CI Runtime

**Target runtimes**:
- CircleCI `test_quick`: < 5 minutes
- CircleCI `test_full`: < 15 minutes
- GitHub Actions matrix: < 20 minutes per platform

**Optimization techniques**:
- Parallel test execution (`pytest -n auto`)
- Caching dependencies (pip cache)
- Selective test runs (only changed files)
- Docker layer caching

### Benchmark Tracking

Benchmarks are tracked over time:
- Stored in `.benchmarks/` directory
- Uploaded as artifacts in GitHub Actions
- Compare against baseline to detect regressions

**Regression threshold**: 20% performance degradation triggers alert

---

## Monitoring and Alerting

### CI Status

**GitHub Status Badge**:
```markdown
![CI Status](https://github.com/kademoslabs/kekkai/actions/workflows/test-cross-platform.yml/badge.svg)
```

**CircleCI Status Badge**:
```markdown
![CircleCI](https://circleci.com/gh/kademoslabs/kekkai.svg?style=shield)
```

### Failure Notifications

**GitHub Actions**:
- Failed workflow creates GitHub issue (for distribution triggers)
- PR comments for security scan results

**CircleCI**:
- Email notifications for failed builds (configurable)
- Slack webhooks (optional, configure in CircleCI)

---

## Best Practices

### 1. Test Locally Before Pushing

```bash
# Run same checks as CI
make ci-quick  # Fast checks
make ci        # Full suite

# Fix issues before push
make fmt       # Auto-format
make lint      # Check linting
```

### 2. Write Platform-Agnostic Tests

```python
# ✅ Good: Platform-agnostic
def test_path_handling(tmp_path: Path) -> None:
    file_path = tmp_path / "test.txt"
    file_path.write_text("content")
    assert file_path.exists()

# ❌ Bad: Platform-specific hardcoded paths
def test_path_handling_bad() -> None:
    file_path = Path("/tmp/test.txt")  # Fails on Windows
    file_path.write_text("content")
```

### 3. Use Platform Markers for Exceptions

```python
@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
def test_windows_specific() -> None:
    # Windows-specific test
    pass
```

### 4. Monitor CI Performance

- Review benchmark results after each run
- Optimize tests taking > 5 seconds
- Use `pytest-xdist` for parallel execution

---

## Troubleshooting

### Q: Why do I have both CircleCI and GitHub Actions?

**A**: They serve different purposes:
- **CircleCI**: Fast Linux testing + deployment (existing infrastructure)
- **GitHub Actions**: Cross-platform validation (Windows, macOS)

No duplication - they complement each other.

### Q: Tests pass in GitHub Actions but fail in CircleCI

**A**: Different environments:
- GitHub Actions: Fresh Ubuntu VM
- CircleCI: Docker container

Check for:
- Docker availability
- Environment variables
- File permissions

### Q: How do I run only Windows tests locally?

**A**: On Windows:
```bash
make windows-test
```

On Linux/macOS (simulated):
```bash
pytest tests/windows -v
```

---

## Related Documentation

- [Testing Guide](./testing.md)
- [Automated Distribution Updates](../ci/automated-distributions.md)
- [Docker Security](../ci/docker-security.md)

---

## Support

**For CI/CD issues**:
- GitHub: [kademoslabs/kekkai/issues](https://github.com/kademoslabs/kekkai/issues)
- Labels: `ci`, `testing`, `distribution`
