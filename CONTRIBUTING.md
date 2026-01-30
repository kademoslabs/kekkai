# Contributing to Kekkai

Thank you for your interest in contributing to Kekkai! This guide will help you get started.

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

---

## Getting Started

### Prerequisites

- Python 3.12+
- Docker 24+
- Git
- Make

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kademoslabs/kekkai.git
   cd kekkai
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

3. **Install dependencies:**
   ```bash
   make setup
   ```

4. **Verify installation:**
   ```bash
   kekkai --version
   make ci-quick
   ```

---

## Project Structure

```
kekkai/
├── src/
│   └── kekkai/
│       ├── cli.py              # CLI entry point
│       ├── config.py           # Configuration handling
│       ├── dojo.py             # DefectDojo orchestration
│       ├── dojo_import.py      # DefectDojo import logic
│       ├── output.py           # Terminal output formatting
│       ├── paths.py            # Path utilities
│       ├── policy.py           # Policy evaluation
│       ├── runner.py           # Pipeline runner
│       ├── manifest.py         # Run manifest handling
│       ├── scanners/           # Scanner implementations
│       │   ├── base.py         # Scanner base class
│       │   ├── container.py    # Docker container management
│       │   ├── trivy.py        # Trivy scanner
│       │   ├── semgrep.py      # Semgrep scanner
│       │   ├── gitleaks.py     # Gitleaks scanner
│       │   ├── zap.py          # ZAP DAST scanner
│       │   └── falco.py        # Falco runtime scanner
│       ├── threatflow/         # AI threat modeling
│       ├── triage/             # Interactive triage TUI
│       ├── github/             # GitHub integration
│       └── installer/          # Tool installer
├── tests/
│   ├── test_*.py               # Unit tests
│   ├── integration/            # Integration tests
│   └── regression/             # Regression tests
├── apps/
│   ├── kekkai/                 # Docker image
│   ├── portal/                 # Enterprise portal
│   └── vscode-kekkai/          # VS Code extension
├── docs/                       # Documentation
├── scripts/                    # Utility scripts
├── requirements/
│   └── dev.txt                 # Development dependencies
├── pyproject.toml              # Package configuration
├── Makefile                    # Build automation
└── .circleci/config.yml        # CI configuration
```

---

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/changes

### 2. Make Changes

Follow the coding standards outlined below.

### 3. Run Tests

```bash
# Quick tests (formatting, linting, unit tests)
make ci-quick

# Full test suite
make ci

# Specific test types
make unit          # Unit tests only
make integration   # Integration tests only
make regression    # Regression tests only
```

### 4. Commit Changes

Write clear, descriptive commit messages:

```bash
git commit -m "feat(scanners): add support for custom Trivy rules"
git commit -m "fix(dojo): resolve volume cleanup on down command"
git commit -m "docs(api): add programmatic usage examples"
```

Commit message format: `type(scope): description`

Types:
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `refactor` - Code refactoring
- `test` - Test changes
- `chore` - Build/tooling changes

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Then create a Pull Request on GitHub.

---

## Coding Standards

### Python Style

- Follow PEP 8
- Use type hints for all public functions
- Maximum line length: 100 characters
- Use `ruff` for formatting and linting

```bash
# Format code
make fmt

# Check linting
make lint
```

### Type Hints

```python
# Good
def process_findings(findings: list[Finding], limit: int = 10) -> list[Finding]:
    ...

# Avoid
def process_findings(findings, limit=10):
    ...
```

### Docstrings

Use Google-style docstrings for public APIs:

```python
def evaluate_policy(
    findings: list[Finding],
    config: PolicyConfig,
    scan_errors: list[str],
) -> PolicyResult:
    """Evaluate findings against policy configuration.

    Args:
        findings: List of security findings to evaluate.
        config: Policy configuration with thresholds.
        scan_errors: List of scanner error messages.

    Returns:
        PolicyResult with pass/fail status and violation details.

    Raises:
        ValueError: If config contains invalid thresholds.
    """
    ...
```

### Error Handling

```python
# Good - specific exceptions with context
if not repo_path.exists():
    raise FileNotFoundError(f"Repository not found: {repo_path}")

# Avoid - generic exceptions
if not repo_path.exists():
    raise Exception("Path not found")
```

### Security Considerations

- Never log sensitive data (API keys, secrets, passwords)
- Sanitize all user input before shell execution
- Use parameterized queries for any database operations
- Validate file paths to prevent directory traversal
- Use `secrets` module for random token generation

---

## Testing Guidelines

### Test Structure

```
tests/
├── test_*.py                    # Unit tests (no external deps)
├── integration/
│   └── test_*_integration.py    # Integration tests (may need Docker)
└── regression/
    └── test_*_regression.py     # Regression tests (API stability)
```

### Writing Tests

```python
import pytest
from kekkai.policy import PolicyConfig, evaluate_policy

class TestEvaluatePolicy:
    """Tests for policy evaluation."""

    def test_passes_when_no_findings(self):
        """Empty findings list should pass any policy."""
        config = PolicyConfig(fail_on_critical=True)
        result = evaluate_policy([], config, [])
        assert result.passed is True
        assert result.exit_code == 0

    def test_fails_on_critical_finding(self):
        """Critical finding should fail when fail_on_critical is True."""
        finding = Finding(severity="critical", ...)
        config = PolicyConfig(fail_on_critical=True)
        result = evaluate_policy([finding], config, [])
        assert result.passed is False
        assert result.exit_code == 2

    @pytest.mark.integration
    def test_scanner_produces_findings(self):
        """Integration test requiring Docker."""
        ...
```

### Test Markers

```python
@pytest.mark.integration   # Requires external resources (Docker)
@pytest.mark.regression    # API stability tests
@pytest.mark.e2e           # End-to-end tests
```

### Running Specific Tests

```bash
# Run single test file
pytest tests/test_policy.py -v

# Run single test
pytest tests/test_policy.py::TestEvaluatePolicy::test_passes_when_no_findings -v

# Run by marker
pytest -m integration -v
pytest -m "not integration" -v  # Skip integration tests
```

---

## Adding New Scanners

1. **Create scanner module:**
   ```python
   # src/kekkai/scanners/my_scanner.py
   from .base import Scanner, ScanContext, ScanResult

   class MyScanner(Scanner):
       name = "myscanner"

       def run(self, ctx: ScanContext) -> ScanResult:
           # Implementation
           ...
   ```

2. **Register in `__init__.py`:**
   ```python
   # src/kekkai/scanners/__init__.py
   from .my_scanner import MyScanner

   SCANNER_REGISTRY["myscanner"] = MyScanner
   ```

3. **Add tests:**
   ```python
   # tests/test_scanner_my_scanner.py
   from kekkai.scanners import MyScanner

   class TestMyScanner:
       def test_scanner_name(self):
           scanner = MyScanner()
           assert scanner.name == "myscanner"
   ```

4. **Update documentation:**
   - Add to `docs/cli-reference.md`
   - Add to `docs/api.md`

---

## Documentation

### Writing Documentation

- Use Markdown format
- Keep language clear and concise
- Include code examples
- Test all examples work

### Documentation Structure

```
docs/
├── README.md           # Documentation index
├── cli-reference.md    # CLI commands and flags
├── configuration.md    # Config file format
├── ci-integration.md   # CI/CD setup guides
├── troubleshooting.md  # Common issues
├── api.md              # Python API reference
└── */                  # Feature-specific docs
```

### Building Documentation

Documentation is written in Markdown and can be viewed directly on GitHub or with any Markdown viewer.

---

## Pull Request Process

1. **Before submitting:**
   - Run `make ci-quick` and ensure it passes
   - Add/update tests for your changes
   - Update documentation if needed
   - Rebase on latest `main`

2. **PR Description:**
   - Describe what the PR does
   - Link related issues
   - Include test instructions
   - Note any breaking changes

3. **Review Process:**
   - Address reviewer feedback
   - Keep commits clean (squash if needed)
   - Ensure CI passes

4. **Merge:**
   - PRs are squash-merged to `main`
   - Delete feature branch after merge

---

## Release Process

Releases are automated via GitHub Actions:

1. Version bump in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v1.2.3`
4. Push tag: `git push origin v1.2.3`
5. GitHub Actions builds and publishes

---

## Getting Help

- **Questions:** Open a [Discussion](https://github.com/kademoslabs/kekkai/discussions)
- **Bugs:** Open an [Issue](https://github.com/kademoslabs/kekkai/issues)
- **Security:** Email [security@kademos.org](mailto:security@kademos.org)

---

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
