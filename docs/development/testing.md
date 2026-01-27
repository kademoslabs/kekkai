# Testing Guide

Comprehensive guide for running tests on Kekkai across all platforms (Linux, macOS, Windows).

---

## Quick Start

```bash
# Run all tests
make ci

# Run unit tests only
make unit

# Run integration tests
make integration

# Run regression tests
make regression

# Run cross-platform tests
make test-matrix

# Run performance benchmarks
make benchmark
```

---

## Test Organization

### Test Directory Structure

```
tests/
├── ci/                          # CI/CD and cross-platform tests
│   ├── test_cross_platform.py  # Cross-platform compatibility tests
│   ├── test_benchmarks.py      # Performance benchmarking tests
│   ├── test_trigger_workflow.py # Distribution trigger tests
│   └── test_release_artifacts.py # Release artifact tests
├── windows/                     # Windows-specific unit tests
│   ├── test_scoop_manifest.py
│   ├── test_chocolatey_nuspec.py
│   └── test_windows_validators.py
├── integration/                 # Integration tests
│   ├── test_platform_parity.py  # Platform parity tests
│   ├── test_windows_environment.py
│   ├── test_chocolatey_installation.py
│   └── test_scoop_installation.py
├── regression/                  # Regression tests
│   ├── test_platform_regressions.py
│   ├── test_scoop_backwards_compat.py
│   └── test_chocolatey_backwards_compat.py
└── [other test files]
```

### Test Markers

Kekkai uses pytest markers to categorize tests:

```python
@pytest.mark.integration  # Integration tests (may require Docker, network)
@pytest.mark.e2e          # End-to-end tests
@pytest.mark.regression   # Regression tests
@pytest.mark.benchmark    # Performance benchmarks
```

Platform-specific markers:

```python
@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
@pytest.mark.skipif(sys.platform.startswith("win"), reason="Unix only")
```

---

## Running Tests Locally

### Linux

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
make setup

# Run tests
make ci              # Full CI suite
make unit            # Unit tests only
make integration     # Integration tests
make test-matrix     # Cross-platform tests
```

### macOS

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
make setup

# Run tests
make ci              # Full CI suite
make unit            # Unit tests only
make integration     # Integration tests
make test-matrix     # Cross-platform tests

# Homebrew-specific tests
make brew-test       # Test Homebrew installation
```

### Windows

**PowerShell:**

```powershell
# Setup
python -m venv .venv
.\.venv\Scripts\Activate.ps1
make setup

# Run tests
make ci-quick        # Quick CI checks
make unit            # Unit tests
make windows-unit    # Windows-specific unit tests
make windows-test    # All Windows tests
make test-matrix     # Cross-platform tests

# Distribution-specific tests
make chocolatey-unit # Chocolatey unit tests
```

**Command Prompt:**

```cmd
# Setup
python -m venv .venv
.venv\Scripts\activate.bat
make setup

# Run tests
make ci-quick
make windows-test
```

---

## Test Categories

### Unit Tests

Fast, isolated tests with no external dependencies.

```bash
# Run all unit tests
make unit

# Run specific test file
pytest tests/windows/test_scoop_manifest.py -v

# Run specific test
pytest tests/ci/test_cross_platform.py::TestPathHandling::test_path_normalization -v
```

### Integration Tests

Tests that interact with external systems (Docker, file system, network).

```bash
# Run all integration tests
make integration

# Run Windows integration tests
pytest tests/integration/test_windows_environment.py -v

# Skip slow tests
pytest -m "integration and not slow" -v
```

### Regression Tests

Tests that ensure backward compatibility and consistent behavior.

```bash
# Run all regression tests
make regression

# Run platform regression tests
pytest tests/regression/test_platform_regressions.py -v
```

### Cross-Platform Tests

Tests that verify consistent behavior across Linux, macOS, and Windows.

```bash
# Run full cross-platform suite
make test-matrix

# Run specific cross-platform tests
pytest tests/ci/test_cross_platform.py -v
pytest tests/integration/test_platform_parity.py -v
pytest tests/regression/test_platform_regressions.py -v
```

---

## Performance Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
make benchmark

# Run benchmark integration tests
make benchmark-full

# Run specific benchmark
pytest tests/ci/test_benchmarks.py::TestBenchmarkFunction -v
```

### Viewing Benchmark Results

Benchmark results are stored in `.benchmarks/`:

```bash
# View latest benchmark
cat .benchmarks/benchmark_*.json

# Compare with baseline
pytest tests/ci/test_benchmarks.py::TestBenchmarkRunner::test_runner_compare_with_baseline -v
```

### Benchmark Report Format

```json
{
  "timestamp": 1234567890.123,
  "platform": {
    "system": "Windows",
    "release": "10",
    "machine": "AMD64",
    "python_version": "3.12.0"
  },
  "results": [
    {
      "name": "scan_performance",
      "duration_seconds": 1.234,
      "memory_peak_mb": 45.6,
      "platform": "win32",
      "metadata": {}
    }
  ]
}
```

---

## Test Coverage

### Generating Coverage Reports

```bash
# Generate HTML coverage report
make coverage-report

# View coverage
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov\index.html  # Windows
```

### Coverage Requirements

- **Minimum coverage**: 69% (configured in `pyproject.toml`)
- **Target coverage**: 80%+
- New features must include tests

### Coverage by Platform

```bash
# Generate coverage on specific platform
pytest --cov=src --cov-report=html

# Upload to CI
# Coverage is automatically collected in GitHub Actions
```

---

## Platform-Specific Testing

### Windows-Specific Tests

```bash
# Windows unit tests
make windows-unit

# Windows integration tests
make windows-integration

# All Windows tests
make windows-test

# Chocolatey tests
make chocolatey-test

# Scoop tests (simulated on Linux/macOS)
pytest tests/windows/test_scoop_manifest.py -v
```

### macOS-Specific Tests

```bash
# Test Homebrew installation
make brew-test

# macOS-specific integration tests
pytest tests/integration/ -v -k "macos"
```

### Linux-Specific Tests

```bash
# Docker tests
pytest tests/integration/test_docker_wrapper.py -v

# Native mode tests
make native-test
```

---

## Continuous Integration

### GitHub Actions (Cross-Platform)

Runs on every PR and push to `main`:

- **Platforms**: Ubuntu, Windows, macOS
- **Python**: 3.12
- **Tests**:
  - Linting and formatting
  - Type checking (mypy)
  - Unit tests
  - Integration tests
  - Windows-specific tests (Windows only)
  - Performance benchmarks

**View Results**: Check the "Cross-Platform Testing" workflow in GitHub Actions.

### CircleCI (Linux Deployment)

Runs on `develop` and `main` branches:

- **develop**: Fast checks (`make ci-quick`)
- **main**: Full suite (`make ci`) + build validation
- **Release tags**: Full pipeline + deployment

**No Conflicts**: GitHub Actions and CircleCI complement each other:
- GitHub Actions = Cross-platform validation
- CircleCI = Linux testing + deployments

---

## Debugging Tests

### Running Tests with Verbose Output

```bash
# Very verbose output
pytest tests/ -vv

# Show print statements
pytest tests/ -s

# Show local variables on failure
pytest tests/ -l

# Stop on first failure
pytest tests/ -x
```

### Running Specific Tests

```bash
# Run single test file
pytest tests/ci/test_cross_platform.py

# Run single test class
pytest tests/ci/test_cross_platform.py::TestPathHandling

# Run single test method
pytest tests/ci/test_cross_platform.py::TestPathHandling::test_path_normalization
```

### Debugging Test Failures

```bash
# Drop into debugger on failure
pytest tests/ --pdb

# Show full traceback
pytest tests/ --tb=long

# Show short traceback
pytest tests/ --tb=short
```

---

## Test Isolation

### Using tmp_path Fixture

```python
def test_file_operations(tmp_path: Path) -> None:
    """Test using temporary directory."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    assert test_file.exists()
    # Cleaned up automatically after test
```

### Mocking External Dependencies

```python
from unittest.mock import Mock, patch

def test_with_mock() -> None:
    """Test with mocked subprocess."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = Mock(returncode=0, stdout="success")

        # Test code here
```

---

## Writing New Tests

### Test Naming Conventions

```python
# Unit test
def test_function_name_behavior() -> None:
    """Test that function_name does X when Y."""
    pass

# Integration test
@pytest.mark.integration
def test_system_integration() -> None:
    """Test integration between components."""
    pass

# Platform-specific test
@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
def test_windows_feature() -> None:
    """Test Windows-specific feature."""
    pass
```

### Test Structure

```python
import pytest
from pathlib import Path


class TestFeatureName:
    """Test feature description."""

    def test_basic_behavior(self) -> None:
        """Test basic behavior."""
        # Arrange
        input_data = "test"

        # Act
        result = function_under_test(input_data)

        # Assert
        assert result == expected_output

    def test_edge_case(self, tmp_path: Path) -> None:
        """Test edge case behavior."""
        # Use fixtures
        test_file = tmp_path / "test.txt"

        # Test code
        assert condition
```

---

## Common Issues

### Tests Pass Locally But Fail in CI

**Cause**: Platform-specific behavior differences

**Solution**:
1. Run tests on actual target platform (Windows, macOS)
2. Use GitHub Actions to test cross-platform
3. Add platform-specific skips if necessary

### Import Errors

**Cause**: Missing dependencies or wrong Python path

**Solution**:
```bash
# Ensure dependencies installed
pip install -r requirements/dev.txt

# Ensure using virtual environment
which python  # Should show .venv/bin/python

# On Windows
where python  # Should show .venv\Scripts\python.exe
```

### Docker Tests Failing

**Cause**: Docker not running or not available

**Solution**:
```bash
# Check Docker
docker --version
docker ps

# Start Docker Desktop (macOS/Windows)
# Or start Docker daemon (Linux)
sudo systemctl start docker
```

---

## CI/CD Integration

### Running Tests Like CI

```bash
# Run exactly what GitHub Actions runs
make lint
make unit
make integration
make regression

# Full CI suite
make ci
```

### Pre-Commit Hooks

Kekkai uses pre-commit hooks to ensure code quality:

```bash
# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files

# Skip hooks (not recommended)
git commit --no-verify
```

---

## Performance Tips

### Faster Test Runs

```bash
# Run tests in parallel (requires pytest-xdist)
pytest tests/ -n auto

# Run only failed tests
pytest tests/ --lf

# Run tests matching pattern
pytest tests/ -k "windows"
```

### Test Selection

```bash
# Skip slow tests
pytest tests/ -m "not slow"

# Skip integration tests
pytest tests/ -m "not integration"

# Run only unit tests
pytest tests/ -m "not integration and not e2e and not regression"
```

---

## Related Documentation

- [CI/CD Architecture](./ci-cd.md)
- [Windows Installation](../installation/windows.md)
- [Contributing Guide](../../CONTRIBUTING.md)

---

## Support

**For testing issues**:
- GitHub: [kademoslabs/kekkai/issues](https://github.com/kademoslabs/kekkai/issues)
- Label: `testing`, `ci`
