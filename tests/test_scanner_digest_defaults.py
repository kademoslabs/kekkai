"""Unit tests for scanner digest default handling.

Verifies that scanners work correctly with digest=None (default)
to allow Docker to pull architecture-appropriate images.
"""

from __future__ import annotations

from kekkai.scanners.gitleaks import GITLEAKS_DIGEST, GitleaksScanner
from kekkai.scanners.semgrep import SEMGREP_DIGEST, SemgrepScanner
from kekkai.scanners.trivy import TRIVY_DIGEST, TrivyScanner


class TestTrivyDigestDefaults:
    """Tests for Trivy scanner digest handling."""

    def test_default_digest_is_none(self) -> None:
        """Verify TRIVY_DIGEST constant is None."""
        assert TRIVY_DIGEST is None

    def test_scanner_accepts_none_digest(self) -> None:
        """Verify scanner initializes with None digest."""
        scanner = TrivyScanner()
        assert scanner._digest is None

    def test_scanner_accepts_explicit_none(self) -> None:
        """Verify scanner accepts explicit None digest parameter."""
        scanner = TrivyScanner(digest=None)
        assert scanner._digest is None

    def test_scanner_accepts_custom_digest(self) -> None:
        """Verify scanner accepts custom digest for backwards compatibility."""
        custom_digest = "sha256:abc123"
        scanner = TrivyScanner(digest=custom_digest)
        assert scanner._digest == custom_digest


class TestSemgrepDigestDefaults:
    """Tests for Semgrep scanner digest handling."""

    def test_default_digest_is_none(self) -> None:
        """Verify SEMGREP_DIGEST constant is None."""
        assert SEMGREP_DIGEST is None

    def test_scanner_accepts_none_digest(self) -> None:
        """Verify scanner initializes with None digest."""
        scanner = SemgrepScanner()
        assert scanner._digest is None

    def test_scanner_accepts_explicit_none(self) -> None:
        """Verify scanner accepts explicit None digest parameter."""
        scanner = SemgrepScanner(digest=None)
        assert scanner._digest is None

    def test_scanner_accepts_custom_digest(self) -> None:
        """Verify scanner accepts custom digest for backwards compatibility."""
        custom_digest = "sha256:def456"
        scanner = SemgrepScanner(digest=custom_digest)
        assert scanner._digest == custom_digest


class TestGitleaksDigestDefaults:
    """Tests for Gitleaks scanner digest handling."""

    def test_default_digest_is_none(self) -> None:
        """Verify GITLEAKS_DIGEST constant is None."""
        assert GITLEAKS_DIGEST is None

    def test_scanner_accepts_none_digest(self) -> None:
        """Verify scanner initializes with None digest."""
        scanner = GitleaksScanner()
        assert scanner._digest is None

    def test_scanner_accepts_explicit_none(self) -> None:
        """Verify scanner accepts explicit None digest parameter."""
        scanner = GitleaksScanner(digest=None)
        assert scanner._digest is None

    def test_scanner_accepts_custom_digest(self) -> None:
        """Verify scanner accepts custom digest for backwards compatibility."""
        custom_digest = "sha256:ghi789"
        scanner = GitleaksScanner(digest=custom_digest)
        assert scanner._digest == custom_digest
