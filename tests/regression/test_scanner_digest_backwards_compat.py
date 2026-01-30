"""Regression tests for scanner digest backwards compatibility.

Ensures the API for providing custom digests remains backwards compatible
after changing defaults to None.
"""

from __future__ import annotations

import pytest

from kekkai.scanners.gitleaks import GITLEAKS_IMAGE, GitleaksScanner
from kekkai.scanners.semgrep import SEMGREP_IMAGE, SemgrepScanner
from kekkai.scanners.trivy import TRIVY_IMAGE, TrivyScanner

pytestmark = pytest.mark.regression


class TestTrivyBackwardsCompat:
    """Regression tests for Trivy scanner API stability."""

    def test_image_constant_unchanged(self) -> None:
        """Verify TRIVY_IMAGE constant is unchanged."""
        assert TRIVY_IMAGE == "aquasec/trivy"

    def test_constructor_signature_stable(self) -> None:
        """Verify constructor accepts all expected parameters."""
        scanner = TrivyScanner(
            image="custom/image",
            digest="sha256:custom",
            timeout_seconds=300,
        )
        assert scanner._image == "custom/image"
        assert scanner._digest == "sha256:custom"
        assert scanner._timeout == 300

    def test_default_image_used(self) -> None:
        """Verify default image is used when not specified."""
        scanner = TrivyScanner()
        assert scanner._image == TRIVY_IMAGE

    def test_properties_available(self) -> None:
        """Verify public properties remain available."""
        scanner = TrivyScanner()
        assert scanner.name == "trivy"
        assert scanner.scan_type == "Trivy Scan"
        assert scanner.backend_used is None


class TestSemgrepBackwardsCompat:
    """Regression tests for Semgrep scanner API stability."""

    def test_image_constant_unchanged(self) -> None:
        """Verify SEMGREP_IMAGE constant is unchanged."""
        assert SEMGREP_IMAGE == "returntocorp/semgrep"

    def test_constructor_signature_stable(self) -> None:
        """Verify constructor accepts all expected parameters."""
        scanner = SemgrepScanner(
            image="custom/image",
            digest="sha256:custom",
            timeout_seconds=300,
            config="p/security-audit",
        )
        assert scanner._image == "custom/image"
        assert scanner._digest == "sha256:custom"
        assert scanner._timeout == 300
        assert scanner._config == "p/security-audit"

    def test_default_image_used(self) -> None:
        """Verify default image is used when not specified."""
        scanner = SemgrepScanner()
        assert scanner._image == SEMGREP_IMAGE

    def test_properties_available(self) -> None:
        """Verify public properties remain available."""
        scanner = SemgrepScanner()
        assert scanner.name == "semgrep"
        assert scanner.scan_type == "Semgrep JSON Report"
        assert scanner.backend_used is None


class TestGitleaksBackwardsCompat:
    """Regression tests for Gitleaks scanner API stability."""

    def test_image_constant_unchanged(self) -> None:
        """Verify GITLEAKS_IMAGE constant is unchanged."""
        assert GITLEAKS_IMAGE == "zricethezav/gitleaks"

    def test_constructor_signature_stable(self) -> None:
        """Verify constructor accepts all expected parameters."""
        scanner = GitleaksScanner(
            image="custom/image",
            digest="sha256:custom",
            timeout_seconds=120,
        )
        assert scanner._image == "custom/image"
        assert scanner._digest == "sha256:custom"
        assert scanner._timeout == 120

    def test_default_image_used(self) -> None:
        """Verify default image is used when not specified."""
        scanner = GitleaksScanner()
        assert scanner._image == GITLEAKS_IMAGE

    def test_properties_available(self) -> None:
        """Verify public properties remain available."""
        scanner = GitleaksScanner()
        assert scanner.name == "gitleaks"
        assert scanner.scan_type == "Gitleaks Scan"
        assert scanner.backend_used is None
