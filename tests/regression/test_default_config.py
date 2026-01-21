"""Regression tests to ensure risky features are disabled by default.

These tests verify that DAST (ZAP) and runtime security (Falco) scanners
are not accidentally enabled without explicit user consent.

ASVS Requirements:
- V16.5.2: Secure degradation on failures
- Default deny for dangerous functionality
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.config import (
    FalcoSettings,
    ZapSettings,
    _parse_falco,
    _parse_zap,
    default_config,
)
from kekkai.scanners import OPTIONAL_SCANNERS, SCANNER_REGISTRY


@pytest.mark.regression
class TestDefaultScannerRegistry:
    """Verify the default scanner registry does NOT include risky scanners."""

    def test_zap_not_in_default_registry(self) -> None:
        """ZAP should not be in the default registry to prevent accidental DAST."""
        assert "zap" not in SCANNER_REGISTRY

    def test_falco_not_in_default_registry(self) -> None:
        """Falco should not be in the default registry to prevent accidental runtime monitoring."""
        assert "falco" not in SCANNER_REGISTRY

    def test_only_sast_sca_in_default_registry(self) -> None:
        """Only SAST/SCA scanners should be in the default registry."""
        expected = {"trivy", "semgrep", "gitleaks"}
        assert set(SCANNER_REGISTRY.keys()) == expected

    def test_optional_scanners_separate(self) -> None:
        """Optional scanners should be in a separate registry."""
        assert "zap" in OPTIONAL_SCANNERS
        assert "falco" in OPTIONAL_SCANNERS


@pytest.mark.regression
class TestZapDefaultsSecure:
    """Verify ZAP defaults are secure."""

    def test_zap_disabled_by_default(self) -> None:
        """ZAP should be disabled by default."""
        settings = ZapSettings()
        assert settings.enabled is False

    def test_zap_no_default_target(self) -> None:
        """ZAP should have no default target URL."""
        settings = ZapSettings()
        assert settings.target_url is None

    def test_zap_private_ips_blocked_by_default(self) -> None:
        """ZAP should block private IPs by default."""
        settings = ZapSettings()
        assert settings.allow_private_ips is False

    def test_zap_no_default_allowed_domains(self) -> None:
        """ZAP should have empty domain allowlist by default."""
        settings = ZapSettings()
        assert settings.allowed_domains == []

    def test_parse_zap_none_returns_none(self) -> None:
        """Parsing None should return None (not enabled)."""
        assert _parse_zap(None) is None

    def test_parse_zap_empty_dict_disabled(self) -> None:
        """Parsing empty dict should create disabled settings."""
        settings = _parse_zap({})
        assert settings is not None
        assert settings.enabled is False


@pytest.mark.regression
class TestFalcoDefaultsSecure:
    """Verify Falco defaults are secure."""

    def test_falco_disabled_by_default(self) -> None:
        """Falco should be disabled by default."""
        settings = FalcoSettings()
        assert settings.enabled is False

    def test_falco_no_default_rules_file(self) -> None:
        """Falco should have no default rules file."""
        settings = FalcoSettings()
        assert settings.rules_file is None

    def test_parse_falco_none_returns_none(self) -> None:
        """Parsing None should return None (not enabled)."""
        assert _parse_falco(None) is None

    def test_parse_falco_empty_dict_disabled(self) -> None:
        """Parsing empty dict should create disabled settings."""
        settings = _parse_falco({})
        assert settings is not None
        assert settings.enabled is False


@pytest.mark.regression
class TestConfigDefaultsSecure:
    """Verify overall config defaults are secure."""

    def test_default_config_no_zap(self, tmp_path: Path) -> None:
        """Default config should not include ZAP settings."""
        cfg = default_config(tmp_path)
        assert "zap" not in cfg

    def test_default_config_no_falco(self, tmp_path: Path) -> None:
        """Default config should not include Falco settings."""
        cfg = default_config(tmp_path)
        assert "falco" not in cfg

    def test_default_config_no_risky_scanners(self, tmp_path: Path) -> None:
        """Default config should not include risky scanners in scanner list."""
        cfg = default_config(tmp_path)
        scanners_value = cfg.get("scanners")
        if scanners_value is not None and isinstance(scanners_value, list | str):
            assert "zap" not in scanners_value
            assert "falco" not in scanners_value
