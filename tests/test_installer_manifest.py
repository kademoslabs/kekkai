"""Unit tests for installer manifests."""

from __future__ import annotations

from unittest.mock import patch

from kekkai.installer import (
    TOOL_MANIFESTS,
    get_expected_hash,
    get_manifest,
    validate_manifest_url,
)


class TestToolManifests:
    """Test tool manifest definitions."""

    def test_trivy_manifest_exists(self) -> None:
        manifest = get_manifest("trivy")
        assert manifest is not None
        assert manifest.name == "trivy"
        assert manifest.version
        assert manifest.sha256

    def test_semgrep_manifest_exists(self) -> None:
        manifest = get_manifest("semgrep")
        assert manifest is not None
        assert manifest.name == "semgrep"
        assert manifest.archive_type == "zip"

    def test_gitleaks_manifest_exists(self) -> None:
        manifest = get_manifest("gitleaks")
        assert manifest is not None
        assert manifest.name == "gitleaks"

    def test_unknown_tool_returns_none(self) -> None:
        assert get_manifest("unknown_tool") is None

    def test_all_manifests_have_required_fields(self) -> None:
        for name, manifest in TOOL_MANIFESTS.items():
            assert manifest.name == name
            assert manifest.version
            assert manifest.url_template
            assert manifest.sha256
            assert manifest.archive_type in ("tar.gz", "zip")


class TestGetExpectedHash:
    """Test expected hash retrieval."""

    def test_get_hash_for_supported_platform(self) -> None:
        manifest = get_manifest("trivy")
        assert manifest is not None

        with patch("kekkai.installer.manifest.get_platform_key", return_value="linux_amd64"):
            expected = get_expected_hash(manifest)
            assert expected is not None
            assert len(expected) == 64  # SHA256 hex length

    def test_get_hash_for_unsupported_platform(self) -> None:
        manifest = get_manifest("trivy")
        assert manifest is not None

        with patch("kekkai.installer.manifest.get_platform_key", return_value="freebsd_amd64"):
            expected = get_expected_hash(manifest)
            assert expected is None


class TestValidateManifestUrl:
    """Test URL validation."""

    def test_valid_trivy_url(self) -> None:
        url = "https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy.tar.gz"
        assert validate_manifest_url(url) is True

    def test_valid_semgrep_url(self) -> None:
        url = "https://github.com/semgrep/semgrep/releases/download/v1.0.0/semgrep.zip"
        assert validate_manifest_url(url) is True

    def test_valid_gitleaks_url(self) -> None:
        url = "https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/gitleaks.tar.gz"
        assert validate_manifest_url(url) is True

    def test_invalid_domain_rejected(self) -> None:
        url = "https://evil.com/malware.tar.gz"
        assert validate_manifest_url(url) is False

    def test_http_rejected(self) -> None:
        url = "http://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy.tar.gz"
        assert validate_manifest_url(url) is False

    def test_different_github_repo_rejected(self) -> None:
        url = "https://github.com/attacker/trivy/releases/download/v0.58.1/trivy.tar.gz"
        assert validate_manifest_url(url) is False

    def test_github_non_release_rejected(self) -> None:
        url = "https://github.com/aquasecurity/trivy/raw/main/trivy.tar.gz"
        assert validate_manifest_url(url) is False
