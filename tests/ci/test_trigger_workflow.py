"""Unit tests for CI/CD distribution trigger workflows."""

import hashlib
import json
from pathlib import Path

import pytest

from kekkai_core.ci.metadata import (
    calculate_sha256,
    extract_tarball_url,
    extract_version_from_tag,
    format_dispatch_payload,
)
from kekkai_core.ci.validators import (
    validate_github_token,
    validate_repo_format,
    validate_semver,
    verify_checksum,
)


class TestMetadataExtraction:
    """Test metadata extraction utilities."""

    def test_version_extraction_from_tag(self) -> None:
        """Extract version 0.0.1 from tag v0.0.1."""
        version = extract_version_from_tag("v0.0.1")
        assert version == "0.0.1"

    def test_version_extraction_from_rc_tag(self) -> None:
        """Extract version 0.0.1-rc1 from tag v0.0.1-rc1."""
        version = extract_version_from_tag("v0.0.1-rc1")
        assert version == "0.0.1-rc1"

    def test_version_extraction_without_v_prefix(self) -> None:
        """Extract version from tag without 'v' prefix."""
        version = extract_version_from_tag("0.0.1")
        assert version == "0.0.1"

    def test_version_extraction_with_build_metadata(self) -> None:
        """Extract version with build metadata."""
        version = extract_version_from_tag("v1.2.3+build.123")
        assert version == "1.2.3+build.123"

    def test_invalid_tag_format_raises_error(self) -> None:
        """Reject tags not matching semantic versioning."""
        with pytest.raises(ValueError, match="Invalid tag format"):
            extract_version_from_tag("invalid")

        with pytest.raises(ValueError, match="Invalid tag format"):
            extract_version_from_tag("v1.2")

        with pytest.raises(ValueError, match="Invalid tag format"):
            extract_version_from_tag("1.2.3.4")

    def test_empty_tag_raises_error(self) -> None:
        """Reject empty tag."""
        with pytest.raises(ValueError, match="Tag cannot be empty"):
            extract_version_from_tag("")

    def test_sha256_calculation_matches_tarball(self, tmp_path: Path) -> None:
        """Verify SHA256 of test file matches expected checksum."""
        test_file = tmp_path / "test.tar.gz"
        test_content = b"test content for tarball"
        test_file.write_bytes(test_content)

        expected_sha256 = hashlib.sha256(test_content).hexdigest()
        actual_sha256 = calculate_sha256(test_file)

        assert actual_sha256 == expected_sha256

    def test_sha256_calculation_large_file(self, tmp_path: Path) -> None:
        """Verify SHA256 calculation works for large files."""
        test_file = tmp_path / "large.tar.gz"
        # Create 1MB file
        test_content = b"x" * (1024 * 1024)
        test_file.write_bytes(test_content)

        expected_sha256 = hashlib.sha256(test_content).hexdigest()
        actual_sha256 = calculate_sha256(test_file)

        assert actual_sha256 == expected_sha256

    def test_sha256_calculation_missing_file(self, tmp_path: Path) -> None:
        """Verify error handling for missing file."""
        missing_file = tmp_path / "missing.tar.gz"

        with pytest.raises(FileNotFoundError):
            calculate_sha256(missing_file)

    def test_tarball_url_generation(self) -> None:
        """Verify tarball URL generation."""
        url = extract_tarball_url("kademoslabs/kekkai", "0.0.1")
        assert url == "https://github.com/kademoslabs/kekkai/archive/refs/tags/v0.0.1.tar.gz"

    def test_tarball_url_removes_v_prefix(self) -> None:
        """Verify tarball URL generation handles 'v' prefix."""
        url = extract_tarball_url("kademoslabs/kekkai", "v0.0.1")
        assert url == "https://github.com/kademoslabs/kekkai/archive/refs/tags/v0.0.1.tar.gz"


class TestRepositoryDispatch:
    """Test repository dispatch payload formatting."""

    def test_homebrew_dispatch_payload_structure(self) -> None:
        """Verify JSON payload contains version and sha256."""
        payload = format_dispatch_payload(
            "kekkai-release",
            "0.0.1",
            "abc123",
        )

        assert payload["event_type"] == "kekkai-release"
        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == "0.0.1"
        assert payload["client_payload"]["sha256"] == "abc123"

    def test_docker_dispatch_payload_structure(self) -> None:
        """Verify JSON payload contains tag for Docker workflow."""
        payload = format_dispatch_payload("docker-release", "0.0.1")

        assert payload["event_type"] == "docker-release"
        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == "0.0.1"

    def test_payload_without_sha256(self) -> None:
        """Verify payload works without SHA256."""
        payload = format_dispatch_payload("test-release", "0.0.1")

        assert payload["event_type"] == "test-release"
        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == "0.0.1"
        assert "sha256" not in payload["client_payload"]

    def test_payload_json_serializable(self) -> None:
        """Verify payload is JSON serializable."""
        payload = format_dispatch_payload("test", "0.0.1", "abc123")

        # Should not raise exception
        json_str = json.dumps(payload)
        assert isinstance(json_str, str)

        # Verify round-trip
        parsed = json.loads(json_str)
        assert parsed == payload


class TestValidators:
    """Test validation utilities."""

    def test_validate_semver_valid_versions(self) -> None:
        """Verify valid semver versions pass validation."""
        assert validate_semver("0.0.1") is True
        assert validate_semver("1.2.3") is True
        assert validate_semver("10.20.30") is True
        assert validate_semver("1.2.3-rc1") is True
        assert validate_semver("1.2.3-alpha.1") is True
        assert validate_semver("1.2.3+build.123") is True
        assert validate_semver("1.2.3-rc1+build.123") is True

    def test_validate_semver_invalid_versions(self) -> None:
        """Verify invalid versions fail validation."""
        assert validate_semver("v0.0.1") is False  # Has 'v' prefix
        assert validate_semver("1.2") is False  # Missing patch
        assert validate_semver("1.2.3.4") is False  # Too many parts
        assert validate_semver("1.x.3") is False  # Non-numeric
        assert validate_semver("") is False  # Empty

    def test_verify_checksum_matching(self, tmp_path: Path) -> None:
        """Verify checksum verification with matching checksums."""
        test_file = tmp_path / "test.tar.gz"
        test_content = b"test content"
        test_file.write_bytes(test_content)

        expected_sha256 = hashlib.sha256(test_content).hexdigest()

        assert verify_checksum(test_file, expected_sha256) is True

    def test_verify_checksum_case_insensitive(self, tmp_path: Path) -> None:
        """Verify checksum comparison is case-insensitive."""
        test_file = tmp_path / "test.tar.gz"
        test_content = b"test content"
        test_file.write_bytes(test_content)

        expected_sha256 = hashlib.sha256(test_content).hexdigest()

        # Test with uppercase
        assert verify_checksum(test_file, expected_sha256.upper()) is True

    def test_verify_checksum_not_matching(self, tmp_path: Path) -> None:
        """Verify checksum verification fails with wrong checksum."""
        test_file = tmp_path / "test.tar.gz"
        test_file.write_bytes(b"test content")

        wrong_sha256 = "0" * 64

        assert verify_checksum(test_file, wrong_sha256) is False

    def test_validate_repo_format_valid(self) -> None:
        """Verify valid repository formats pass validation."""
        assert validate_repo_format("kademoslabs/kekkai") is True
        assert validate_repo_format("user/repo") is True
        assert validate_repo_format("org-name/repo-name") is True
        assert validate_repo_format("user_name/repo_name") is True

    def test_validate_repo_format_invalid(self) -> None:
        """Verify invalid repository formats fail validation."""
        assert validate_repo_format("kademoslabs") is False  # Missing slash
        assert validate_repo_format("kademoslabs/kekkai/extra") is False  # Too many parts
        assert validate_repo_format("kademoslabs/") is False  # Missing repo name
        assert validate_repo_format("/kekkai") is False  # Missing owner

    def test_validate_github_token_valid(self) -> None:
        """Verify valid token formats pass basic validation."""
        # Classic token (40 chars)
        assert validate_github_token("ghp_" + "x" * 36) is True

        # Fine-grained token
        assert validate_github_token("github_pat_" + "x" * 30) is True

    def test_validate_github_token_invalid(self) -> None:
        """Verify invalid token formats fail validation."""
        assert validate_github_token("") is False  # Empty
        assert validate_github_token("short") is False  # Too short
        assert validate_github_token("x" * 10) is False  # Too short


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_missing_github_token_fails_gracefully(self) -> None:
        """Workflow fails with clear message if token missing."""
        # This is tested in the workflow YAML validation
        # Here we test the validator function
        assert validate_github_token("") is False
        assert validate_github_token(None) is False  # type: ignore[arg-type]

    def test_invalid_version_format_fails_validation(self) -> None:
        """Workflow fails if version doesn't match semver."""
        with pytest.raises(ValueError):
            extract_version_from_tag("invalid-version")

        assert validate_semver("not-semver") is False

    def test_tarball_download_failure_handled(self, tmp_path: Path) -> None:
        """Verify SHA256 calculation handles missing file."""
        missing_file = tmp_path / "nonexistent.tar.gz"

        with pytest.raises(FileNotFoundError):
            calculate_sha256(missing_file)
