"""Unit tests for Scoop manifest generation and validation."""

import json

import pytest

from kekkai_core.windows.scoop import (
    format_scoop_manifest_json,
    generate_scoop_checksum_file,
    generate_scoop_manifest,
    validate_scoop_manifest,
)


class TestScoopManifest:
    """Test Scoop manifest generation."""

    def test_manifest_json_is_valid(self) -> None:
        """Verify generated manifest is valid JSON."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Should be JSON serializable
        json_str = json.dumps(manifest)
        assert isinstance(json_str, str)

        # Should be parseable
        parsed = json.loads(json_str)
        assert parsed == manifest

    def test_manifest_has_required_fields(self) -> None:
        """Check version, description, homepage, license fields present."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="b" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "version" in manifest
        assert "description" in manifest
        assert "homepage" in manifest
        assert "license" in manifest
        assert "url" in manifest
        assert "hash" in manifest

        assert manifest["version"] == "0.0.1"
        assert manifest["license"] == "MIT"

    def test_architecture_specifies_url(self) -> None:
        """Verify URL is specified in manifest."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="c" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "url" in manifest
        assert manifest["url"].startswith("https://")

    def test_url_points_to_github_release(self) -> None:
        """Verify URL follows GitHub release pattern."""
        whl_url = "https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl"
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="d" * 64,
            whl_url=whl_url,
        )

        assert manifest["url"] == whl_url
        assert "github.com" in manifest["url"]
        assert "releases/download" in manifest["url"]

    def test_depends_on_python(self) -> None:
        """Verify Python listed as dependency."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="e" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "depends" in manifest
        assert manifest["depends"] == "python"

    def test_installer_script_uses_pip(self) -> None:
        """Verify installer uses 'python -m pip install'."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="f" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "installer" in manifest
        assert "script" in manifest["installer"]

        # Check script contains pip install command
        script = manifest["installer"]["script"]
        assert isinstance(script, list)
        assert any("pip install" in line for line in script)
        assert any("--force-reinstall" in line for line in script)
        assert any("--no-deps" in line for line in script)

    def test_uninstaller_script_removes_package(self) -> None:
        """Verify uninstaller uses 'pip uninstall -y'."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="1" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "uninstaller" in manifest
        assert "script" in manifest["uninstaller"]

        script = manifest["uninstaller"]["script"]
        assert isinstance(script, list)
        assert any("pip uninstall" in line for line in script)
        assert any("-y" in line for line in script)

    def test_checkver_uses_github(self) -> None:
        """Verify checkver points to GitHub repository."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="2" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "checkver" in manifest
        assert "github" in manifest["checkver"]
        assert "github.com" in manifest["checkver"]["github"]

    def test_autoupdate_url_template(self) -> None:
        """Verify autoupdate URL uses $version variable."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="3" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "autoupdate" in manifest
        assert "url" in manifest["autoupdate"]
        assert "$version" in manifest["autoupdate"]["url"]

    def test_invalid_version_format_raises_error(self) -> None:
        """Reject invalid version formats."""
        with pytest.raises(ValueError, match="Invalid version format"):
            generate_scoop_manifest(
                version="1.2",  # Missing patch version
                sha256="4" * 64,
                whl_url="https://github.com/test/test/releases/download/v1.2/test.whl",
            )

        with pytest.raises(ValueError, match="Invalid version format"):
            generate_scoop_manifest(
                version="v1.2.3",  # Has 'v' prefix
                sha256="5" * 64,
                whl_url="https://github.com/test/test/releases/download/v1.2.3/test.whl",
            )

    def test_non_https_url_raises_error(self) -> None:
        """Reject non-HTTPS URLs."""
        with pytest.raises(ValueError, match="must use HTTPS"):
            generate_scoop_manifest(
                version="0.0.1",
                sha256="6" * 64,
                whl_url="http://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

    def test_invalid_sha256_raises_error(self) -> None:
        """Reject invalid SHA256 format."""
        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            generate_scoop_manifest(
                version="0.0.1",
                sha256="short",  # Too short
                whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            generate_scoop_manifest(
                version="0.0.1",
                sha256="g" * 64,  # Invalid hex character
                whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

    def test_python_version_validation_in_script(self) -> None:
        """Verify installer validates Python version."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="7" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            python_version="3.12",
        )

        script = manifest["installer"]["script"]
        assert any("3.12" in line for line in script)
        assert any("pythonVersion" in line or "version" in line for line in script)


class TestScoopValidation:
    """Test Scoop manifest validation."""

    def test_valid_manifest_passes(self) -> None:
        """Verify valid manifest passes validation."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="8" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert validate_scoop_manifest(manifest) is True

    def test_missing_required_field_fails(self) -> None:
        """Verify missing required fields fail validation."""
        manifest = {
            "version": "0.0.1",
            # Missing other required fields
        }

        with pytest.raises(ValueError, match="Missing required field"):
            validate_scoop_manifest(manifest)

    def test_invalid_version_fails(self) -> None:
        """Verify invalid version format fails validation."""
        manifest = {
            "version": "1.2",  # Invalid
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "https://test.com/file.whl",
            "hash": "9" * 64,
        }

        with pytest.raises(ValueError, match="Invalid version format"):
            validate_scoop_manifest(manifest)

    def test_non_https_url_fails(self) -> None:
        """Verify non-HTTPS URL fails validation."""
        manifest = {
            "version": "0.0.1",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "http://test.com/file.whl",  # HTTP not HTTPS
            "hash": "a" * 64,
        }

        with pytest.raises(ValueError, match="must use HTTPS"):
            validate_scoop_manifest(manifest)

    def test_invalid_sha256_fails(self) -> None:
        """Verify invalid SHA256 fails validation."""
        manifest = {
            "version": "0.0.1",
            "description": "Test",
            "homepage": "https://test.com",
            "license": "MIT",
            "url": "https://test.com/file.whl",
            "hash": "short",  # Invalid
        }

        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            validate_scoop_manifest(manifest)


class TestScoopFormatting:
    """Test Scoop manifest formatting utilities."""

    def test_format_manifest_json_pretty_printed(self) -> None:
        """Verify JSON is pretty-printed with indentation."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="b" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        json_str = format_scoop_manifest_json(manifest)

        assert isinstance(json_str, str)
        assert "\n" in json_str  # Has newlines (pretty-printed)
        assert "  " in json_str  # Has indentation

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed == manifest

    def test_generate_checksum_file(self) -> None:
        """Verify checksum file generation."""
        checksum_file = generate_scoop_checksum_file(
            version="0.0.1",
            sha256="c" * 64,
        )

        assert "kekkai-0.0.1-py3-none-any.whl" in checksum_file
        assert "c" * 64 in checksum_file
        assert checksum_file.endswith("\n")
