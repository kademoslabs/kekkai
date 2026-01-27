"""Regression tests for Scoop backward compatibility."""

import pytest

from kekkai_core.windows.scoop import generate_scoop_manifest, validate_scoop_manifest


@pytest.mark.regression
class TestScoopBackwardsCompatibility:
    """Test backward compatibility for Scoop manifests."""

    def test_old_manifest_format_still_works(self) -> None:
        """Ensure manifest format from v0.0.1 still generates correctly."""
        # Generate manifest with old-style parameters
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Should validate successfully
        assert validate_scoop_manifest(manifest) is True

        # Should have all expected fields
        assert manifest["version"] == "0.0.1"
        assert "installer" in manifest
        assert "uninstaller" in manifest
        assert "checkver" in manifest
        assert "autoupdate" in manifest

    def test_python_version_compatibility(self) -> None:
        """Test manifest generation with different Python version requirements."""
        # Test with Python 3.12 (current requirement)
        manifest_312 = generate_scoop_manifest(
            version="0.0.1",
            sha256="b" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            python_version="3.12",
        )

        assert validate_scoop_manifest(manifest_312) is True

        # Test with Python 3.13 (future requirement)
        manifest_313 = generate_scoop_manifest(
            version="0.0.1",
            sha256="c" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            python_version="3.13",
        )

        assert validate_scoop_manifest(manifest_313) is True

    def test_semver_prerelease_versions(self) -> None:
        """Test manifest generation with semver pre-release versions."""
        # Test release candidate
        manifest_rc = generate_scoop_manifest(
            version="0.0.1-rc1",
            sha256="d" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1-rc1/test.whl",
        )

        assert validate_scoop_manifest(manifest_rc) is True
        assert manifest_rc["version"] == "0.0.1-rc1"

        # Test alpha version
        manifest_alpha = generate_scoop_manifest(
            version="0.0.1-alpha.1",
            sha256="e" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1-alpha.1/test.whl",
        )

        assert validate_scoop_manifest(manifest_alpha) is True
        assert manifest_alpha["version"] == "0.0.1-alpha.1"

        # Test beta version
        manifest_beta = generate_scoop_manifest(
            version="0.0.1-beta",
            sha256="f" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1-beta/test.whl",
        )

        assert validate_scoop_manifest(manifest_beta) is True

    def test_upgrade_from_old_to_new_version(self) -> None:
        """Test upgrading from older version to newer version."""
        # Old version
        manifest_old = generate_scoop_manifest(
            version="0.0.1",
            sha256="1" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # New version
        manifest_new = generate_scoop_manifest(
            version="0.0.2",
            sha256="2" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.2/test.whl",
        )

        # Both should validate
        assert validate_scoop_manifest(manifest_old) is True
        assert validate_scoop_manifest(manifest_new) is True

        # Structure should be compatible
        assert set(manifest_old.keys()) == set(manifest_new.keys())

    def test_installer_script_structure_unchanged(self) -> None:
        """Verify installer script structure hasn't changed."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="3" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Verify installer structure
        assert "installer" in manifest
        assert "script" in manifest["installer"]
        assert isinstance(manifest["installer"]["script"], list)

        # Verify key commands are present
        script = manifest["installer"]["script"]
        assert any("python --version" in line or "pythonVersion" in line for line in script)
        assert any("pip install" in line for line in script)
        assert any("--force-reinstall" in line for line in script)
        assert any("--no-deps" in line for line in script)

    def test_uninstaller_script_structure_unchanged(self) -> None:
        """Verify uninstaller script structure hasn't changed."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="4" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Verify uninstaller structure
        assert "uninstaller" in manifest
        assert "script" in manifest["uninstaller"]
        assert isinstance(manifest["uninstaller"]["script"], list)

        # Verify uninstall command present
        script = manifest["uninstaller"]["script"]
        assert any("pip uninstall" in line and "-y" in line for line in script)


@pytest.mark.regression
class TestDistributionTriggerCompatibility:
    """Test compatibility with distribution trigger system."""

    def test_manifest_compatible_with_trigger_payload(self) -> None:
        """Verify manifest can be generated from trigger payload."""
        # Simulate trigger payload
        version = "0.0.1"
        sha256 = "5" * 64
        whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

        # Generate manifest from payload
        manifest = generate_scoop_manifest(
            version=version,
            sha256=sha256,
            whl_url=whl_url,
        )

        # Should validate successfully
        assert validate_scoop_manifest(manifest) is True
        assert manifest["version"] == version
        assert manifest["hash"] == sha256
        assert manifest["url"] == whl_url

    def test_github_release_url_format(self) -> None:
        """Verify GitHub release URL format is compatible."""
        version = "0.0.1"
        whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

        manifest = generate_scoop_manifest(
            version=version,
            sha256="6" * 64,
            whl_url=whl_url,
        )

        # Verify URL format
        assert "github.com" in manifest["url"]
        assert "releases/download" in manifest["url"]
        assert f"v{version}" in manifest["url"]
        assert ".whl" in manifest["url"]

    def test_autoupdate_url_template_format(self) -> None:
        """Verify autoupdate URL template uses correct format."""
        manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="7" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Verify autoupdate template
        assert "autoupdate" in manifest
        assert "url" in manifest["autoupdate"]

        autoupdate_url = manifest["autoupdate"]["url"]
        assert "$version" in autoupdate_url
        assert "github.com" in autoupdate_url
        assert "kekkai-$version-py3-none-any.whl" in autoupdate_url
