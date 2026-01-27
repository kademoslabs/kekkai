"""Integration tests for Chocolatey package installation.

These tests verify end-to-end Chocolatey installation workflows.
Most tests require Windows and admin privileges, so they're marked
appropriately and will be skipped on other platforms.
"""

import sys
from pathlib import Path

import pytest

from kekkai_core.windows.chocolatey import generate_chocolatey_package_structure


class TestChocolateyInstallation:
    """Test Chocolatey installation workflows."""

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.requires_admin
    @pytest.mark.integration
    def test_choco_install_kekkai(self, tmp_path: Path) -> None:
        """
        Full install → verify → uninstall workflow.

        NOTE: This test requires:
        - Windows OS
        - Administrator privileges
        - Chocolatey installed
        - Actual package built

        Skipped in CI due to admin requirement.
        """
        pytest.skip("Requires manual testing with actual Chocolatey package")

        # Steps (for manual testing):
        # 1. choco install kekkai -s . -y
        # 2. kekkai --version
        # 3. kekkai --help
        # 4. choco uninstall kekkai -y

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.requires_admin
    @pytest.mark.integration
    def test_choco_silent_install(self) -> None:
        """
        Enterprise silent installation test.

        Verifies installation works without user interaction.
        """
        pytest.skip("Requires manual testing with actual Chocolatey package")

        # Steps (for manual testing):
        # 1. choco install kekkai -y --force
        # 2. Verify no prompts
        # 3. kekkai --version

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.requires_admin
    @pytest.mark.integration
    def test_choco_upgrade_kekkai(self) -> None:
        """
        Upgrade from old version to new version.

        Verifies upgrade path works correctly.
        """
        pytest.skip("Requires manual testing with actual Chocolatey package")

        # Steps (for manual testing):
        # 1. choco install kekkai --version 0.0.1 -y
        # 2. kekkai --version  # Should show 0.0.1
        # 3. choco upgrade kekkai -y
        # 4. kekkai --version  # Should show newer version

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.requires_admin
    @pytest.mark.integration
    def test_choco_uninstall_cleanup(self) -> None:
        """
        Verify uninstallation removes all files cleanly.
        """
        pytest.skip("Requires manual testing with actual Chocolatey package")

        # Steps (for manual testing):
        # 1. choco install kekkai -y
        # 2. Note installation paths
        # 3. choco uninstall kekkai -y
        # 4. Verify no kekkai files remain in Python site-packages


class TestChocolateyPublishing:
    """Test Chocolatey package publishing workflows."""

    @pytest.mark.integration
    def test_local_package_build(self, tmp_path: Path) -> None:
        """
        Build Chocolatey package locally using choco pack.

        This tests package structure generation without requiring
        actual Chocolatey installation.
        """
        # Generate package structure
        version = "0.0.1"
        sha256 = "a" * 64

        structure = generate_chocolatey_package_structure(version, sha256)

        # Write package files to temp directory
        package_dir = tmp_path / "kekkai-package"
        package_dir.mkdir()

        for file_path, content in structure.items():
            file_full_path = package_dir / file_path
            file_full_path.parent.mkdir(parents=True, exist_ok=True)
            file_full_path.write_text(content, encoding="utf-8")

        # Verify files exist
        assert (package_dir / "kekkai.nuspec").exists()
        assert (package_dir / "tools" / "chocolateyinstall.ps1").exists()
        assert (package_dir / "tools" / "chocolateyuninstall.ps1").exists()

        # Verify nuspec is valid XML
        nuspec_content = (package_dir / "kekkai.nuspec").read_text(encoding="utf-8")
        assert '<?xml version="1.0" encoding="utf-8"?>' in nuspec_content
        assert "<package" in nuspec_content
        assert "<metadata>" in nuspec_content

        # NOTE: Actual 'choco pack' requires Chocolatey to be installed
        # This test verifies structure only

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.integration
    def test_local_package_install(self, tmp_path: Path) -> None:
        """
        Install from locally built package.

        This tests installation from a local package source,
        which is useful for testing before publishing.
        """
        pytest.skip("Requires Chocolatey installed and manual testing")

        # Steps (for manual testing):
        # 1. Generate package structure
        # 2. choco pack
        # 3. choco install kekkai -s . -y
        # 4. Verify installation


class TestChocolateyPackageValidation:
    """Test package structure validation without actual installation."""

    @pytest.mark.integration
    def test_package_structure_completeness(self, tmp_path: Path) -> None:
        """Verify generated package structure is complete."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Required files
        assert "kekkai.nuspec" in structure
        assert "tools/chocolateyinstall.ps1" in structure
        assert "tools/chocolateyuninstall.ps1" in structure

        # Nuspec should be valid XML
        nuspec_xml = structure["kekkai.nuspec"]
        assert "<?xml version" in nuspec_xml
        assert "<package" in nuspec_xml
        assert "kekkai" in nuspec_xml

        # Scripts should be PowerShell
        install_script = structure["tools/chocolateyinstall.ps1"]
        assert "$ErrorActionPreference" in install_script
        assert "python -m pip install" in install_script

        uninstall_script = structure["tools/chocolateyuninstall.ps1"]
        assert "pip uninstall" in uninstall_script

    @pytest.mark.integration
    def test_package_version_consistency(self, tmp_path: Path) -> None:
        """Verify version is consistent across package files."""
        version = "1.2.3"
        structure = generate_chocolatey_package_structure(
            version=version,
            sha256="a" * 64,
        )

        # Version should appear in nuspec
        nuspec = structure["kekkai.nuspec"]
        assert f"<version>{version}</version>" in nuspec

        # Version should appear in install script
        install_script = structure["tools/chocolateyinstall.ps1"]
        assert version in install_script

    @pytest.mark.integration
    def test_package_sha256_consistency(self, tmp_path: Path) -> None:
        """Verify SHA256 is consistent in package files."""
        sha256 = "abc123def456" * 5 + "abcd"  # 64 chars
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256=sha256,
        )

        # SHA256 should appear in install script
        install_script = structure["tools/chocolateyinstall.ps1"]
        assert sha256 in install_script


class TestChocolateyEnterpriseScenarios:
    """Test enterprise deployment scenarios."""

    @pytest.mark.integration
    def test_package_supports_silent_install(self, tmp_path: Path) -> None:
        """Verify package structure supports silent installation."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Silent install should not require user interaction
        # ErrorActionPreference = Stop will cause failures to abort
        assert "$ErrorActionPreference = 'Stop'" in install_script

        # Should not have Read-Host or other interactive commands
        assert "Read-Host" not in install_script

    @pytest.mark.integration
    def test_package_handles_offline_scenarios(self, tmp_path: Path) -> None:
        """Verify package structure documents offline installation."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        # Install script downloads from GitHub
        # For offline, wheel would need to be pre-downloaded
        install_script = structure["tools/chocolateyinstall.ps1"]
        assert "Invoke-WebRequest" in install_script

        # NOTE: Offline installation would require manual wheel download
        # and modification of install script to use local path

    @pytest.mark.integration
    def test_package_error_messages_are_clear(self, tmp_path: Path) -> None:
        """Verify package provides clear error messages."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should have informative error messages
        assert "Python" in install_script
        assert "required" in install_script
        assert "throw" in install_script or "Write-Error" in install_script

        # Errors should mention what failed
        assert "checksum" in install_script.lower() or "failed" in install_script.lower()


class TestChocolateySecurityValidation:
    """Test security aspects of Chocolatey package."""

    @pytest.mark.integration
    def test_package_uses_https_only(self, tmp_path: Path) -> None:
        """Verify all URLs use HTTPS."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        for file_content in structure.values():
            # Check for any HTTP URLs (not HTTPS)
            if "http://" in file_content and "https://" not in file_content.replace("http://", ""):
                pytest.fail(f"Found HTTP URL in: {file_content[:100]}")

    @pytest.mark.integration
    def test_package_verifies_checksums(self, tmp_path: Path) -> None:
        """Verify package validates file checksums."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should use Get-FileHash to verify checksum
        assert "Get-FileHash" in install_script
        assert "SHA256" in install_script
        assert "checksum" in install_script.lower()

    @pytest.mark.integration
    def test_package_no_arbitrary_code_execution(self, tmp_path: Path) -> None:
        """Verify package doesn't execute arbitrary code."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should not use Invoke-Expression
        assert "Invoke-Expression" not in install_script
        assert " iex " not in install_script.lower()

        # Should not pipe downloads to execution
        assert "| Invoke-Expression" not in install_script
        assert "| iex" not in install_script.lower()
