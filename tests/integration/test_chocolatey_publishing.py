"""Integration tests for Chocolatey package publishing workflow.

These tests verify the automation and CI/CD aspects of Chocolatey publishing.
"""

import sys
from pathlib import Path

import pytest

from kekkai_core.windows.chocolatey import (
    generate_chocolatey_package_structure,
    generate_verification_file,
)


class TestChocolateyPublishingWorkflow:
    """Test Chocolatey publishing automation."""

    @pytest.mark.integration
    def test_package_generation_for_release(self, tmp_path: Path) -> None:
        """
        Verify package can be generated for a release.

        This simulates what the CI/CD pipeline would do.
        """
        version = "0.0.1"
        sha256 = "a" * 64

        # Generate package
        structure = generate_chocolatey_package_structure(version, sha256)

        # Write to disk
        package_dir = tmp_path / "chocolatey-package"
        package_dir.mkdir()

        for file_path, content in structure.items():
            full_path = package_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")

        # Verify all expected files exist
        assert (package_dir / "kekkai.nuspec").exists()
        assert (package_dir / "tools" / "chocolateyinstall.ps1").exists()
        assert (package_dir / "tools" / "chocolateyuninstall.ps1").exists()

        # Verify files are not empty
        assert (package_dir / "kekkai.nuspec").stat().st_size > 0
        assert (package_dir / "tools" / "chocolateyinstall.ps1").stat().st_size > 0
        assert (package_dir / "tools" / "chocolateyuninstall.ps1").stat().st_size > 0

    @pytest.mark.integration
    def test_verification_file_generation(self, tmp_path: Path) -> None:
        """
        Verify VERIFICATION.txt can be generated for moderation.
        """
        version = "0.0.1"
        sha256 = "abc123def456" * 5 + "abcd"

        verification = generate_verification_file(version, sha256)

        # Write to disk
        verification_file = tmp_path / "VERIFICATION.txt"
        verification_file.write_text(verification, encoding="utf-8")

        # Verify file exists and has content
        assert verification_file.exists()
        assert verification_file.stat().st_size > 0

        # Verify content
        content = verification_file.read_text(encoding="utf-8")
        assert "VERIFICATION" in content
        assert version in content
        assert sha256 in content
        assert "GitHub" in content

    @pytest.mark.integration
    def test_complete_package_with_verification(self, tmp_path: Path) -> None:
        """
        Generate complete package including VERIFICATION.txt.
        """
        version = "0.0.1"
        sha256 = "a" * 64

        # Generate package structure
        structure = generate_chocolatey_package_structure(version, sha256)

        # Generate verification file
        verification = generate_verification_file(version, sha256)

        # Write all files
        package_dir = tmp_path / "kekkai"
        package_dir.mkdir()

        for file_path, content in structure.items():
            full_path = package_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")

        # Add VERIFICATION.txt
        (package_dir / "VERIFICATION.txt").write_text(verification, encoding="utf-8")

        # Verify complete package structure
        assert (package_dir / "kekkai.nuspec").exists()
        assert (package_dir / "tools" / "chocolateyinstall.ps1").exists()
        assert (package_dir / "tools" / "chocolateyuninstall.ps1").exists()
        assert (package_dir / "VERIFICATION.txt").exists()

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
    @pytest.mark.integration
    def test_choco_pack_command(self, tmp_path: Path) -> None:
        """
        Test that package structure is compatible with 'choco pack'.

        NOTE: Requires Chocolatey installed on Windows.
        """
        pytest.skip("Requires Chocolatey installed - manual testing only")

        # Steps for manual testing:
        # 1. Generate package structure in directory
        # 2. cd to directory
        # 3. Run: choco pack
        # 4. Verify: kekkai.{version}.nupkg created


class TestChocolateyModeration:
    """Test package requirements for Chocolatey moderation."""

    @pytest.mark.integration
    def test_package_has_all_required_metadata(self, tmp_path: Path) -> None:
        """
        Verify package has all metadata required by Chocolatey moderators.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec = structure["kekkai.nuspec"]

        # Required metadata fields
        required_fields = [
            "<id>kekkai</id>",
            "<version>0.0.1</version>",
            "<authors>",
            "<description>",
            "<licenseUrl>",
            "<projectUrl>",
        ]

        for field in required_fields:
            assert field in nuspec, f"Missing required field: {field}"

    @pytest.mark.integration
    def test_package_scripts_are_documented(self, tmp_path: Path) -> None:
        """
        Verify install/uninstall scripts have proper documentation.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]
        uninstall_script = structure["tools/chocolateyuninstall.ps1"]

        # Scripts should have headers/comments
        assert "#" in install_script
        assert "#" in uninstall_script

        # Should mention Kekkai
        assert "Kekkai" in install_script or "kekkai" in install_script.lower()
        assert "Kekkai" in uninstall_script or "kekkai" in uninstall_script.lower()

    @pytest.mark.integration
    def test_package_has_tags(self, tmp_path: Path) -> None:
        """
        Verify package has appropriate tags for discoverability.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec = structure["kekkai.nuspec"]

        # Should have tags
        assert "<tags>" in nuspec

        # Should have relevant tags
        tags_section = nuspec[nuspec.find("<tags>") : nuspec.find("</tags>")].lower()
        assert "security" in tags_section or "appsec" in tags_section

    @pytest.mark.integration
    def test_package_dependencies_declared(self, tmp_path: Path) -> None:
        """
        Verify package declares Python dependency.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec = structure["kekkai.nuspec"]

        # Should have dependencies section
        assert "<dependencies>" in nuspec

        # Should depend on Python
        assert 'id="python"' in nuspec


class TestChocolateyAutomation:
    """Test CI/CD automation aspects."""

    @pytest.mark.integration
    def test_version_parameterization(self, tmp_path: Path) -> None:
        """
        Verify package generation works with different versions.
        """
        versions = ["0.0.1", "1.0.0", "2.5.3-rc1", "3.0.0-beta.1"]

        for version in versions:
            structure = generate_chocolatey_package_structure(
                version=version,
                sha256="a" * 64,
            )

            nuspec = structure["kekkai.nuspec"]
            assert f"<version>{version}</version>" in nuspec

            install_script = structure["tools/chocolateyinstall.ps1"]
            assert version in install_script

    @pytest.mark.integration
    def test_sha256_parameterization(self, tmp_path: Path) -> None:
        """
        Verify SHA256 can be parameterized for different releases.
        """
        checksums = [
            "a" * 64,
            "abc123def456" * 5 + "abcd",
            "0123456789abcdef" * 4,
        ]

        for checksum in checksums:
            structure = generate_chocolatey_package_structure(
                version="0.0.1",
                sha256=checksum,
            )

            install_script = structure["tools/chocolateyinstall.ps1"]
            assert checksum in install_script

    @pytest.mark.integration
    def test_python_version_parameterization(self, tmp_path: Path) -> None:
        """
        Verify Python version requirement can be configured.
        """
        python_versions = ["3.12", "3.13"]

        for py_version in python_versions:
            structure = generate_chocolatey_package_structure(
                version="0.0.1",
                sha256="a" * 64,
                python_version=py_version,
            )

            install_script = structure["tools/chocolateyinstall.ps1"]
            assert py_version in install_script

            nuspec = structure["kekkai.nuspec"]
            assert py_version in nuspec


class TestChocolateyErrorScenarios:
    """Test error handling in package scripts."""

    @pytest.mark.integration
    def test_install_script_handles_python_not_found(self, tmp_path: Path) -> None:
        """
        Verify install script handles missing Python gracefully.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should check for Python existence
        assert "Get-Command python" in install_script

        # Should handle error
        assert "throw" in install_script or "exit 1" in install_script

    @pytest.mark.integration
    def test_install_script_handles_checksum_mismatch(self, tmp_path: Path) -> None:
        """
        Verify install script handles checksum mismatch.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should verify checksum
        assert "Get-FileHash" in install_script

        # Should handle mismatch
        assert "mismatch" in install_script.lower() or "throw" in install_script

    @pytest.mark.integration
    def test_install_script_handles_download_failure(self, tmp_path: Path) -> None:
        """
        Verify install script handles download failures.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should download file
        assert "Invoke-WebRequest" in install_script

        # Should have error handling
        assert "try {" in install_script or "$ErrorActionPreference = 'Stop'" in install_script
