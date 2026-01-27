"""Regression tests for Chocolatey package backwards compatibility."""

import pytest

from kekkai_core.windows.chocolatey import generate_chocolatey_package_structure


class TestChocolateyBackwardsCompatibility:
    """Test backwards compatibility of Chocolatey packages."""

    @pytest.mark.regression
    def test_upgrade_from_old_version(self) -> None:
        """
        Verify upgrade path from previous Chocolatey versions.

        This test validates that the package structure remains compatible
        with previous versions, allowing smooth upgrades.
        """
        # Generate old-style package
        old_version = "0.0.1"
        old_structure = generate_chocolatey_package_structure(
            version=old_version,
            sha256="a" * 64,
        )

        # Generate new-style package
        new_version = "0.0.2"
        new_structure = generate_chocolatey_package_structure(
            version=new_version,
            sha256="b" * 64,
        )

        # Key structure should remain the same
        assert old_structure.keys() == new_structure.keys()

        # Both should have nuspec
        assert "kekkai.nuspec" in old_structure
        assert "kekkai.nuspec" in new_structure

        # Both should have tools scripts
        assert "tools/chocolateyinstall.ps1" in old_structure
        assert "tools/chocolateyinstall.ps1" in new_structure

    @pytest.mark.regression
    def test_coexist_with_pip_installation(self) -> None:
        """
        Verify Chocolatey package works alongside pip installation.

        This ensures users can have both installation methods available
        without conflicts.
        """
        # Generate Chocolatey package
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Chocolatey uses --force-reinstall, which should work even if
        # pip version is already installed
        assert "--force-reinstall" in install_script

        # Uninstall should only remove pip package, not interfere with
        # other installations
        uninstall_script = structure["tools/chocolateyuninstall.ps1"]
        assert "pip uninstall -y kekkai" in uninstall_script

    @pytest.mark.regression
    def test_python_version_matrix(self) -> None:
        """
        Test with different Python versions (3.12, 3.13).

        Verifies package works across supported Python versions.
        """
        python_versions = ["3.12", "3.13"]

        for py_version in python_versions:
            structure = generate_chocolatey_package_structure(
                version="0.0.1",
                sha256="a" * 64,
                python_version=py_version,
            )

            install_script = structure["tools/chocolateyinstall.ps1"]

            # Should check for the specified Python version
            assert py_version in install_script

            # Version check logic should be consistent
            assert (
                "pythonVersion = python --version" in install_script
                or "python --version" in install_script
            )


class TestChocolateyPackageStructureStability:
    """Test that package structure remains stable across versions."""

    @pytest.mark.regression
    def test_file_paths_unchanged(self) -> None:
        """
        Verify file paths in package structure haven't changed.

        This prevents breaking changes in package layout.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        expected_files = {
            "kekkai.nuspec",
            "tools/chocolateyinstall.ps1",
            "tools/chocolateyuninstall.ps1",
        }

        assert set(structure.keys()) == expected_files

    @pytest.mark.regression
    def test_nuspec_structure_stable(self) -> None:
        """
        Verify nuspec XML structure remains stable.

        This ensures existing automation doesn't break.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec = structure["kekkai.nuspec"]

        # Required elements should always be present
        required_elements = [
            "<package",
            "<metadata>",
            "<id>kekkai</id>",
            "<version>",
            "<authors>",
            "<description>",
            "<dependencies>",
            "<files>",
        ]

        for element in required_elements:
            assert element in nuspec, f"Missing element: {element}"

    @pytest.mark.regression
    def test_install_script_api_stable(self) -> None:
        """
        Verify install script uses stable PowerShell APIs.

        This prevents breaking changes in script behavior.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should use standard cmdlets that are stable
        stable_cmdlets = [
            "Get-Command",
            "Invoke-WebRequest",
            "Get-FileHash",
        ]

        for cmdlet in stable_cmdlets:
            assert cmdlet in install_script, f"Missing cmdlet: {cmdlet}"

    @pytest.mark.regression
    def test_error_handling_consistent(self) -> None:
        """
        Verify error handling approach is consistent.

        This ensures predictable failure modes.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should have consistent error handling
        assert "$ErrorActionPreference = 'Stop'" in install_script
        assert "throw" in install_script

        uninstall_script = structure["tools/chocolateyuninstall.ps1"]

        # Uninstall should be more lenient
        assert "$ErrorActionPreference = 'Continue'" in uninstall_script


class TestChocolateyDependencyCompatibility:
    """Test dependency declarations remain compatible."""

    @pytest.mark.regression
    def test_python_dependency_format_stable(self) -> None:
        """
        Verify Python dependency declaration format is stable.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
            python_version="3.12",
        )

        nuspec = structure["kekkai.nuspec"]

        # Python dependency should use range notation
        assert 'id="python"' in nuspec
        assert 'version="[3.12,)"' in nuspec or "3.12" in nuspec

    @pytest.mark.regression
    def test_no_breaking_dependency_changes(self) -> None:
        """
        Verify no unexpected dependencies have been added.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec = structure["kekkai.nuspec"]

        # Should only depend on Python (not Docker, etc.)
        assert 'id="python"' in nuspec

        # Should not have excessive dependencies
        dependency_count = nuspec.count("<dependency")
        assert dependency_count == 1, "Unexpected number of dependencies"


class TestChocolateyURLStability:
    """Test URL patterns remain stable."""

    @pytest.mark.regression
    def test_github_release_url_pattern(self) -> None:
        """
        Verify GitHub release URL pattern is consistent.
        """
        version = "1.2.3"
        structure = generate_chocolatey_package_structure(
            version=version,
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # URL should follow expected pattern
        expected_url_fragment = (
            f"https://github.com/kademoslabs/kekkai/releases/download/v{version}"
        )
        assert expected_url_fragment in install_script

        # Should use wheel format
        assert f"kekkai-{version}-py3-none-any.whl" in install_script

    @pytest.mark.regression
    def test_all_urls_use_https(self) -> None:
        """
        Verify all URLs consistently use HTTPS.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        for file_content in structure.values():
            # Should have https://
            if "http" in file_content.lower():
                assert "https://" in file_content, "Found non-HTTPS URL"


class TestChocolateyInstallationBehavior:
    """Test installation behavior remains consistent."""

    @pytest.mark.regression
    def test_pip_install_flags_stable(self) -> None:
        """
        Verify pip install flags haven't changed.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should use these specific flags
        assert "--force-reinstall" in install_script
        assert "--no-deps" in install_script

    @pytest.mark.regression
    def test_uninstall_behavior_stable(self) -> None:
        """
        Verify uninstall behavior hasn't changed.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        uninstall_script = structure["tools/chocolateyuninstall.ps1"]

        # Should use pip uninstall with -y flag
        assert "pip uninstall -y kekkai" in uninstall_script

        # Should not fail on errors (graceful uninstall)
        assert "Continue" in uninstall_script or "exit 0" in uninstall_script


class TestChocolateySecurityPractices:
    """Test security practices remain consistent."""

    @pytest.mark.regression
    def test_no_invoke_expression_introduced(self) -> None:
        """
        Verify Invoke-Expression hasn't been introduced (security risk).
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        for file_content in structure.values():
            assert "Invoke-Expression" not in file_content
            assert " iex " not in file_content.lower()

    @pytest.mark.regression
    def test_checksum_verification_still_present(self) -> None:
        """
        Verify checksum verification hasn't been removed.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should still verify checksums
        assert "Get-FileHash" in install_script
        assert "SHA256" in install_script

    @pytest.mark.regression
    def test_input_validation_preserved(self) -> None:
        """
        Verify input validation logic is still present.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]

        # Should validate Python version
        assert "python --version" in install_script

        # Should validate checksum match
        assert "checksum" in install_script.lower()
