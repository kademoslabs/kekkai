"""Unit tests for Chocolatey NuGet package specification generation."""

import xml.etree.ElementTree as ET

import pytest

from kekkai_core.windows.chocolatey import (
    format_nuspec_xml,
    generate_chocolatey_package_structure,
    generate_nuspec,
    generate_verification_file,
    validate_nuspec,
)


class TestChocolateyNuspec:
    """Test Chocolatey nuspec generation."""

    def test_nuspec_xml_is_valid(self) -> None:
        """Verify generated nuspec is valid XML."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Should be parseable XML
        root = ET.fromstring(xml_str)
        assert root.tag.endswith("package")

        # Should have metadata element
        metadata = root.find(
            ".//{http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd}metadata"
        )
        assert metadata is not None

    def test_nuspec_has_required_fields(self) -> None:
        """Check id, version, authors, description, license fields present."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="b" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "id" in nuspec
        assert "version" in nuspec
        assert "authors" in nuspec
        assert "description" in nuspec
        assert "licenseUrl" in nuspec
        assert "projectUrl" in nuspec

        assert nuspec["id"] == "kekkai"
        assert nuspec["version"] == "0.0.1"
        assert nuspec["authors"] == "Kademos Labs"

    def test_nuspec_dependencies_include_python(self) -> None:
        """Verify Python 3.12+ listed as dependency."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="c" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            python_version="3.12",
        )

        assert "dependencies" in nuspec
        assert isinstance(nuspec["dependencies"], list)
        assert len(nuspec["dependencies"]) > 0

        python_dep = next((d for d in nuspec["dependencies"] if d["id"] == "python"), None)
        assert python_dep is not None
        assert "version" in python_dep
        assert "3.12" in python_dep["version"]

    def test_nuspec_version_matches_release(self) -> None:
        """Verify version in nuspec matches provided version."""
        version = "1.2.3"
        nuspec = generate_nuspec(
            version=version,
            sha256="d" * 64,
            whl_url=f"https://github.com/test/test/releases/download/v{version}/test.whl",
        )

        assert nuspec["version"] == version

    def test_nuspec_tags_are_appropriate(self) -> None:
        """Verify tags include security, appsec, cli."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="e" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "tags" in nuspec
        tags = nuspec["tags"].lower()
        assert "security" in tags
        assert "appsec" in tags
        assert "cli" in tags

    def test_nuspec_rejects_http_urls(self) -> None:
        """Verify only HTTPS URLs are allowed."""
        with pytest.raises(ValueError, match="must use HTTPS"):
            generate_nuspec(
                version="0.0.1",
                sha256="f" * 64,
                whl_url="http://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

    def test_nuspec_validates_sha256(self) -> None:
        """Verify SHA256 must be 64 hex characters."""
        # Valid SHA256
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )
        assert nuspec["_sha256"] == "a" * 64

        # Invalid SHA256 - too short
        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            generate_nuspec(
                version="0.0.1",
                sha256="abc123",
                whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

        # Invalid SHA256 - non-hex characters
        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            generate_nuspec(
                version="0.0.1",
                sha256="g" * 64,
                whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
            )

    def test_nuspec_invalid_version_rejected(self) -> None:
        """Verify invalid version formats are rejected."""
        # Valid versions should work
        for valid_version in ["0.0.1", "1.2.3", "2.0.0-rc1", "3.1.4-beta.2"]:
            nuspec = generate_nuspec(
                version=valid_version,
                sha256="a" * 64,
                whl_url=f"https://github.com/test/test/releases/download/v{valid_version}/test.whl",
            )
            assert nuspec["version"] == valid_version

        # Invalid versions should raise
        for invalid_version in ["1.2", "v1.2.3", "1.2.3.4", "invalid"]:
            with pytest.raises(ValueError, match="Invalid version format"):
                generate_nuspec(
                    version=invalid_version,
                    sha256="a" * 64,
                    whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
                )


class TestNuspecValidation:
    """Test nuspec validation logic."""

    def test_validate_valid_nuspec(self) -> None:
        """Verify valid nuspec passes validation."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert validate_nuspec(nuspec) is True

    def test_validate_missing_required_field(self) -> None:
        """Verify validation fails if required field is missing."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Remove required field
        del nuspec["id"]

        with pytest.raises(ValueError, match="Missing required field: id"):
            validate_nuspec(nuspec)

    def test_validate_invalid_version(self) -> None:
        """Verify validation fails for invalid version format."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Corrupt version
        nuspec["version"] = "invalid"

        with pytest.raises(ValueError, match="Invalid version format"):
            validate_nuspec(nuspec)

    def test_validate_invalid_sha256(self) -> None:
        """Verify validation fails for invalid SHA256."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        # Corrupt SHA256
        nuspec["_sha256"] = "invalid"

        with pytest.raises(ValueError, match="Invalid SHA256 format"):
            validate_nuspec(nuspec)


class TestNuspecXMLFormatting:
    """Test XML formatting of nuspec."""

    def test_xml_has_proper_namespace(self) -> None:
        """Verify XML uses correct Chocolatey namespace."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        assert "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd" in xml_str
        assert '<?xml version="1.0" encoding="utf-8"?>' in xml_str

    def test_xml_has_metadata_element(self) -> None:
        """Verify XML contains metadata element."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        assert "<metadata>" in xml_str
        assert "</metadata>" in xml_str

    def test_xml_includes_dependencies(self) -> None:
        """Verify XML includes dependencies section."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        assert "<dependencies>" in xml_str
        assert 'id="python"' in xml_str

    def test_xml_includes_files_section(self) -> None:
        """Verify XML includes files section."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        assert "<files>" in xml_str
        assert "tools" in xml_str


class TestPackageStructure:
    """Test complete package structure generation."""

    def test_package_structure_has_all_files(self) -> None:
        """Verify package structure includes nuspec and scripts."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "kekkai.nuspec" in structure
        assert "tools/chocolateyinstall.ps1" in structure
        assert "tools/chocolateyuninstall.ps1" in structure

    def test_package_nuspec_is_xml(self) -> None:
        """Verify nuspec file is valid XML."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec_xml = structure["kekkai.nuspec"]
        root = ET.fromstring(nuspec_xml)
        assert root.tag.endswith("package")

    def test_package_install_script_is_powershell(self) -> None:
        """Verify install script is PowerShell."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        install_script = structure["tools/chocolateyinstall.ps1"]
        assert "# Kekkai Chocolatey Installation Script" in install_script
        assert "$ErrorActionPreference = 'Stop'" in install_script
        assert "python -m pip install" in install_script

    def test_package_uninstall_script_is_powershell(self) -> None:
        """Verify uninstall script is PowerShell."""
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        uninstall_script = structure["tools/chocolateyuninstall.ps1"]
        assert "# Kekkai Chocolatey Uninstallation Script" in uninstall_script
        assert "pip uninstall -y kekkai" in uninstall_script


class TestVerificationFile:
    """Test VERIFICATION.txt generation for Chocolatey moderation."""

    def test_verification_file_has_url(self) -> None:
        """Verify verification file contains download URL."""
        verification = generate_verification_file(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "https://github.com/kademoslabs/kekkai/releases/download/v0.0.1" in verification
        assert "kekkai-0.0.1-py3-none-any.whl" in verification

    def test_verification_file_has_sha256(self) -> None:
        """Verify verification file contains SHA256 checksum."""
        sha256 = "abc123" * 10 + "abcd"  # 64 chars
        verification = generate_verification_file(
            version="0.0.1",
            sha256=sha256,
        )

        assert sha256 in verification
        assert "SHA256" in verification

    def test_verification_file_has_instructions(self) -> None:
        """Verify verification file contains verification instructions."""
        verification = generate_verification_file(
            version="0.0.1",
            sha256="a" * 64,
        )

        assert "VERIFICATION" in verification
        assert "Get-FileHash" in verification
        assert "PowerShell command:" in verification
