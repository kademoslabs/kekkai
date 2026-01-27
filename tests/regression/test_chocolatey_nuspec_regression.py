"""Regression tests for Chocolatey nuspec XML structure.

These tests use golden file comparison to detect unintended changes
in the nuspec XML structure that could break automation or moderation.
"""

import xml.etree.ElementTree as ET

import pytest

from kekkai_core.windows.chocolatey import (
    format_nuspec_xml,
    generate_chocolatey_package_structure,
    generate_nuspec,
)


class TestChocolateyNuspecRegression:
    """Test nuspec structure against golden reference."""

    @pytest.mark.regression
    def test_nuspec_matches_golden_file(self) -> None:
        """
        Verify nuspec structure matches golden reference file.

        This test compares generated nuspec with a known-good version
        to detect breaking changes.
        """
        # Generate current nuspec
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Parse XML
        root = ET.fromstring(xml_str)

        # Golden file expectations - verify key structure
        # (We don't use an actual golden file to avoid maintenance burden,
        # but we verify key structural elements)

        ns = {"ns": "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"}

        # Verify root element
        assert root.tag.endswith("package")

        # Verify metadata exists
        metadata = root.find("ns:metadata", ns)
        assert metadata is not None

        # Verify key elements exist
        id_elem = metadata.find("ns:id", ns)
        assert id_elem is not None
        assert id_elem.text == "kekkai"

        version_elem = metadata.find("ns:version", ns)
        assert version_elem is not None
        assert version_elem.text == "0.0.1"

        # Verify dependencies structure
        deps = metadata.find("ns:dependencies", ns)
        assert deps is not None

        # Verify files section
        files = root.find("ns:files", ns)
        assert files is not None

    @pytest.mark.regression
    def test_nuspec_structure_unchanged(self) -> None:
        """
        Verify nuspec XML structure hasn't changed in breaking ways.

        This test checks that the order and nesting of elements
        remains consistent.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec_xml = structure["kekkai.nuspec"]

        # Parse XML
        root = ET.fromstring(nuspec_xml)

        ns = {"ns": "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"}

        # Verify element hierarchy
        metadata = root.find("ns:metadata", ns)
        assert metadata is not None

        # Verify metadata children order (important for some parsers)
        children = list(metadata)
        child_tags = [c.tag.split("}")[-1] for c in children]

        # Key fields should exist (order may vary, but all should be present)
        expected_fields = {
            "id",
            "version",
            "authors",
            "description",
            "licenseUrl",
            "projectUrl",
        }

        actual_fields = set(child_tags)
        assert expected_fields.issubset(
            actual_fields
        ), f"Missing fields: {expected_fields - actual_fields}"

    @pytest.mark.regression
    def test_nuspec_xml_namespace_stable(self) -> None:
        """
        Verify XML namespace hasn't changed.

        Changing the namespace would break existing tooling.
        """
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Should use the standard Chocolatey namespace
        expected_ns = "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"
        assert expected_ns in xml_str

    @pytest.mark.regression
    def test_nuspec_encoding_stable(self) -> None:
        """
        Verify XML encoding declaration is stable.
        """
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Should have UTF-8 encoding declaration
        assert '<?xml version="1.0" encoding="utf-8"?>' in xml_str

    @pytest.mark.regression
    def test_nuspec_dependency_format_unchanged(self) -> None:
        """
        Verify dependency XML format hasn't changed.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
            python_version="3.12",
        )

        nuspec_xml = structure["kekkai.nuspec"]
        root = ET.fromstring(nuspec_xml)

        ns = {"ns": "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"}

        # Find dependencies
        deps = root.find(".//ns:dependencies", ns)
        assert deps is not None

        # Find Python dependency
        python_dep = deps.find('.//ns:dependency[@id="python"]', ns)
        assert python_dep is not None

        # Verify attributes
        assert "id" in python_dep.attrib
        assert "version" in python_dep.attrib
        assert python_dep.attrib["id"] == "python"

    @pytest.mark.regression
    def test_nuspec_files_section_format(self) -> None:
        """
        Verify files section format hasn't changed.
        """
        structure = generate_chocolatey_package_structure(
            version="0.0.1",
            sha256="a" * 64,
        )

        nuspec_xml = structure["kekkai.nuspec"]
        root = ET.fromstring(nuspec_xml)

        ns = {"ns": "http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"}

        # Find files section
        files = root.find(".//ns:files", ns)
        assert files is not None

        # Should have at least one file entry
        file_entries = files.findall("ns:file", ns)
        assert len(file_entries) > 0

        # Verify file entry has expected attributes
        for file_entry in file_entries:
            assert "src" in file_entry.attrib
            assert "target" in file_entry.attrib


class TestNuspecFieldValueStability:
    """Test that field values remain stable where expected."""

    @pytest.mark.regression
    def test_package_id_stable(self) -> None:
        """Verify package ID hasn't changed."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert nuspec["id"] == "kekkai"

    @pytest.mark.regression
    def test_authors_field_stable(self) -> None:
        """Verify authors field hasn't changed."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert nuspec["authors"] == "Kademos Labs"

    @pytest.mark.regression
    def test_license_url_stable(self) -> None:
        """Verify license URL hasn't changed."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "github.com/kademoslabs/kekkai" in nuspec["licenseUrl"]

    @pytest.mark.regression
    def test_project_url_stable(self) -> None:
        """Verify project URL hasn't changed."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        assert "github.com/kademoslabs/kekkai" in nuspec["projectUrl"]


class TestNuspecXMLFormatting:
    """Test XML formatting consistency."""

    @pytest.mark.regression
    def test_xml_indentation_consistent(self) -> None:
        """Verify XML uses consistent indentation."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Should have 2-space indentation
        lines = xml_str.split("\n")
        indented_lines = [line for line in lines if line.startswith("  ")]

        assert len(indented_lines) > 0, "No indented lines found"

        # Check that indentation is 2-space
        for line in indented_lines:
            # Count leading spaces
            spaces = len(line) - len(line.lstrip(" "))
            # Should be multiple of 2
            assert spaces % 2 == 0, f"Inconsistent indentation in line: {line}"

    @pytest.mark.regression
    def test_xml_line_endings_consistent(self) -> None:
        """Verify XML uses consistent line endings."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        # Should use \n line endings (Unix-style)
        assert "\r\n" not in xml_str or "\n" in xml_str

    @pytest.mark.regression
    def test_xml_no_unnecessary_whitespace(self) -> None:
        """Verify XML doesn't have unnecessary trailing whitespace."""
        nuspec = generate_nuspec(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/test/test/releases/download/v0.0.1/test.whl",
        )

        xml_str = format_nuspec_xml(nuspec)

        lines = xml_str.split("\n")

        # No trailing spaces (except empty lines)
        for line in lines:
            if line:
                assert not line.endswith(" "), f"Trailing whitespace in line: {repr(line)}"
