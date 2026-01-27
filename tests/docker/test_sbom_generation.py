"""Unit tests for SBOM generation."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.docker.sbom import (
    SBOMError,
    attach_sbom_to_image,
    extract_dependencies,
    generate_sbom,
    validate_sbom_format,
)


class TestSBOMGeneration:
    """Test SBOM generation with Trivy."""

    @patch("subprocess.run")
    def test_generate_sbom_spdx_json(self, mock_run: MagicMock) -> None:
        """Verify SBOM generation in SPDX JSON format."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": "kekkai",
            "documentNamespace": "https://example.com",
            "packages": [],
        }

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(sbom_data), stderr="")

        result = generate_sbom("test-image:latest", output_format="spdx-json")

        assert result == sbom_data
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "trivy" in args
        assert "image" in args
        assert "--format" in args
        assert "spdx-json" in args

    @patch("subprocess.run")
    def test_generate_sbom_cyclonedx_json(self, mock_run: MagicMock) -> None:
        """Verify SBOM generation in CycloneDX JSON format."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [],
        }

        mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(sbom_data), stderr="")

        result = generate_sbom("test-image:latest", output_format="cyclonedx-json")

        assert result == sbom_data
        args = mock_run.call_args[0][0]
        assert "cyclonedx-json" in args

    @patch("subprocess.run")
    def test_generate_sbom_with_output_file(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify SBOM can be written to file."""
        output_file = tmp_path / "sbom.spdx.json"
        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")

        generate_sbom("test-image:latest", output_file=output_file)

        args = mock_run.call_args[0][0]
        assert "--output" in args
        output_index = args.index("--output")
        assert args[output_index + 1] == str(output_file)

    @patch("subprocess.run")
    def test_generate_sbom_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Verify SBOM generation failures raise error."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "trivy", stderr="generation failed")

        with pytest.raises(SBOMError, match="SBOM generation failed"):
            generate_sbom("test-image:latest")

    @patch("subprocess.run")
    def test_generate_sbom_timeout_handled(self, mock_run: MagicMock) -> None:
        """Verify timeout errors are handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 300)

        with pytest.raises(SBOMError, match="timed out"):
            generate_sbom("test-image:latest")

    @patch("subprocess.run")
    def test_generate_sbom_invalid_json_raises_error(self, mock_run: MagicMock) -> None:
        """Verify invalid JSON output raises error."""
        mock_run.return_value = MagicMock(returncode=0, stdout="invalid json", stderr="")

        with pytest.raises(SBOMError, match="Failed to parse"):
            generate_sbom("test-image:latest", output_format="spdx-json")


class TestSBOMValidation:
    """Test SBOM format validation."""

    def test_validate_spdx_format_valid(self) -> None:
        """Verify valid SPDX SBOM passes validation."""
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": "kekkai",
            "documentNamespace": "https://example.com",
        }

        assert validate_sbom_format(sbom_data, "spdx-json") is True

    def test_validate_spdx_format_missing_fields(self) -> None:
        """Verify SPDX validation fails with missing fields."""
        sbom_data = {"spdxVersion": "SPDX-2.3", "name": "kekkai"}

        assert validate_sbom_format(sbom_data, "spdx-json") is False

    def test_validate_cyclonedx_format_valid(self) -> None:
        """Verify valid CycloneDX SBOM passes validation."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
        }

        assert validate_sbom_format(sbom_data, "cyclonedx-json") is True

    def test_validate_cyclonedx_format_missing_fields(self) -> None:
        """Verify CycloneDX validation fails with missing fields."""
        sbom_data = {"bomFormat": "CycloneDX"}

        assert validate_sbom_format(sbom_data, "cyclonedx-json") is False

    def test_validate_empty_sbom(self) -> None:
        """Verify empty SBOM fails validation."""
        assert validate_sbom_format({}, "spdx-json") is False


class TestDependencyExtraction:
    """Test dependency extraction from SBOM."""

    def test_extract_dependencies_spdx(self) -> None:
        """Verify dependency extraction from SPDX SBOM."""
        sbom_data: dict[str, Any] = {
            "packages": [
                {"name": "python", "version": "3.12"},
                {"name": "pytest", "version": "7.4.0"},
                {"name": "mypy", "version": "1.5.0"},
            ]
        }

        deps = extract_dependencies(sbom_data, "spdx-json")

        assert len(deps) == 3
        assert "python" in deps
        assert "pytest" in deps
        assert "mypy" in deps

    def test_extract_dependencies_cyclonedx(self) -> None:
        """Verify dependency extraction from CycloneDX SBOM."""
        sbom_data: dict[str, Any] = {
            "components": [
                {"name": "python", "version": "3.12"},
                {"name": "requests", "version": "2.31.0"},
            ]
        }

        deps = extract_dependencies(sbom_data, "cyclonedx-json")

        assert len(deps) == 2
        assert "python" in deps
        assert "requests" in deps

    def test_extract_dependencies_empty_sbom(self) -> None:
        """Verify extraction handles empty SBOM."""
        sbom_data: dict[str, Any] = {"packages": []}

        deps = extract_dependencies(sbom_data, "spdx-json")

        assert len(deps) == 0

    def test_extract_dependencies_missing_name(self) -> None:
        """Verify extraction skips packages without name."""
        sbom_data = {"packages": [{"version": "1.0.0"}, {"name": "valid-package"}]}

        deps = extract_dependencies(sbom_data, "spdx-json")

        assert len(deps) == 1
        assert "valid-package" in deps


class TestSBOMAttachment:
    """Test SBOM attachment to Docker images."""

    @patch("subprocess.run")
    def test_attach_sbom_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify SBOM can be attached to image."""
        sbom_file = tmp_path / "sbom.spdx.json"
        sbom_file.write_text('{"spdxVersion": "SPDX-2.3"}')

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = attach_sbom_to_image("test-image:latest", sbom_file)

        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "cosign" in args
        assert "attach" in args
        assert "sbom" in args
        assert "--sbom" in args
        assert str(sbom_file) in args

    def test_attach_sbom_file_not_found(self, tmp_path: Path) -> None:
        """Verify error if SBOM file doesn't exist."""
        sbom_file = tmp_path / "nonexistent.json"

        with pytest.raises(SBOMError, match="SBOM file not found"):
            attach_sbom_to_image("test-image:latest", sbom_file)

    @patch("subprocess.run")
    def test_attach_sbom_failure_raises_error(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify attachment failures raise error."""
        import subprocess

        sbom_file = tmp_path / "sbom.spdx.json"
        sbom_file.write_text("{}")

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "cosign", stderr="attachment failed"
        )

        with pytest.raises(SBOMError, match="SBOM attachment failed"):
            attach_sbom_to_image("test-image:latest", sbom_file)

    @patch("subprocess.run")
    def test_attach_sbom_timeout_handled(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify timeout during attachment is handled."""
        import subprocess

        sbom_file = tmp_path / "sbom.spdx.json"
        sbom_file.write_text("{}")

        mock_run.side_effect = subprocess.TimeoutExpired("cosign", 120)

        with pytest.raises(SBOMError, match="timed out"):
            attach_sbom_to_image("test-image:latest", sbom_file)
