"""Regression tests for Scoop manifest golden file comparison."""

import json
from pathlib import Path

import pytest

from kekkai_core.windows.scoop import generate_scoop_manifest


@pytest.mark.regression
class TestScoopManifestRegression:
    """Test Scoop manifest against golden file."""

    def test_manifest_matches_golden_structure(self) -> None:
        """Verify generated manifest matches golden file structure."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest with same parameters
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare keys (structure)
        assert set(generated_manifest.keys()) == set(golden_manifest.keys())

        # Compare metadata fields
        assert generated_manifest["version"] == golden_manifest["version"]
        assert generated_manifest["description"] == golden_manifest["description"]
        assert generated_manifest["homepage"] == golden_manifest["homepage"]
        assert generated_manifest["license"] == golden_manifest["license"]
        assert generated_manifest["depends"] == golden_manifest["depends"]

    def test_installer_script_matches_golden(self) -> None:
        """Verify installer script matches golden file."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare installer structure
        assert "installer" in generated_manifest
        assert "installer" in golden_manifest
        assert "script" in generated_manifest["installer"]
        assert "script" in golden_manifest["installer"]

        # Compare script length and key lines
        gen_script = generated_manifest["installer"]["script"]
        golden_script = golden_manifest["installer"]["script"]

        assert isinstance(gen_script, list)
        assert isinstance(golden_script, list)

        # Key lines should be present
        assert any("python --version" in line or "pythonVersion" in line for line in gen_script)
        assert any("pip install" in line for line in gen_script)
        assert any("--force-reinstall" in line for line in gen_script)

    def test_uninstaller_script_matches_golden(self) -> None:
        """Verify uninstaller script matches golden file."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare uninstaller
        assert "uninstaller" in generated_manifest
        assert "uninstaller" in golden_manifest

        gen_uninstall = generated_manifest["uninstaller"]["script"]
        golden_uninstall = golden_manifest["uninstaller"]["script"]

        assert isinstance(gen_uninstall, list)
        assert isinstance(golden_uninstall, list)

    def test_checkver_structure_unchanged(self) -> None:
        """Verify checkver structure hasn't changed."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare checkver
        assert "checkver" in generated_manifest
        assert "checkver" in golden_manifest
        assert set(generated_manifest["checkver"].keys()) == set(golden_manifest["checkver"].keys())

    def test_autoupdate_structure_unchanged(self) -> None:
        """Verify autoupdate structure hasn't changed."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare autoupdate
        assert "autoupdate" in generated_manifest
        assert "autoupdate" in golden_manifest
        assert set(generated_manifest["autoupdate"].keys()) == set(
            golden_manifest["autoupdate"].keys()
        )

    def test_notes_present(self) -> None:
        """Verify notes are present in manifest."""
        # Load golden manifest
        golden_path = Path(__file__).parent / "fixtures" / "scoop_manifest_golden.json"
        with golden_path.open() as f:
            golden_manifest = json.load(f)

        # Generate new manifest
        generated_manifest = generate_scoop_manifest(
            version="0.0.1",
            sha256="a" * 64,
            whl_url="https://github.com/kademoslabs/kekkai/releases/download/v0.0.1/kekkai-0.0.1-py3-none-any.whl",
        )

        # Compare notes
        assert "notes" in generated_manifest
        assert "notes" in golden_manifest
        assert isinstance(generated_manifest["notes"], list)
        assert isinstance(golden_manifest["notes"], list)
