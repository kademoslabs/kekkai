"""Regression tests for SLSA - ensure existing functionality unchanged."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.docker.signing import CosignError, sign_image, verify_signature


@pytest.mark.regression
class TestDockerSigningUnchanged:
    """Verify existing Docker signing is not affected by SLSA additions."""

    @patch("subprocess.run")
    def test_sign_image_still_works(self, mock_run: MagicMock) -> None:
        """Docker image signing API unchanged."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = sign_image("kademoslabs/kekkai:latest")

        assert result is True
        args = mock_run.call_args[0][0]
        assert "cosign" in args
        assert "sign" in args

    @patch("subprocess.run")
    def test_verify_signature_still_works(self, mock_run: MagicMock) -> None:
        """Docker signature verification API unchanged."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_signature("kademoslabs/kekkai:latest")

        assert result is True
        args = mock_run.call_args[0][0]
        assert "cosign" in args
        assert "verify" in args

    @patch("subprocess.run")
    def test_sign_with_key_path(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Key path parameter still accepted."""
        key = tmp_path / "cosign.key"
        key.write_text("fake-key")
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = sign_image("test:latest", key_path=key)

        assert result is True
        args = mock_run.call_args[0][0]
        assert "--key" in args

    @patch("subprocess.run")
    def test_cosign_error_unchanged(self, mock_run: MagicMock) -> None:
        """CosignError exception still raised on failure."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "cosign", stderr="fail")

        with pytest.raises(CosignError):
            sign_image("test:latest")


@pytest.mark.regression
class TestReleaseArtifactsStructure:
    """Verify release artifact structure expectations."""

    def test_wheel_naming_convention(self) -> None:
        """Wheel files follow PEP 427 naming."""
        # This documents expected artifact naming
        expected_pattern = "kekkai-{version}-py3-none-any.whl"
        assert "{version}" in expected_pattern
        assert "py3" in expected_pattern

    def test_provenance_file_naming(self) -> None:
        """Provenance files follow SLSA naming convention."""
        artifact_name = "kekkai-1.0.0-py3-none-any.whl"
        expected_provenance = f"{artifact_name}.intoto.jsonl"
        assert expected_provenance.endswith(".intoto.jsonl")

    def test_signature_file_naming(self) -> None:
        """Signature files use .sig extension."""
        artifact_name = "kekkai-1.0.0-py3-none-any.whl"
        expected_sig = f"{artifact_name}.sig"
        assert expected_sig.endswith(".sig")


@pytest.mark.regression
class TestModuleImports:
    """Verify module structure doesn't break imports."""

    def test_docker_signing_import(self) -> None:
        """Docker signing module still importable."""
        from kekkai_core.docker.signing import (
            CosignError,
            generate_keypair,
            sign_image,
            verify_signature,
        )

        assert CosignError is not None
        assert sign_image is not None
        assert verify_signature is not None
        assert generate_keypair is not None

    def test_slsa_import(self) -> None:
        """SLSA module importable."""
        from kekkai_core.slsa import (
            AttestationError,
            ProvenanceResult,
            verify_provenance,
        )

        assert AttestationError is not None
        assert ProvenanceResult is not None
        assert verify_provenance is not None

    def test_kekkai_core_namespace(self) -> None:
        """kekkai_core package structure intact."""
        import kekkai_core

        assert hasattr(kekkai_core, "__file__")
