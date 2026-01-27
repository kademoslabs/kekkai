"""Unit tests for Cosign image signing and verification."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.docker.signing import (
    CosignError,
    generate_keypair,
    sign_image,
    verify_signature,
)


class TestImageSigning:
    """Test Docker image signing with Cosign."""

    @patch("subprocess.run")
    def test_sign_image_success(self, mock_run: MagicMock) -> None:
        """Verify image signing succeeds."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = sign_image("test-image:latest")

        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "cosign" in args
        assert "sign" in args
        assert "--yes" in args
        assert "test-image:latest" in args

    @patch("subprocess.run")
    def test_sign_image_with_key(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify signing with private key."""
        key_path = tmp_path / "cosign.key"
        key_path.write_text("fake-private-key")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = sign_image("test-image:latest", key_path=key_path)

        assert result is True
        args = mock_run.call_args[0][0]
        assert "--key" in args
        key_index = args.index("--key")
        assert args[key_index + 1] == str(key_path)

    @patch("subprocess.run")
    def test_sign_image_with_password(self, mock_run: MagicMock) -> None:
        """Verify signing with password-protected key."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        sign_image("test-image:latest", password="test-password")

        # Verify COSIGN_PASSWORD env var passed
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["env"] is not None

    @patch("subprocess.run")
    def test_sign_image_failure_raises_error(self, mock_run: MagicMock) -> None:
        """Verify signing failures raise CosignError."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "cosign", stderr="signing failed")

        with pytest.raises(CosignError, match="Image signing failed"):
            sign_image("test-image:latest")

    @patch("subprocess.run")
    def test_sign_image_timeout_handled(self, mock_run: MagicMock) -> None:
        """Verify timeout errors are handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("cosign", 120)

        with pytest.raises(CosignError, match="timed out"):
            sign_image("test-image:latest")


class TestSignatureVerification:
    """Test Docker image signature verification."""

    @patch("subprocess.run")
    def test_verify_signature_valid(self, mock_run: MagicMock) -> None:
        """Verify signature verification succeeds for valid signature."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_signature("test-image:latest")

        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "cosign" in args
        assert "verify" in args
        assert "test-image:latest" in args

    @patch("subprocess.run")
    def test_verify_signature_with_key(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify signature verification with public key."""
        pub_key = tmp_path / "cosign.pub"
        pub_key.write_text("fake-public-key")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_signature("test-image:latest", key_path=pub_key)

        assert result is True
        args = mock_run.call_args[0][0]
        assert "--key" in args
        key_index = args.index("--key")
        assert args[key_index + 1] == str(pub_key)

    @patch("subprocess.run")
    def test_verify_signature_invalid(self, mock_run: MagicMock) -> None:
        """Verify signature verification fails for invalid signature."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="verification failed")

        result = verify_signature("test-image:latest")

        assert result is False

    @patch("subprocess.run")
    def test_verify_signature_timeout_raises_error(self, mock_run: MagicMock) -> None:
        """Verify timeout during verification raises error."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("cosign", 120)

        with pytest.raises(CosignError, match="timed out"):
            verify_signature("test-image:latest")


class TestKeyGeneration:
    """Test Cosign keypair generation."""

    @patch("subprocess.run")
    def test_generate_keypair_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify keypair generation succeeds."""
        output_dir = tmp_path / "keys"

        # Mock key file creation
        def create_keys(*args: object, **kwargs: object) -> MagicMock:
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text("private-key")
            (output_dir / "cosign.pub").write_text("public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        private_key, public_key = generate_keypair(output_dir)

        assert private_key.exists()
        assert public_key.exists()
        assert private_key.name == "cosign.key"
        assert public_key.name == "cosign.pub"

    @patch("subprocess.run")
    def test_generate_keypair_creates_directory(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify keypair generation creates output directory."""
        output_dir = tmp_path / "nonexistent" / "keys"

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd")
            if cwd:
                cwd_path = Path(str(cwd))
                cwd_path.mkdir(parents=True, exist_ok=True)
                (cwd_path / "cosign.key").write_text("private")
                (cwd_path / "cosign.pub").write_text("public")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        private_key, public_key = generate_keypair(output_dir)

        assert output_dir.exists()
        assert private_key.exists()
        assert public_key.exists()

    @patch("subprocess.run")
    def test_generate_keypair_failure_raises_error(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Verify keypair generation failures raise error."""
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "cosign", stderr="key generation failed"
        )

        with pytest.raises(CosignError, match="Key generation failed"):
            generate_keypair(tmp_path)

    @patch("subprocess.run")
    def test_generate_keypair_missing_keys_raises_error(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Verify error if keys not created after generation."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Keys not created, should raise error
        with pytest.raises(CosignError, match="keys not found"):
            generate_keypair(tmp_path)

    @patch("subprocess.run")
    def test_generate_keypair_timeout_handled(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify timeout during key generation is handled."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("cosign", 60)

        with pytest.raises(CosignError, match="timed out"):
            generate_keypair(tmp_path)


class TestKeyRotation:
    """Test key rotation scenarios."""

    @patch("subprocess.run")
    def test_sign_with_new_key_after_rotation(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify signing works with newly rotated key."""
        new_key = tmp_path / "cosign-new.key"
        new_key.write_text("new-private-key")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = sign_image("test-image:latest", key_path=new_key)

        assert result is True
        args = mock_run.call_args[0][0]
        assert str(new_key) in args

    @patch("subprocess.run")
    def test_verify_with_old_key_fails_after_rotation(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Verify old key fails verification after rotation."""
        old_pub_key = tmp_path / "cosign-old.pub"
        old_pub_key.write_text("old-public-key")

        # Simulate verification failure with old key
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="verification failed")

        result = verify_signature("test-image:latest", key_path=old_pub_key)

        assert result is False
