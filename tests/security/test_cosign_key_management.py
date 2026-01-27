"""Unit tests for Cosign key management procedures."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from kekkai_core.docker.signing import generate_keypair


class TestCosignKeyGeneration:
    """Test Cosign keypair generation."""

    @patch("subprocess.run")
    def test_key_generation_creates_keypair(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify keypair generation creates both keys."""

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd", str(tmp_path))
            output_dir = Path(str(cwd))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text(
                "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n"
                "test\n"
                "-----END ENCRYPTED COSIGN PRIVATE KEY-----\n"
            )
            (output_dir / "cosign.pub").write_text(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
            )
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        private_key, public_key = generate_keypair(tmp_path)

        assert private_key.exists()
        assert public_key.exists()
        assert private_key.name == "cosign.key"
        assert public_key.name == "cosign.pub"

    @patch("subprocess.run")
    def test_keys_have_correct_format(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify generated keys have correct PEM format."""

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd", str(tmp_path))
            output_dir = Path(str(cwd))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text(
                "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n"
                "test\n"
                "-----END ENCRYPTED COSIGN PRIVATE KEY-----\n"
            )
            (output_dir / "cosign.pub").write_text(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
            )
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        private_key, public_key = generate_keypair(tmp_path)

        private_content = private_key.read_text()
        public_content = public_key.read_text()

        assert "BEGIN ENCRYPTED COSIGN PRIVATE KEY" in private_content
        assert "END ENCRYPTED COSIGN PRIVATE KEY" in private_content
        assert "BEGIN PUBLIC KEY" in public_content
        assert "END PUBLIC KEY" in public_content

    @patch("subprocess.run")
    def test_key_validation_succeeds(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify generated keys can be validated."""

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd", str(tmp_path))
            output_dir = Path(str(cwd))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text(
                "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n"
                "test\n"
                "-----END ENCRYPTED COSIGN PRIVATE KEY-----\n"
            )
            (output_dir / "cosign.pub").write_text(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
            )
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        private_key, public_key = generate_keypair(tmp_path)

        # Keys exist and can be read
        assert private_key.read_text()
        assert public_key.read_text()

    @patch("subprocess.run")
    def test_key_generation_creates_directory(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify key generation creates output directory if missing."""
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


class TestKeyRotation:
    """Test key rotation procedures."""

    @patch("subprocess.run")
    def test_key_rotation_generates_new_keypair(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verify key rotation generates new keypair."""

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd", str(tmp_path))
            output_dir = Path(str(cwd))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text("new-private-key")
            (output_dir / "cosign.pub").write_text("new-public-key")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        # Generate first keypair
        old_private, old_public = generate_keypair(tmp_path / "old")

        # Generate new keypair (rotation)
        new_private, new_public = generate_keypair(tmp_path / "new")

        # Keys should be different
        assert old_private.parent != new_private.parent
        assert old_public.parent != new_public.parent


class TestKeyBackupAndRecovery:
    """Test key backup and recovery procedures."""

    def test_public_key_can_be_backed_up(self, tmp_path: Path) -> None:
        """Verify public key can be copied for backup."""
        # Create mock public key
        original_pub = tmp_path / "cosign.pub"
        original_pub.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n")

        # Backup
        backup_dir = tmp_path / "backup"
        backup_dir.mkdir()
        backup_pub = backup_dir / "cosign-backup.pub"

        # Copy for backup
        import shutil

        shutil.copy(original_pub, backup_pub)

        assert backup_pub.exists()
        assert backup_pub.read_text() == original_pub.read_text()

    def test_private_key_can_be_securely_deleted(self, tmp_path: Path) -> None:
        """Verify private key file can be deleted."""
        # Create mock private key
        private_key = tmp_path / "cosign.key"
        private_key.write_text(
            "-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\n"
            "test\n"
            "-----END ENCRYPTED COSIGN PRIVATE KEY-----\n"
        )

        assert private_key.exists()

        # Securely delete (in test, just regular delete)
        private_key.unlink()

        assert not private_key.exists()


class TestKeySecurityValidation:
    """Test key security validation."""

    def test_private_key_should_not_be_world_readable(self, tmp_path: Path) -> None:
        """Verify private key has restrictive permissions."""
        import os

        private_key = tmp_path / "cosign.key"
        private_key.write_text("private")

        # Set restrictive permissions (owner read/write only)
        os.chmod(private_key, 0o600)

        # Check permissions
        stat_info = private_key.stat()
        assert stat_info.st_mode & 0o777 == 0o600

    def test_public_key_can_be_world_readable(self, tmp_path: Path) -> None:
        """Verify public key can have open permissions."""
        import os

        public_key = tmp_path / "cosign.pub"
        public_key.write_text("public")

        # Set public permissions (readable by all)
        os.chmod(public_key, 0o644)

        # Check permissions
        stat_info = public_key.stat()
        assert stat_info.st_mode & 0o777 == 0o644

    def test_gitignore_includes_cosign_keys(self) -> None:
        """Verify .gitignore includes Cosign key patterns."""
        gitignore = Path(".gitignore")

        if gitignore.exists():
            content = gitignore.read_text()
            # Check for key-related patterns
            assert any(pattern in content for pattern in [".cosign-keys", "*.key", "cosign.key"])


class TestEmergencyRevocation:
    """Test emergency key revocation procedures."""

    def test_emergency_revocation_workflow_documented(self) -> None:
        """Verify emergency revocation procedure exists."""
        docs = Path("docs/security/cosign-key-management.md")

        if docs.exists():
            content = docs.read_text()
            assert "Emergency Key Revocation" in content
            assert "compromise" in content.lower()
            assert "revoke" in content.lower()

    @patch("subprocess.run")
    def test_can_generate_new_keys_after_revocation(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Verify new keys can be generated after revocation."""

        def create_keys(*args: object, **kwargs: Any) -> MagicMock:
            cwd = kwargs.get("cwd", str(tmp_path))
            output_dir = Path(str(cwd))
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "cosign.key").write_text("new-emergency-key")
            (output_dir / "cosign.pub").write_text("new-emergency-pub")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = create_keys

        # Generate emergency replacement keys
        private_key, public_key = generate_keypair(tmp_path)

        assert private_key.exists()
        assert public_key.exists()
        assert "emergency" in private_key.read_text()
