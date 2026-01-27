"""Docker image signing and verification with Cosign."""

import os
import subprocess
from pathlib import Path


class CosignError(Exception):
    """Raised when Cosign operations fail."""


def sign_image(
    image: str,
    key_path: Path | None = None,
    password: str | None = None,
) -> bool:
    """
    Sign Docker image with Cosign.

    Args:
        image: Docker image to sign (e.g., 'kademoslabs/kekkai:latest')
        key_path: Path to Cosign private key (optional, uses keyless if None)
        password: Password for private key (optional)

    Returns:
        True if signing succeeded

    Raises:
        CosignError: If signing fails
    """
    cmd = ["cosign", "sign", "--yes"]

    if key_path:
        cmd.extend(["--key", str(key_path)])

    cmd.append(image)

    try:
        env = {}
        if password:
            env["COSIGN_PASSWORD"] = password

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
            env={**os.environ, **env} if env else None,
        )
        return result.returncode == 0

    except subprocess.CalledProcessError as e:
        raise CosignError(f"Image signing failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise CosignError("Image signing timed out after 120s") from e


def verify_signature(
    image: str,
    key_path: Path | None = None,
) -> bool:
    """
    Verify Docker image signature with Cosign.

    Args:
        image: Docker image to verify (e.g., 'kademoslabs/kekkai:latest')
        key_path: Path to Cosign public key (optional, uses keyless if None)

    Returns:
        True if signature is valid

    Raises:
        CosignError: If verification fails
    """
    cmd = ["cosign", "verify"]

    if key_path:
        cmd.extend(["--key", str(key_path)])

    cmd.append(image)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # Don't raise on non-zero exit
            timeout=120,
        )
        return result.returncode == 0

    except subprocess.TimeoutExpired as e:
        raise CosignError("Signature verification timed out after 120s") from e


def generate_keypair(output_dir: Path) -> tuple[Path, Path]:
    """
    Generate Cosign keypair.

    Args:
        output_dir: Directory to store keys

    Returns:
        Tuple of (private_key_path, public_key_path)

    Raises:
        CosignError: If key generation fails
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = output_dir / "cosign.key"
    public_key = output_dir / "cosign.pub"

    cmd = ["cosign", "generate-key-pair"]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            cwd=str(output_dir),
            timeout=60,
        )

        if not private_key.exists() or not public_key.exists():
            raise CosignError("Key generation succeeded but keys not found")

        return (private_key, public_key)

    except subprocess.CalledProcessError as e:
        raise CosignError(f"Key generation failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise CosignError("Key generation timed out after 60s") from e
