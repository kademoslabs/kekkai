"""Docker image metadata extraction and validation."""

import json
import subprocess
from typing import Any


class DockerMetadataError(Exception):
    """Raised when metadata extraction fails."""


def extract_image_metadata(image: str) -> dict[str, Any]:
    """
    Extract metadata from Docker image.

    Args:
        image: Docker image (e.g., 'kademoslabs/kekkai:latest')

    Returns:
        Image metadata as dictionary

    Raises:
        DockerMetadataError: If extraction fails
    """
    cmd = ["docker", "inspect", image]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

        metadata = json.loads(result.stdout)

        if not metadata or not isinstance(metadata, list):
            raise DockerMetadataError(f"Invalid metadata format for image: {image}")

        return metadata[0] if metadata else {}

    except subprocess.CalledProcessError as e:
        raise DockerMetadataError(f"Failed to extract metadata: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise DockerMetadataError("Metadata extraction timed out after 30s") from e
    except json.JSONDecodeError as e:
        raise DockerMetadataError(f"Failed to parse metadata: {e}") from e


def get_oci_labels(metadata: dict[str, Any]) -> dict[str, str]:
    """
    Extract OCI labels from image metadata.

    Args:
        metadata: Image metadata dictionary

    Returns:
        Dictionary of OCI labels
    """
    config = metadata.get("Config", {})
    labels = config.get("Labels") or {}

    # Filter for OCI labels (org.opencontainers.image.*)
    oci_labels = {
        key: value for key, value in labels.items() if key.startswith("org.opencontainers.image.")
    }

    return oci_labels


def parse_manifest(image: str) -> dict[str, Any]:
    """
    Parse Docker image manifest.

    Args:
        image: Docker image (e.g., 'kademoslabs/kekkai:latest')

    Returns:
        Manifest as dictionary

    Raises:
        DockerMetadataError: If parsing fails
    """
    cmd = ["docker", "manifest", "inspect", image]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

        manifest: dict[str, Any] = json.loads(result.stdout)
        return manifest

    except subprocess.CalledProcessError as e:
        raise DockerMetadataError(f"Failed to parse manifest: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise DockerMetadataError("Manifest parsing timed out after 30s") from e
    except json.JSONDecodeError as e:
        raise DockerMetadataError(f"Failed to parse manifest JSON: {e}") from e


def get_supported_architectures(manifest: dict[str, Any]) -> list[str]:
    """
    Extract supported architectures from manifest.

    Args:
        manifest: Image manifest dictionary

    Returns:
        List of supported architectures (e.g., ['amd64', 'arm64'])
    """
    architectures: list[str] = []

    # Multi-arch manifests have a "manifests" array
    manifests = manifest.get("manifests", [])

    if manifests:
        for m in manifests:
            platform = m.get("platform", {})
            arch = platform.get("architecture", "")
            if arch:
                architectures.append(arch)
    else:
        # Single-arch image
        platform = manifest.get("platform", {})
        arch = platform.get("architecture", "")
        if arch:
            architectures.append(arch)

    return architectures


def verify_multi_arch_support(
    manifest: dict[str, Any],
    required_archs: list[str],
) -> bool:
    """
    Verify image supports required architectures.

    Args:
        manifest: Image manifest dictionary
        required_archs: List of required architectures

    Returns:
        True if all required architectures are supported
    """
    supported = get_supported_architectures(manifest)
    return all(arch in supported for arch in required_archs)
