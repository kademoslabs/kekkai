"""Archive extraction utilities."""

from __future__ import annotations

import logging
import os
import tarfile
import zipfile
from pathlib import Path

from .errors import ExtractionError, SecurityError

logger = logging.getLogger(__name__)


def _is_safe_path(base_path: Path, target_path: Path) -> bool:
    """Check if target path is safe (no path traversal).

    Args:
        base_path: Base extraction directory.
        target_path: Target path to check.

    Returns:
        True if path is safe.
    """
    try:
        target_path.resolve().relative_to(base_path.resolve())
        return True
    except ValueError:
        return False


def extract_tar_gz(archive_path: Path, dest_dir: Path, binary_name: str) -> Path:
    """Extract a tar.gz archive and return path to binary.

    Args:
        archive_path: Path to the archive.
        dest_dir: Destination directory.
        binary_name: Name of the binary to extract.

    Returns:
        Path to extracted binary.

    Raises:
        ExtractionError: If extraction fails.
        SecurityError: If archive contains path traversal.
    """
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            # Security: Check for path traversal
            for member in tar.getmembers():
                member_path = dest_dir / member.name
                if not _is_safe_path(dest_dir, member_path):
                    raise SecurityError(f"Path traversal detected in archive: {member.name}")

            # Find and extract the binary
            binary_member = None
            for member in tar.getmembers():
                if member.name == binary_name or member.name.endswith(f"/{binary_name}"):
                    binary_member = member
                    break

            if not binary_member:
                raise ExtractionError(f"Binary '{binary_name}' not found in archive")

            # Extract just the binary
            tar.extract(binary_member, dest_dir, filter="data")

            extracted_path = dest_dir / binary_member.name
            if not extracted_path.exists():
                raise ExtractionError(f"Extraction failed: {extracted_path} not found")

            # Move to final location if nested
            final_path = dest_dir / binary_name
            if extracted_path != final_path:
                extracted_path.rename(final_path)

            return final_path

    except tarfile.TarError as e:
        raise ExtractionError(f"Failed to extract tar.gz: {e}") from e


def extract_zip(archive_path: Path, dest_dir: Path, binary_name: str) -> Path:
    """Extract a zip archive and return path to binary.

    Args:
        archive_path: Path to the archive.
        dest_dir: Destination directory.
        binary_name: Name of the binary to extract.

    Returns:
        Path to extracted binary.

    Raises:
        ExtractionError: If extraction fails.
        SecurityError: If archive contains path traversal.
    """
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            # Security: Check for path traversal
            for name in zf.namelist():
                member_path = dest_dir / name
                if not _is_safe_path(dest_dir, member_path):
                    raise SecurityError(f"Path traversal detected in archive: {name}")

            # Find and extract the binary
            binary_name_variants = [binary_name, f"{binary_name}.exe"]
            binary_member = None

            for name in zf.namelist():
                base_name = os.path.basename(name)
                if base_name in binary_name_variants:
                    binary_member = name
                    break

            if not binary_member:
                raise ExtractionError(f"Binary '{binary_name}' not found in archive")

            # Extract just the binary
            zf.extract(binary_member, dest_dir)

            extracted_path = dest_dir / binary_member
            if not extracted_path.exists():
                raise ExtractionError(f"Extraction failed: {extracted_path} not found")

            # Move to final location if nested
            final_name = binary_name
            if extracted_path.suffix == ".exe":
                final_name = f"{binary_name}.exe"

            final_path = dest_dir / final_name
            if extracted_path != final_path:
                extracted_path.rename(final_path)

            return final_path

    except zipfile.BadZipFile as e:
        raise ExtractionError(f"Failed to extract zip: {e}") from e


def extract_archive(
    archive_path: Path, dest_dir: Path, binary_name: str, archive_type: str
) -> Path:
    """Extract an archive and return path to binary.

    Args:
        archive_path: Path to the archive.
        dest_dir: Destination directory.
        binary_name: Name of the binary to extract.
        archive_type: Type of archive ("tar.gz" or "zip").

    Returns:
        Path to extracted binary.
    """
    if archive_type == "tar.gz":
        return extract_tar_gz(archive_path, dest_dir, binary_name)
    elif archive_type == "zip":
        return extract_zip(archive_path, dest_dir, binary_name)
    else:
        raise ExtractionError(f"Unsupported archive type: {archive_type}")
