"""Unit tests for installer archive extraction."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from kekkai.installer import ExtractionError, SecurityError
from kekkai.installer.extract import extract_archive, extract_tar_gz, extract_zip


class TestExtractTarGz:
    """Test tar.gz extraction."""

    def test_extract_simple_tarball(self, tmp_path: Path) -> None:
        # Create a test archive
        archive_path = tmp_path / "test.tar.gz"
        binary_content = b"#!/bin/sh\necho hello"

        with tarfile.open(archive_path, "w:gz") as tar:
            import io

            data = io.BytesIO(binary_content)
            info = tarfile.TarInfo(name="mytool")
            info.size = len(binary_content)
            tar.addfile(info, data)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_tar_gz(archive_path, dest_dir, "mytool")

        assert result.exists()
        assert result.name == "mytool"
        assert result.read_bytes() == binary_content

    def test_extract_nested_binary(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.tar.gz"
        binary_content = b"binary content"

        with tarfile.open(archive_path, "w:gz") as tar:
            import io

            data = io.BytesIO(binary_content)
            info = tarfile.TarInfo(name="subdir/mytool")
            info.size = len(binary_content)
            tar.addfile(info, data)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_tar_gz(archive_path, dest_dir, "mytool")

        assert result.exists()
        assert result.name == "mytool"

    def test_binary_not_found_raises_error(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.tar.gz"

        with tarfile.open(archive_path, "w:gz") as tar:
            import io

            data = io.BytesIO(b"content")
            info = tarfile.TarInfo(name="other_file")
            info.size = 7
            tar.addfile(info, data)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        with pytest.raises(ExtractionError, match="not found in archive"):
            extract_tar_gz(archive_path, dest_dir, "missing_binary")

    def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.tar.gz"

        with tarfile.open(archive_path, "w:gz") as tar:
            import io

            data = io.BytesIO(b"malicious")
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 9
            tar.addfile(info, data)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        with pytest.raises(SecurityError, match="Path traversal"):
            extract_tar_gz(archive_path, dest_dir, "passwd")


class TestExtractZip:
    """Test zip extraction."""

    def test_extract_simple_zip(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.zip"
        binary_content = b"zip binary content"

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("mytool", binary_content)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_zip(archive_path, dest_dir, "mytool")

        assert result.exists()
        assert result.name == "mytool"
        assert result.read_bytes() == binary_content

    def test_extract_exe_file(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.zip"
        binary_content = b"windows exe"

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("mytool.exe", binary_content)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_zip(archive_path, dest_dir, "mytool")

        assert result.exists()
        assert result.name == "mytool.exe"

    def test_binary_not_found_raises_error(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.zip"

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("other_file", b"content")

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        with pytest.raises(ExtractionError, match="not found in archive"):
            extract_zip(archive_path, dest_dir, "missing_binary")


class TestExtractArchive:
    """Test generic archive extraction."""

    def test_dispatch_to_tar_gz(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.tar.gz"

        with tarfile.open(archive_path, "w:gz") as tar:
            import io

            data = io.BytesIO(b"content")
            info = tarfile.TarInfo(name="tool")
            info.size = 7
            tar.addfile(info, data)

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_archive(archive_path, dest_dir, "tool", "tar.gz")
        assert result.exists()

    def test_dispatch_to_zip(self, tmp_path: Path) -> None:
        archive_path = tmp_path / "test.zip"

        with zipfile.ZipFile(archive_path, "w") as zf:
            zf.writestr("tool", b"content")

        dest_dir = tmp_path / "extracted"
        dest_dir.mkdir()

        result = extract_archive(archive_path, dest_dir, "tool", "zip")
        assert result.exists()

    def test_unsupported_type_raises_error(self, tmp_path: Path) -> None:
        with pytest.raises(ExtractionError, match="Unsupported archive type"):
            extract_archive(tmp_path / "test.rar", tmp_path, "tool", "rar")
