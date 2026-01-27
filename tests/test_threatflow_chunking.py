"""Unit tests for ThreatFlow chunking."""

from __future__ import annotations

from pathlib import Path

from kekkai.threatflow.chunking import (
    CHARS_PER_TOKEN,
    ChunkingConfig,
    ChunkingResult,
    FileChunk,
    chunk_files,
)


class TestChunkingConfig:
    """Tests for ChunkingConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ChunkingConfig()
        assert config.max_tokens_per_chunk == 2000
        assert config.max_file_size_bytes == 1_000_000
        assert config.max_files == 500
        assert ".py" in config.include_extensions
        assert ".git" in config.exclude_dirs

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = ChunkingConfig(
            max_tokens_per_chunk=1000,
            max_files=100,
        )
        assert config.max_tokens_per_chunk == 1000
        assert config.max_files == 100


class TestFileChunk:
    """Tests for FileChunk."""

    def test_chunk_token_estimate(self) -> None:
        """Test token estimation for chunks."""
        content = "x" * 100  # 100 characters
        chunk = FileChunk(
            file_path="test.py",
            content=content,
            start_line=1,
            end_line=10,
            chunk_index=0,
            total_chunks=1,
        )
        # Should be approximately 100 / CHARS_PER_TOKEN
        assert chunk.token_estimate == 100 // CHARS_PER_TOKEN

    def test_chunk_language_detection(self) -> None:
        """Test that language is set correctly."""
        chunk = FileChunk(
            file_path="test.py",
            content="print('hello')",
            start_line=1,
            end_line=1,
            chunk_index=0,
            total_chunks=1,
            language="python",
        )
        assert chunk.language == "python"


class TestChunkFiles:
    """Tests for chunk_files function."""

    def test_chunk_simple_repo(self, tmp_path: Path) -> None:
        """Test chunking a simple repository."""
        # Create a simple Python file
        py_file = tmp_path / "main.py"
        py_file.write_text("def hello():\n    print('hello')\n")

        result = chunk_files(tmp_path)

        assert isinstance(result, ChunkingResult)
        assert result.total_files_processed == 1
        assert len(result.chunks) >= 1
        assert result.chunks[0].language == "python"

    def test_chunk_excludes_git(self, tmp_path: Path) -> None:
        """Test that .git directory is excluded."""
        # Create .git directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")

        # Create regular file
        py_file = tmp_path / "main.py"
        py_file.write_text("print('hello')")

        result = chunk_files(tmp_path)

        # Should only process main.py
        assert result.total_files_processed == 1
        assert all(".git" not in c.file_path for c in result.chunks)

    def test_chunk_excludes_node_modules(self, tmp_path: Path) -> None:
        """Test that node_modules is excluded."""
        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "package.json").write_text("{}")

        py_file = tmp_path / "main.py"
        py_file.write_text("print('hello')")

        result = chunk_files(tmp_path)

        assert result.total_files_processed == 1
        assert all("node_modules" not in c.file_path for c in result.chunks)

    def test_chunk_respects_max_files(self, tmp_path: Path) -> None:
        """Test that max_files limit is respected."""
        # Create many files
        for i in range(10):
            (tmp_path / f"file{i}.py").write_text(f"# file {i}")

        config = ChunkingConfig(max_files=5)
        result = chunk_files(tmp_path, config)

        assert result.total_files_processed <= 5
        assert len(result.warnings) > 0  # Should warn about limit

    def test_chunk_skips_large_files(self, tmp_path: Path) -> None:
        """Test that large files are skipped."""
        # Create a file larger than limit
        large_file = tmp_path / "large.py"
        large_file.write_text("x" * 2_000_000)  # 2MB

        small_file = tmp_path / "small.py"
        small_file.write_text("print('small')")

        config = ChunkingConfig(max_file_size_bytes=1_000_000)
        result = chunk_files(tmp_path, config)

        assert result.total_files_processed == 1
        assert any(
            "large.py" in path and "too_large" in reason for path, reason in result.skipped_files
        )

    def test_chunk_skips_unsupported_extensions(self, tmp_path: Path) -> None:
        """Test that unsupported extensions are skipped."""
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        (tmp_path / "main.py").write_text("print('hello')")

        result = chunk_files(tmp_path)

        assert result.total_files_processed == 1
        assert any("image.png" in path for path, _ in result.skipped_files)

    def test_chunk_handles_special_files(self, tmp_path: Path) -> None:
        """Test that Dockerfile, Makefile etc are included."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12")
        (tmp_path / "Makefile").write_text("all:\n\techo hello")

        result = chunk_files(tmp_path)

        assert result.total_files_processed == 2

    def test_chunk_empty_repo(self, tmp_path: Path) -> None:
        """Test chunking an empty repository."""
        result = chunk_files(tmp_path)

        assert result.total_files_processed == 0
        assert len(result.chunks) == 0

    def test_chunk_splits_large_content(self, tmp_path: Path) -> None:
        """Test that large files are split into multiple chunks."""
        # Create a file that should be split
        lines = [f"line {i}\n" for i in range(500)]
        (tmp_path / "large.py").write_text("".join(lines))

        config = ChunkingConfig(max_tokens_per_chunk=100)  # Very small chunks
        result = chunk_files(tmp_path, config)

        # Should have multiple chunks for the file
        assert len(result.chunks) > 1
        # All chunks should be from the same file
        assert all(c.file_path == "large.py" for c in result.chunks)

    def test_chunk_result_token_estimate(self, tmp_path: Path) -> None:
        """Test total token estimation."""
        (tmp_path / "test.py").write_text("x" * 400)  # 400 chars = ~100 tokens

        result = chunk_files(tmp_path)

        assert result.total_tokens_estimated > 0
        assert result.total_tokens_estimated == sum(c.token_estimate for c in result.chunks)
