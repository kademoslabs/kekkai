"""Unit tests for code context extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from kekkai.triage.code_context import CodeContext, CodeContextExtractor


class TestCodeContextExtractor:
    """Tests for CodeContextExtractor functionality."""

    @pytest.fixture
    def temp_repo(self, tmp_path: Path) -> Path:
        """Create a temporary repository structure."""
        repo = tmp_path / "repo"
        repo.mkdir()
        return repo

    @pytest.fixture
    def extractor(self, temp_repo: Path) -> CodeContextExtractor:
        """Create a code context extractor."""
        return CodeContextExtractor(temp_repo)

    @pytest.fixture
    def sample_python_file(self, temp_repo: Path) -> Path:
        """Create a sample Python file with 50 lines."""
        py_file = temp_repo / "sample.py"
        lines = [f"# Line {i + 1}\ndef function_{i}():\n    pass\n" for i in range(50)]
        py_file.write_text("".join(lines))
        return py_file

    def test_extract_valid_python_file(
        self, extractor: CodeContextExtractor, sample_python_file: Path
    ) -> None:
        """Test extracting context from a valid Python file."""
        context = extractor.extract("sample.py", 25)

        assert context is not None
        assert context.error is None
        assert context.language == "python"
        assert context.code
        assert context.vulnerable_line

        # Should contain lines around line 25
        assert "25" in context.code

    def test_extract_highlights_vulnerable_line(
        self, extractor: CodeContextExtractor, sample_python_file: Path
    ) -> None:
        """Test that vulnerable line is highlighted with >>> marker."""
        context = extractor.extract("sample.py", 10)

        assert context is not None
        assert context.error is None
        # The >>> marker should be in the code context
        assert ">>>" in context.code
        # Line 10 should be marked
        assert "10" in context.code

    def test_extract_handles_edge_lines_start(
        self, extractor: CodeContextExtractor, sample_python_file: Path
    ) -> None:
        """Test extraction near start of file (line 2)."""
        context = extractor.extract("sample.py", 2)

        assert context is not None
        assert context.error is None
        assert context.code
        # Should not crash, should show what's available

    def test_extract_handles_edge_lines_end(
        self, extractor: CodeContextExtractor, temp_repo: Path
    ) -> None:
        """Test extraction near end of file."""
        # Create file with 100 lines
        py_file = temp_repo / "longfile.py"
        lines = [f"line {i + 1}\n" for i in range(100)]
        py_file.write_text("".join(lines))

        extractor = CodeContextExtractor(temp_repo)
        context = extractor.extract("longfile.py", 98)

        assert context is not None
        assert context.error is None
        assert context.code
        # Should show lines up to 98 and a bit after

    def test_extract_handles_missing_file(self, extractor: CodeContextExtractor) -> None:
        """Test that missing files are handled gracefully."""
        context = extractor.extract("nonexistent.py", 10)

        assert context is not None
        assert context.error is not None
        assert "not found" in context.error.lower()

    def test_extract_skips_binary_files(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that binary files are skipped."""
        # .pyc file
        pyc_file = temp_repo / "module.pyc"
        pyc_file.write_bytes(b"\x00\x00\x00\x00binary")

        context = extractor.extract("module.pyc", 1)
        assert context is None

        # .so file
        so_file = temp_repo / "lib.so"
        so_file.write_bytes(b"\x7fELF")

        context = extractor.extract("lib.so", 1)
        assert context is None

        # .png file
        png_file = temp_repo / "image.png"
        png_file.write_bytes(b"\x89PNG")

        context = extractor.extract("image.png", 1)
        assert context is None

    def test_extract_enforces_size_limit(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that file size limit is enforced (15MB file)."""
        large_file = temp_repo / "huge.txt"
        # Create 15MB file
        with large_file.open("w") as f:
            f.write("x" * (15 * 1024 * 1024))

        context = extractor.extract("huge.txt", 1)
        assert context is not None
        assert context.error is not None
        assert "too large" in context.error.lower()
        assert "15.0MB" in context.error

    def test_detect_language_from_extension(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test language detection for various file extensions."""
        test_cases = [
            ("test.js", "javascript"),
            ("test.go", "go"),
            ("test.rs", "rust"),
            ("test.java", "java"),
            ("test.rb", "ruby"),
            ("test.php", "php"),
            ("test.ts", "typescript"),
        ]

        for filename, expected_lang in test_cases:
            file_path = temp_repo / filename
            file_path.write_text("// test code\n")

            context = extractor.extract(filename, 1)
            assert context is not None
            assert context.error is None
            assert context.language == expected_lang, f"Failed for {filename}"

    def test_extract_returns_none_for_missing_file_path(
        self, extractor: CodeContextExtractor
    ) -> None:
        """Test that None is returned when file_path is empty."""
        context = extractor.extract("", 10)
        assert context is None

    def test_extract_returns_none_for_missing_line(
        self, extractor: CodeContextExtractor, sample_python_file: Path
    ) -> None:
        """Test that None is returned when line is None."""
        context = extractor.extract("sample.py", None)
        assert context is None

    def test_extract_with_subdirectories(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test extraction from files in subdirectories."""
        # Create subdirectory structure
        subdir = temp_repo / "src" / "module"
        subdir.mkdir(parents=True)

        py_file = subdir / "code.py"
        py_file.write_text("def test():\n    return 42\n")

        context = extractor.extract("src/module/code.py", 1)
        assert context is not None
        assert context.error is None
        assert "def test" in context.code

    def test_code_context_dataclass(self) -> None:
        """Test CodeContext dataclass."""
        ctx = CodeContext(
            code="line 1\nline 2\n",
            language="python",
            vulnerable_line="line 2",
            error=None,
        )

        assert ctx.code == "line 1\nline 2\n"
        assert ctx.language == "python"
        assert ctx.vulnerable_line == "line 2"
        assert ctx.error is None

    def test_code_context_with_error(self) -> None:
        """Test CodeContext with error."""
        ctx = CodeContext(
            code="",
            language="",
            vulnerable_line="",
            error="File not found",
        )

        assert ctx.error == "File not found"
        assert not ctx.code

    def test_extract_line_out_of_range(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test extraction with line number beyond file length."""
        small_file = temp_repo / "small.py"
        small_file.write_text("line 1\nline 2\nline 3\n")

        # Request line 100 from 3-line file
        context = extractor.extract("small.py", 100)

        assert context is not None
        # Should gracefully handle and return empty or show what's available
        # The extract_code_context method handles this gracefully

    def test_special_files_without_extension(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that special files without extensions are treated as text."""
        # Create Dockerfile
        dockerfile = temp_repo / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN pip install kekkai\n")

        context = extractor.extract("Dockerfile", 1)
        assert context is not None
        assert context.error is None
        assert "FROM python" in context.code

        # Create Makefile
        makefile = temp_repo / "Makefile"
        makefile.write_text("all:\n\techo 'test'\n")

        context = extractor.extract("Makefile", 1)
        assert context is not None
        assert context.error is None

    def test_extractor_initialization(self, temp_repo: Path) -> None:
        """Test CodeContextExtractor initialization."""
        extractor = CodeContextExtractor(temp_repo, max_file_size_mb=5)

        assert extractor.repo_path == temp_repo.resolve()
        assert extractor.max_file_size_mb == 5
        assert extractor._prompt_builder is not None

    def test_validate_path_within_repo(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test _validate_path accepts paths within repo."""
        valid_path = (temp_repo / "valid.py").resolve()
        assert extractor._validate_path(valid_path) is True

    def test_validate_path_outside_repo(
        self, temp_repo: Path, extractor: CodeContextExtractor, tmp_path: Path
    ) -> None:
        """Test _validate_path rejects paths outside repo."""
        outside_path = (tmp_path / "outside.py").resolve()
        assert extractor._validate_path(outside_path) is False

    def test_extract_windows1252_file(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test extraction of Windows-1252 encoded file with smart quotes."""
        # Create file with Windows-1252 encoding (smart quotes)
        # \x93 and \x94 are left and right double quotes in Windows-1252
        windows_file = temp_repo / "legacy.txt"
        windows_file.write_bytes(b"Line 1\nSmart quote: \x93test\x94\nLine 3\n")

        context = extractor.extract("legacy.txt", 2)

        # Should succeed with replacement characters
        assert context is not None
        assert context.error is None
        # Replacement character � (U+FFFD) should appear for invalid UTF-8 bytes
        assert "�" in context.code or "test" in context.code

    def test_extract_latin1_file(self, temp_repo: Path, extractor: CodeContextExtractor) -> None:
        """Test extraction of Latin-1 encoded file."""
        # Create file with Latin-1 encoding (accented characters)
        latin1_file = temp_repo / "spanish.txt"
        # é in Latin-1 is \xe9, ñ is \xf1
        latin1_file.write_bytes(b"Line 1\ncaf\xe9 espa\xf1ol\nLine 3\n")

        context = extractor.extract("spanish.txt", 2)

        # Should succeed with replacement characters
        assert context is not None
        assert context.error is None
        # Either shows replacement chars or the text (depending on encoding luck)
        assert context.code

    def test_extract_utf8_still_works(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that UTF-8 files still work correctly after adding fallback."""
        # Create proper UTF-8 file with emoji
        utf8_file = temp_repo / "modern.py"
        utf8_file.write_text("# Line 1\n# Test 🔥 emoji\n# Line 3\n", encoding="utf-8")

        context = extractor.extract("modern.py", 2)

        # Should succeed without fallback
        assert context is not None
        assert context.error is None
        assert "🔥" in context.code or "emoji" in context.code

    def test_extract_binary_still_skipped(
        self, temp_repo: Path, extractor: CodeContextExtractor
    ) -> None:
        """Test that binary files are still skipped after adding encoding fallback."""
        # Create binary file
        binary_file = temp_repo / "binary.pyc"
        binary_file.write_bytes(b"\x00\x00\x00\x00\xffbinary")

        context = extractor.extract("binary.pyc", 1)

        # Should be skipped (return None for binary)
        assert context is None
