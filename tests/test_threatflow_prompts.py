"""Unit tests for ThreatFlow prompts."""

from __future__ import annotations

from kekkai.threatflow.prompts import PromptBuilder, STRIDECategory


class TestSTRIDECategory:
    """Tests for STRIDECategory enum."""

    def test_all_stride_categories_exist(self) -> None:
        """Test that all STRIDE categories are defined."""
        assert STRIDECategory.SPOOFING
        assert STRIDECategory.TAMPERING
        assert STRIDECategory.REPUDIATION
        assert STRIDECategory.INFORMATION_DISCLOSURE
        assert STRIDECategory.DENIAL_OF_SERVICE
        assert STRIDECategory.ELEVATION_OF_PRIVILEGE

    def test_all_descriptions_covers_all(self) -> None:
        """Test that all_descriptions includes all categories."""
        desc = STRIDECategory.all_descriptions()
        assert "Spoofing" in desc
        assert "Tampering" in desc
        assert "Repudiation" in desc
        assert "Information Disclosure" in desc
        assert "Denial of Service" in desc
        assert "Elevation of Privilege" in desc


class TestPromptBuilder:
    """Tests for PromptBuilder class."""

    def test_build_system_prompt_includes_stride(self) -> None:
        """Test that system prompt includes STRIDE categories."""
        builder = PromptBuilder()
        prompt = builder.build_system_prompt()
        assert "STRIDE" in prompt
        assert "Spoofing" in prompt
        assert "Tampering" in prompt

    def test_build_system_prompt_includes_safety_instructions(self) -> None:
        """Test that system prompt includes safety instructions."""
        builder = PromptBuilder()
        prompt = builder.build_system_prompt()
        assert "UNTRUSTED" in prompt.upper() or "untrusted" in prompt.lower()
        assert "do not execute" in prompt.lower() or "never execute" in prompt.lower()

    def test_build_dataflow_prompt_includes_content(self) -> None:
        """Test that dataflow prompt includes the provided content."""
        builder = PromptBuilder()
        content = "def hello(): print('hello')"
        prompt = builder.build_dataflow_prompt(content)
        assert content in prompt

    def test_build_dataflow_prompt_includes_instructions(self) -> None:
        """Test that dataflow prompt includes analysis instructions."""
        builder = PromptBuilder()
        prompt = builder.build_dataflow_prompt("code here")
        assert "External Entities" in prompt
        assert "Data Flows" in prompt
        assert "Trust Boundaries" in prompt

    def test_build_threats_prompt_includes_both_inputs(self) -> None:
        """Test that threats prompt includes dataflow and code."""
        builder = PromptBuilder()
        prompt = builder.build_threats_prompt(
            dataflow_content="User -> API",
            code_context="def process(): pass",
        )
        assert "User -> API" in prompt
        assert "def process" in prompt

    def test_build_threats_prompt_includes_stride_format(self) -> None:
        """Test that threats prompt requests STRIDE format."""
        builder = PromptBuilder()
        prompt = builder.build_threats_prompt("dataflow", "code")
        assert "STRIDE" in prompt
        assert "Category" in prompt
        assert "Mitigation" in prompt

    def test_build_assumptions_prompt_includes_metadata(self) -> None:
        """Test that assumptions prompt includes metadata."""
        builder = PromptBuilder()
        prompt = builder.build_assumptions_prompt(
            file_count=10,
            languages=["python", "javascript"],
            components=["API", "Database"],
        )
        assert "10" in prompt
        assert "python" in prompt
        assert "javascript" in prompt

    def test_truncate_content_respects_limit(self) -> None:
        """Test that content is truncated when too long."""
        builder = PromptBuilder(max_content_chars=100)
        long_content = "x" * 200
        result = builder._truncate_content(long_content)
        assert len(result) < 200
        assert "truncated" in result.lower()

    def test_truncate_content_preserves_short_content(self) -> None:
        """Test that short content is not truncated."""
        builder = PromptBuilder(max_content_chars=100)
        short_content = "hello world"
        result = builder._truncate_content(short_content)
        assert result == short_content

    def test_format_code_chunks_includes_all_chunks(self) -> None:
        """Test that format_code_chunks includes all provided chunks."""
        builder = PromptBuilder()
        chunks = [
            ("file1.py", "print('hello')", 1, 1),
            ("file2.py", "def foo(): pass", 1, 1),
        ]
        result = builder.format_code_chunks(chunks)
        assert "file1.py" in result
        assert "file2.py" in result
        assert "print('hello')" in result
        assert "def foo()" in result

    def test_format_code_chunks_includes_line_numbers(self) -> None:
        """Test that format_code_chunks includes line numbers."""
        builder = PromptBuilder(include_line_numbers=True)
        chunks = [("test.py", "code", 10, 20)]
        result = builder.format_code_chunks(chunks)
        assert "10" in result
        assert "20" in result

    def test_format_code_chunks_uses_markdown_fences(self) -> None:
        """Test that format_code_chunks uses markdown code fences."""
        builder = PromptBuilder()
        chunks = [("test.py", "print('hello')", 1, 1)]
        result = builder.format_code_chunks(chunks)
        assert "```python" in result
        assert "```" in result

    def test_detect_lang_python(self) -> None:
        """Test language detection for Python."""
        builder = PromptBuilder()
        assert builder._detect_lang("test.py") == "python"

    def test_detect_lang_javascript(self) -> None:
        """Test language detection for JavaScript."""
        builder = PromptBuilder()
        assert builder._detect_lang("test.js") == "javascript"

    def test_detect_lang_typescript(self) -> None:
        """Test language detection for TypeScript."""
        builder = PromptBuilder()
        assert builder._detect_lang("test.ts") == "typescript"

    def test_detect_lang_unknown(self) -> None:
        """Test language detection for unknown extension."""
        builder = PromptBuilder()
        assert builder._detect_lang("test.xyz") == ""
