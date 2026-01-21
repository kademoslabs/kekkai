"""Safe file chunking for ThreatFlow.

Splits repository files into manageable chunks for LLM processing while:
- Respecting token limits
- Maintaining context boundaries (don't split mid-function)
- Handling various file types appropriately
- Never executing code

ASVS V13.1.3: Resource management and timeouts.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Approximate chars per token (conservative estimate)
CHARS_PER_TOKEN = 4

# Default limits
DEFAULT_MAX_TOKENS_PER_CHUNK = 2000
DEFAULT_MAX_FILE_SIZE_BYTES = 1_000_000  # 1MB
DEFAULT_MAX_FILES = 500

# File extensions to include by default
DEFAULT_INCLUDE_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".rb",
        ".php",
        ".swift",
        ".kt",
        ".scala",
        ".sql",
        ".sh",
        ".bash",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".xml",
        ".html",
        ".css",
        ".md",
        ".txt",
        ".dockerfile",
        ".tf",
        ".hcl",
    }
)

# Directories to exclude
DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "venv",
        ".venv",
        "env",
        ".env",
        "dist",
        "build",
        "target",
        ".tox",
        ".eggs",
        "*.egg-info",
        "vendor",
        "third_party",
    }
)


@dataclass(frozen=True)
class ChunkingConfig:
    """Configuration for file chunking."""

    max_tokens_per_chunk: int = DEFAULT_MAX_TOKENS_PER_CHUNK
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    max_files: int = DEFAULT_MAX_FILES
    include_extensions: frozenset[str] = DEFAULT_INCLUDE_EXTENSIONS
    exclude_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS
    overlap_lines: int = 3  # Lines to overlap between chunks for context


@dataclass(frozen=True)
class FileChunk:
    """A chunk of file content with metadata."""

    file_path: str
    content: str
    start_line: int
    end_line: int
    chunk_index: int
    total_chunks: int
    language: str | None = None

    @property
    def token_estimate(self) -> int:
        """Estimate token count for this chunk."""
        return len(self.content) // CHARS_PER_TOKEN


@dataclass
class ChunkingResult:
    """Result of chunking a repository."""

    chunks: list[FileChunk] = field(default_factory=list)
    skipped_files: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    total_files_processed: int = 0
    total_tokens_estimated: int = 0
    warnings: list[str] = field(default_factory=list)


def _detect_language(file_path: str) -> str | None:
    """Detect programming language from file extension."""
    ext_to_lang = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".rb": "ruby",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".sql": "sql",
        ".sh": "bash",
        ".bash": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
        ".md": "markdown",
        ".tf": "terraform",
        ".hcl": "hcl",
    }
    ext = Path(file_path).suffix.lower()
    return ext_to_lang.get(ext)


def _should_include_file(
    file_path: Path,
    config: ChunkingConfig,
) -> tuple[bool, str | None]:
    """Check if a file should be included in chunking.

    Returns (should_include, skip_reason).
    """
    # Check extension
    special_files = ("dockerfile", "makefile", "jenkinsfile", "vagrantfile")
    ext_ok = file_path.suffix.lower() in config.include_extensions
    name_ok = file_path.name.lower() in special_files
    if not ext_ok and not name_ok:
        return False, "unsupported_extension"

    # Check file size
    try:
        size = file_path.stat().st_size
        if size > config.max_file_size_bytes:
            return False, f"file_too_large ({size} bytes)"
        if size == 0:
            return False, "empty_file"
    except OSError:
        return False, "cannot_read"

    return True, None


def _should_exclude_dir(dir_name: str, config: ChunkingConfig) -> bool:
    """Check if a directory should be excluded."""
    return dir_name in config.exclude_dirs or dir_name.startswith(".")


def _find_chunk_boundary(lines: list[str], target_line: int, direction: int = 1) -> int:
    """Find a good boundary for splitting chunks.

    Looks for natural breakpoints like blank lines, function definitions.
    """
    # Try to find a blank line near the target
    search_range = 5
    for offset in range(search_range):
        check_line = target_line + (offset * direction)
        if 0 <= check_line < len(lines):
            line = lines[check_line].strip()
            # Good break points: blank lines, class/function definitions
            if not line or line.startswith(("def ", "class ", "function ", "async def ")):
                return check_line

    return target_line


def _chunk_file_content(
    file_path: str,
    content: str,
    config: ChunkingConfig,
) -> list[FileChunk]:
    """Split file content into chunks."""
    lines = content.splitlines(keepends=True)
    if not lines:
        return []

    max_chars = config.max_tokens_per_chunk * CHARS_PER_TOKEN
    language = _detect_language(file_path)
    chunks: list[FileChunk] = []

    current_start = 0
    chunk_index = 0

    while current_start < len(lines):
        # Find end of chunk based on character count
        current_chars = 0
        current_end = current_start

        while current_end < len(lines) and current_chars < max_chars:
            current_chars += len(lines[current_end])
            current_end += 1

        # Try to find a good boundary if we're not at the end
        if current_end < len(lines):
            boundary = _find_chunk_boundary(lines, current_end - 1, direction=-1)
            if boundary > current_start:
                current_end = boundary + 1

        # Build chunk content
        chunk_lines = lines[current_start:current_end]
        chunk_content = "".join(chunk_lines)

        chunks.append(
            FileChunk(
                file_path=file_path,
                content=chunk_content,
                start_line=current_start + 1,  # 1-indexed
                end_line=current_end,
                chunk_index=chunk_index,
                total_chunks=0,  # Updated later
                language=language,
            )
        )

        # Move to next chunk, with overlap
        current_start = max(current_start + 1, current_end - config.overlap_lines)
        chunk_index += 1

    # Update total_chunks for all chunks
    total = len(chunks)
    return [
        FileChunk(
            file_path=c.file_path,
            content=c.content,
            start_line=c.start_line,
            end_line=c.end_line,
            chunk_index=c.chunk_index,
            total_chunks=total,
            language=c.language,
        )
        for c in chunks
    ]


def _iter_repo_files(
    repo_path: Path,
    config: ChunkingConfig,
) -> Iterator[tuple[Path, str | None]]:
    """Iterate over files in the repository.

    Yields (file_path, skip_reason) tuples.
    """
    for root, dirs, files in os.walk(repo_path):
        # Filter out excluded directories in-place
        dirs[:] = [d for d in dirs if not _should_exclude_dir(d, config)]

        for filename in files:
            file_path = Path(root) / filename
            should_include, skip_reason = _should_include_file(file_path, config)

            if should_include:
                yield file_path, None
            else:
                yield file_path, skip_reason


def chunk_files(
    repo_path: Path,
    config: ChunkingConfig | None = None,
) -> ChunkingResult:
    """Chunk all eligible files in a repository.

    Args:
        repo_path: Path to the repository root
        config: Chunking configuration (uses defaults if not provided)

    Returns:
        ChunkingResult with all chunks and metadata
    """
    config = config or ChunkingConfig()
    result = ChunkingResult()

    files_processed = 0
    for file_path, skip_reason in _iter_repo_files(repo_path, config):
        if skip_reason:
            rel_path = str(file_path.relative_to(repo_path))
            result.skipped_files.append((rel_path, skip_reason))
            continue

        # Enforce file limit
        if files_processed >= config.max_files:
            result.warnings.append(
                f"Reached max file limit ({config.max_files}). Some files were not processed."
            )
            break

        # Read file content (text only - never execute)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            rel_path = str(file_path.relative_to(repo_path))
            result.skipped_files.append((rel_path, f"read_error: {e}"))
            continue

        # Chunk the file
        rel_path = str(file_path.relative_to(repo_path))
        file_chunks = _chunk_file_content(rel_path, content, config)
        result.chunks.extend(file_chunks)
        files_processed += 1

    result.total_files_processed = files_processed
    result.total_tokens_estimated = sum(c.token_estimate for c in result.chunks)

    return result
