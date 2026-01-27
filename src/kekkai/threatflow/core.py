"""ThreatFlow core orchestrator.

Main entry point for threat model generation that:
- Coordinates chunking, redaction, sanitization
- Manages LLM interactions
- Produces structured artifacts
- Enforces security controls

ASVS V16.5.1: Generic errors without exposing internals.
ASVS V13.1.3: Timeouts and resource limits.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .artifacts import ArtifactGenerator, ThreatModelArtifacts
from .chunking import ChunkingConfig, ChunkingResult, chunk_files
from .model_adapter import (
    ModelAdapter,
    ModelConfig,
    ModelResponse,
    create_adapter,
)
from .prompts import PromptBuilder
from .redaction import ThreatFlowRedactor
from .sanitizer import Sanitizer

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class ThreatFlowConfig:
    """Configuration for ThreatFlow analysis."""

    # Model settings
    model_mode: str = "local"  # local, openai, anthropic, mock
    model_path: str | None = None
    api_key: str | None = None
    api_base: str | None = None
    model_name: str | None = None

    # Processing settings
    max_tokens_per_chunk: int = 2000
    max_files: int = 500
    timeout_seconds: int = 300

    # Output settings
    output_dir: Path | None = None

    # Security settings
    redact_secrets: bool = True
    sanitize_content: bool = True
    warn_on_injection: bool = True

    @classmethod
    def from_env(cls) -> ThreatFlowConfig:
        """Create config from environment variables."""
        return cls(
            model_mode=os.environ.get("KEKKAI_THREATFLOW_MODE", "local"),
            model_path=os.environ.get("KEKKAI_THREATFLOW_MODEL_PATH"),
            api_key=os.environ.get("KEKKAI_THREATFLOW_API_KEY"),
            api_base=os.environ.get("KEKKAI_THREATFLOW_API_BASE"),
            model_name=os.environ.get("KEKKAI_THREATFLOW_MODEL_NAME"),
        )


@dataclass
class ThreatFlowResult:
    """Result of ThreatFlow analysis."""

    success: bool
    artifacts: ThreatModelArtifacts | None = None
    output_files: list[Path] = field(default_factory=list)
    model_mode: str = "unknown"
    duration_ms: int = 0
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    injection_warnings: list[str] = field(default_factory=list)
    files_processed: int = 0
    files_skipped: int = 0

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON output."""
        return {
            "success": self.success,
            "model_mode": self.model_mode,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "warnings": self.warnings,
            "injection_warnings": self.injection_warnings,
            "files_processed": self.files_processed,
            "files_skipped": self.files_skipped,
            "output_files": [str(p) for p in self.output_files],
        }


class ThreatFlow:
    """ThreatFlow threat model generator.

    Security-first design:
    - Never executes repository code
    - Redacts secrets before LLM processing
    - Defends against prompt injection
    - Local model by default
    """

    def __init__(
        self,
        config: ThreatFlowConfig | None = None,
        adapter: ModelAdapter | None = None,
    ) -> None:
        self.config = config or ThreatFlowConfig.from_env()

        # Initialize adapter
        if adapter:
            self._adapter = adapter
        else:
            model_config = ModelConfig(
                model_path=self.config.model_path,
                api_key=self.config.api_key,
                api_base=self.config.api_base,
                model_name=self.config.model_name,
                timeout_seconds=self.config.timeout_seconds,
            )
            self._adapter = create_adapter(self.config.model_mode, model_config)

        # Initialize security components
        self._redactor = ThreatFlowRedactor()
        self._sanitizer = Sanitizer()
        self._prompt_builder = PromptBuilder()

    @property
    def model_mode(self) -> str:
        """Get the current model mode."""
        return self.config.model_mode

    @property
    def is_local(self) -> bool:
        """Check if using local model."""
        return self._adapter.is_local

    def analyze(
        self,
        repo_path: Path,
        output_dir: Path | None = None,
    ) -> ThreatFlowResult:
        """Analyze a repository and generate threat model.

        Args:
            repo_path: Path to the repository to analyze
            output_dir: Directory for output artifacts

        Returns:
            ThreatFlowResult with artifacts and metadata
        """
        start_time = time.time()
        warnings: list[str] = []
        injection_warnings: list[str] = []

        # Validate input
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            return ThreatFlowResult(
                success=False,
                error="Repository path does not exist",
                model_mode=self.config.model_mode,
            )

        if not repo_path.is_dir():
            return ThreatFlowResult(
                success=False,
                error="Repository path is not a directory",
                model_mode=self.config.model_mode,
            )

        # Determine output directory
        out_dir = output_dir or self.config.output_dir
        if out_dir is None:
            out_dir = repo_path / ".threatflow"
        out_dir = Path(out_dir)

        # Warn if using remote API
        if not self._adapter.is_local:
            msg = (
                f"WARNING: Using remote API ({self._adapter.name}). "
                "Code content will be sent to external service."
            )
            logger.warning(msg)
            warnings.append(msg)

        try:
            # Step 1: Chunk repository files
            logger.info("Chunking repository files...")
            chunking_config = ChunkingConfig(
                max_tokens_per_chunk=self.config.max_tokens_per_chunk,
                max_files=self.config.max_files,
            )
            chunk_result = chunk_files(repo_path, chunking_config)
            warnings.extend(chunk_result.warnings)

            if not chunk_result.chunks:
                return ThreatFlowResult(
                    success=False,
                    error="No files to analyze in repository",
                    model_mode=self.config.model_mode,
                    files_skipped=len(chunk_result.skipped_files),
                )

            logger.info(
                "Processed %d files into %d chunks",
                chunk_result.total_files_processed,
                len(chunk_result.chunks),
            )

            # Step 2: Prepare content with security processing
            logger.info("Processing content with security controls...")
            processed_content, proc_warnings = self._process_content(chunk_result)
            injection_warnings.extend(proc_warnings)

            # Step 3: Generate data flow analysis
            logger.info("Generating data flow analysis...")
            dataflow_response = self._generate_dataflow(processed_content)
            if not dataflow_response.success:
                return ThreatFlowResult(
                    success=False,
                    error="Failed to generate data flow analysis",
                    model_mode=self.config.model_mode,
                    duration_ms=int((time.time() - start_time) * 1000),
                )

            # Step 4: Generate threat analysis
            logger.info("Generating threat analysis...")
            threats_response = self._generate_threats(dataflow_response.content, processed_content)
            if not threats_response.success:
                return ThreatFlowResult(
                    success=False,
                    error="Failed to generate threat analysis",
                    model_mode=self.config.model_mode,
                    duration_ms=int((time.time() - start_time) * 1000),
                )

            # Step 5: Build artifacts
            logger.info("Building artifacts...")
            artifacts = self._build_artifacts(
                repo_path=repo_path,
                chunk_result=chunk_result,
                dataflow_output=dataflow_response.content,
                threats_output=threats_response.content,
            )

            # Step 6: Write output files
            logger.info("Writing output files...")
            generator = ArtifactGenerator(
                output_dir=out_dir,
                repo_name=repo_path.name,
            )
            output_files = generator.write_artifacts(artifacts)

            duration_ms = int((time.time() - start_time) * 1000)

            return ThreatFlowResult(
                success=True,
                artifacts=artifacts,
                output_files=output_files,
                model_mode=self.config.model_mode,
                duration_ms=duration_ms,
                warnings=warnings,
                injection_warnings=injection_warnings,
                files_processed=chunk_result.total_files_processed,
                files_skipped=len(chunk_result.skipped_files),
            )

        except Exception:
            # ASVS V16.5.1: Generic error messages
            logger.exception("ThreatFlow analysis failed")
            return ThreatFlowResult(
                success=False,
                error="Analysis failed. Check logs for details.",
                model_mode=self.config.model_mode,
                duration_ms=int((time.time() - start_time) * 1000),
                warnings=warnings,
            )

    def _process_content(self, chunk_result: ChunkingResult) -> tuple[str, list[str]]:
        """Process chunked content with redaction and sanitization.

        Returns:
            Tuple of (processed_content, injection_warnings)
        """
        warnings: list[str] = []
        chunks_data: list[tuple[str, str, int, int]] = []

        for chunk in chunk_result.chunks:
            content = chunk.content

            # Step 1: Redact secrets
            if self.config.redact_secrets:
                secrets_found = self._redactor.detect_secrets(content)
                if secrets_found:
                    logger.info(
                        "Redacting secrets in %s: %s",
                        chunk.file_path,
                        [s[0] for s in secrets_found],
                    )
                content = self._redactor.redact(content)

            # Step 2: Sanitize for prompt injection
            if self.config.sanitize_content:
                result = self._sanitizer.sanitize(content)
                if result.injections_found and self.config.warn_on_injection:
                    for name, risk, desc in result.injections_found:
                        msg = (
                            f"Injection pattern in {chunk.file_path}: "
                            f"{name} ({risk.value}) - {desc}"
                        )
                        warnings.append(msg)
                        logger.warning(msg)
                content = result.sanitized

            chunks_data.append((chunk.file_path, content, chunk.start_line, chunk.end_line))

        # Format all chunks
        formatted = self._prompt_builder.format_code_chunks(chunks_data)
        return formatted, warnings

    def _generate_dataflow(self, content: str) -> ModelResponse:
        """Generate data flow analysis from content."""
        system_prompt = self._prompt_builder.build_system_prompt()
        user_prompt = self._prompt_builder.build_dataflow_prompt(content)

        wrapped_content = self._sanitizer.wrap_content(user_prompt, "dataflow_analysis")

        result: ModelResponse = self._adapter.generate(
            system_prompt=system_prompt,
            user_prompt=wrapped_content,
            config=ModelConfig(timeout_seconds=self.config.timeout_seconds),
        )
        return result

    def _generate_threats(self, dataflow_content: str, code_context: str) -> ModelResponse:
        """Generate threat analysis from dataflow and code."""
        system_prompt = self._prompt_builder.build_system_prompt()
        user_prompt = self._prompt_builder.build_threats_prompt(
            dataflow_content=dataflow_content,
            code_context=code_context,
        )

        wrapped_content = self._sanitizer.wrap_content(user_prompt, "threat_analysis")

        result: ModelResponse = self._adapter.generate(
            system_prompt=system_prompt,
            user_prompt=wrapped_content,
            config=ModelConfig(timeout_seconds=self.config.timeout_seconds),
        )
        return result

    def _build_artifacts(
        self,
        repo_path: Path,
        chunk_result: ChunkingResult,
        dataflow_output: str,
        threats_output: str,
    ) -> ThreatModelArtifacts:
        """Build structured artifacts from LLM output."""
        generator = ArtifactGenerator(output_dir=Path("."), repo_name=repo_path.name)

        # Parse LLM outputs
        threats = generator.parse_llm_threats(threats_output)
        (
            external_entities,
            processes,
            data_stores,
            dataflows,
            trust_boundaries,
        ) = generator.parse_llm_dataflows(dataflow_output)

        # Detect languages from chunks
        languages = list({c.language for c in chunk_result.chunks if c.language})

        return ThreatModelArtifacts(
            threats=threats,
            dataflows=dataflows,
            external_entities=external_entities,
            processes=processes,
            data_stores=data_stores,
            trust_boundaries=trust_boundaries,
            assumptions=[
                "All code was analyzed statically without runtime execution",
                "Third-party dependencies are assumed to be from trusted sources",
                "Environment configuration may differ from analysis assumptions",
            ],
            scope_notes=[
                f"Repository: {repo_path.name}",
                f"Files analyzed: {chunk_result.total_files_processed}",
            ],
            limitations=[
                "This is an automated first-pass analysis",
                "Dynamic behavior and runtime configuration not analyzed",
                "Human review is required for production use",
            ],
            repo_name=repo_path.name,
            analysis_timestamp=datetime.now(UTC).isoformat(),
            model_used=self._adapter.name,
            files_analyzed=chunk_result.total_files_processed,
            languages_detected=languages,
        )


def run_threatflow(
    repo_path: Path | str,
    output_dir: Path | str | None = None,
    config: ThreatFlowConfig | None = None,
) -> ThreatFlowResult:
    """Convenience function to run ThreatFlow analysis.

    Args:
        repo_path: Path to the repository
        output_dir: Optional output directory
        config: Optional configuration

    Returns:
        ThreatFlowResult with analysis output
    """
    tf = ThreatFlow(config=config)
    return tf.analyze(
        repo_path=Path(repo_path),
        output_dir=Path(output_dir) if output_dir else None,
    )
