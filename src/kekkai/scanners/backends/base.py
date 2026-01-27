from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class BackendType(str, Enum):
    DOCKER = "docker"
    NATIVE = "native"


@dataclass(frozen=True)
class ExecutionResult:
    """Result of executing a scanner command."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    backend: BackendType


class ScannerBackend(ABC):
    """Abstract base class for scanner execution backends."""

    @property
    @abstractmethod
    def backend_type(self) -> BackendType:
        """Return the backend type."""
        ...

    @abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Check if this backend is available.

        Returns:
            Tuple of (available, reason)
        """
        ...

    @abstractmethod
    def execute(
        self,
        tool: str,
        args: list[str],
        repo_path: Path,
        output_path: Path,
        timeout_seconds: int = 600,
        env: dict[str, str] | None = None,
        network_required: bool = False,
    ) -> ExecutionResult:
        """Execute a scanner tool.

        Args:
            tool: Tool name or image reference
            args: Command arguments
            repo_path: Path to repository to scan
            output_path: Path for output files
            timeout_seconds: Execution timeout
            env: Environment variables to pass
            network_required: Whether network access is needed

        Returns:
            ExecutionResult with output and status
        """
        ...
