"""SLSA provenance verification using slsa-verifier."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


class AttestationError(Exception):
    """Raised when attestation verification fails."""


@dataclass
class ProvenanceResult:
    """Result of SLSA provenance verification."""

    verified: bool
    builder_id: str | None = None
    source_repo: str | None = None
    commit_sha: str | None = None
    error: str | None = None


def verify_provenance(
    artifact_path: Path,
    provenance_path: Path,
    expected_repo: str = "kademoslabs/kekkai",
) -> ProvenanceResult:
    """
    Verify SLSA provenance for an artifact.

    Args:
        artifact_path: Path to the artifact to verify
        provenance_path: Path to the provenance attestation file
        expected_repo: Expected GitHub repository (owner/repo)

    Returns:
        ProvenanceResult with verification status and metadata

    Raises:
        AttestationError: If verification encounters an unrecoverable error
    """
    if not artifact_path.exists():
        return ProvenanceResult(
            verified=False,
            error=f"Artifact not found: {artifact_path}",
        )

    if not provenance_path.exists():
        return ProvenanceResult(
            verified=False,
            error=f"Provenance file not found: {provenance_path}",
        )

    try:
        result = subprocess.run(
            [
                "slsa-verifier",  # nosec B607 - trusted binary
                "verify-artifact",
                str(artifact_path),
                "--provenance-path",
                str(provenance_path),
                "--source-uri",
                f"github.com/{expected_repo}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return ProvenanceResult(
                verified=False,
                error=result.stderr.strip() or "Verification failed",
            )

        # Parse provenance for metadata
        provenance_data = _parse_provenance(provenance_path)

        return ProvenanceResult(
            verified=True,
            builder_id=provenance_data.get("builder_id"),
            source_repo=provenance_data.get("source_repo"),
            commit_sha=provenance_data.get("commit_sha"),
        )

    except subprocess.TimeoutExpired:
        return ProvenanceResult(
            verified=False,
            error="Verification timed out after 60s",
        )
    except FileNotFoundError:
        return ProvenanceResult(
            verified=False,
            error="slsa-verifier not found. Install: https://github.com/slsa-framework/slsa-verifier",
        )
    except Exception as e:
        raise AttestationError(f"Unexpected error during verification: {e}") from e


def _parse_provenance(provenance_path: Path) -> dict[str, str | None]:
    """Extract metadata from provenance file."""
    try:
        data = json.loads(provenance_path.read_text())

        # Handle SLSA provenance format
        predicate = data.get("predicate", {})
        invocation = predicate.get("invocation", {})
        config_source = invocation.get("configSource", {})

        builder = predicate.get("builder", {})

        return {
            "builder_id": builder.get("id"),
            "source_repo": config_source.get("uri"),
            "commit_sha": config_source.get("digest", {}).get("sha1"),
        }
    except (json.JSONDecodeError, KeyError):
        return {}
