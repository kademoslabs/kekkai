"""Unit tests for SLSA provenance verification."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from kekkai_core.slsa import ProvenanceResult, verify_provenance


class TestProvenanceResult:
    """Tests for ProvenanceResult dataclass."""

    def test_verified_result(self) -> None:
        """Verified result contains metadata."""
        result = ProvenanceResult(
            verified=True,
            builder_id="https://github.com/slsa-framework/slsa-github-generator",
            source_repo="github.com/kademoslabs/kekkai",
            commit_sha="abc123def456",
        )
        assert result.verified is True
        assert result.builder_id is not None
        assert result.error is None

    def test_failed_result(self) -> None:
        """Failed result contains error."""
        result = ProvenanceResult(
            verified=False,
            error="Verification failed: invalid signature",
        )
        assert result.verified is False
        assert result.error is not None
        assert result.builder_id is None


class TestVerifyProvenance:
    """Tests for verify_provenance function."""

    @patch("subprocess.run")
    def test_verify_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Successful verification returns verified result."""
        artifact = tmp_path / "kekkai-1.0.0.whl"
        artifact.write_bytes(b"fake wheel content")

        provenance = tmp_path / "kekkai-1.0.0.whl.intoto.jsonl"
        provenance.write_text(
            json.dumps(
                {
                    "predicate": {
                        "builder": {
                            "id": "https://github.com/slsa-framework/slsa-github-generator"
                        },
                        "invocation": {
                            "configSource": {
                                "uri": "github.com/kademoslabs/kekkai",
                                "digest": {"sha1": "abc123"},
                            }
                        },
                    }
                }
            )
        )

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_provenance(artifact, provenance)

        assert result.verified is True
        assert result.builder_id is not None
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_verify_failure(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Verification failure returns error."""
        artifact = tmp_path / "kekkai-1.0.0.whl"
        artifact.write_bytes(b"fake wheel content")

        provenance = tmp_path / "kekkai-1.0.0.whl.intoto.jsonl"
        provenance.write_text("{}")

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="FAILED: signature verification failed",
        )

        result = verify_provenance(artifact, provenance)

        assert result.verified is False
        assert "signature verification failed" in (result.error or "")

    def test_artifact_not_found(self, tmp_path: Path) -> None:
        """Missing artifact returns error."""
        artifact = tmp_path / "nonexistent.whl"
        provenance = tmp_path / "provenance.jsonl"
        provenance.write_text("{}")

        result = verify_provenance(artifact, provenance)

        assert result.verified is False
        assert "not found" in (result.error or "").lower()

    def test_provenance_not_found(self, tmp_path: Path) -> None:
        """Missing provenance returns error."""
        artifact = tmp_path / "kekkai-1.0.0.whl"
        artifact.write_bytes(b"content")
        provenance = tmp_path / "nonexistent.jsonl"

        result = verify_provenance(artifact, provenance)

        assert result.verified is False
        assert "not found" in (result.error or "").lower()

    @patch("subprocess.run")
    def test_timeout_handled(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Timeout during verification returns error."""
        artifact = tmp_path / "kekkai-1.0.0.whl"
        artifact.write_bytes(b"content")
        provenance = tmp_path / "provenance.jsonl"
        provenance.write_text("{}")

        mock_run.side_effect = subprocess.TimeoutExpired("slsa-verifier", 60)

        result = verify_provenance(artifact, provenance)

        assert result.verified is False
        assert "timed out" in (result.error or "").lower()

    @patch("subprocess.run")
    def test_verifier_not_installed(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Missing slsa-verifier returns helpful error."""
        artifact = tmp_path / "kekkai-1.0.0.whl"
        artifact.write_bytes(b"content")
        provenance = tmp_path / "provenance.jsonl"
        provenance.write_text("{}")

        mock_run.side_effect = FileNotFoundError("slsa-verifier")

        result = verify_provenance(artifact, provenance)

        assert result.verified is False
        assert "slsa-verifier" in (result.error or "").lower()

    @patch("subprocess.run")
    def test_custom_repo(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Custom repository is passed to verifier."""
        artifact = tmp_path / "pkg.whl"
        artifact.write_bytes(b"content")
        provenance = tmp_path / "prov.jsonl"
        provenance.write_text("{}")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        verify_provenance(artifact, provenance, expected_repo="other/repo")

        args = mock_run.call_args[0][0]
        assert "github.com/other/repo" in args


class TestProvenanceParsing:
    """Tests for provenance metadata parsing."""

    @patch("subprocess.run")
    def test_parse_slsa_format(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Correctly parses SLSA provenance format."""
        artifact = tmp_path / "kekkai.whl"
        artifact.write_bytes(b"content")

        provenance_data = {
            "predicate": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
                },
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/kademoslabs/kekkai@refs/tags/v1.0.0",
                        "digest": {"sha1": "deadbeef123456"},
                    }
                },
            }
        }
        provenance = tmp_path / "kekkai.whl.intoto.jsonl"
        provenance.write_text(json.dumps(provenance_data))

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_provenance(artifact, provenance)

        assert result.verified is True
        assert "slsa-github-generator" in (result.builder_id or "")
        assert result.commit_sha == "deadbeef123456"

    @patch("subprocess.run")
    def test_parse_invalid_json(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Invalid JSON in provenance doesn't crash."""
        artifact = tmp_path / "kekkai.whl"
        artifact.write_bytes(b"content")
        provenance = tmp_path / "kekkai.whl.intoto.jsonl"
        provenance.write_text("not valid json {{{")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = verify_provenance(artifact, provenance)

        # Verification can succeed even if parsing metadata fails
        assert result.verified is True
        assert result.builder_id is None
