"""Integration tests for SLSA provenance verification."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kekkai_core.slsa import verify_provenance


@pytest.mark.integration
class TestSLSAVerificationWorkflow:
    """End-to-end SLSA verification tests."""

    def test_full_verification_flow(self, tmp_path: Path) -> None:
        """Test complete verification workflow with mock provenance."""
        # Create mock artifact
        artifact = tmp_path / "kekkai-1.0.0-py3-none-any.whl"
        artifact.write_bytes(b"PK\x03\x04fake wheel content")

        # Create mock SLSA provenance
        provenance_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": "kekkai-1.0.0-py3-none-any.whl",
                    "digest": {"sha256": "abc123"},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
                },
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/kademoslabs/kekkai@refs/tags/v1.0.0",
                        "digest": {"sha1": "abc123def456789"},
                        "entryPoint": ".github/workflows/release-slsa.yml",
                    }
                },
                "metadata": {
                    "buildInvocationId": "12345-67890",
                    "buildStartedOn": "2026-01-27T10:00:00Z",
                    "buildFinishedOn": "2026-01-27T10:05:00Z",
                },
            },
        }

        provenance = tmp_path / "kekkai-1.0.0-py3-none-any.whl.intoto.jsonl"
        provenance.write_text(json.dumps(provenance_data))

        # Mock slsa-verifier success
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = verify_provenance(artifact, provenance)

            assert result.verified is True
            assert "slsa-github-generator" in (result.builder_id or "")
            assert result.commit_sha == "abc123def456789"

    def test_verification_with_tampered_artifact(self, tmp_path: Path) -> None:
        """Verification fails for tampered artifact."""
        artifact = tmp_path / "tampered.whl"
        artifact.write_bytes(b"tampered content")

        provenance = tmp_path / "tampered.whl.intoto.jsonl"
        provenance.write_text(json.dumps({"predicate": {}}))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="FAILED: expected hash abc123, got def456",
            )

            result = verify_provenance(artifact, provenance)

            assert result.verified is False
            assert "hash" in (result.error or "").lower()

    def test_verification_wrong_repo(self, tmp_path: Path) -> None:
        """Verification fails for wrong source repository."""
        artifact = tmp_path / "pkg.whl"
        artifact.write_bytes(b"content")

        provenance = tmp_path / "pkg.whl.intoto.jsonl"
        provenance.write_text(
            json.dumps(
                {
                    "predicate": {
                        "invocation": {"configSource": {"uri": "github.com/attacker/malicious"}}
                    }
                }
            )
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="FAILED: source URI mismatch",
            )

            result = verify_provenance(artifact, provenance, expected_repo="kademoslabs/kekkai")

            assert result.verified is False


@pytest.mark.integration
class TestSLSASecurityScenarios:
    """Security-focused SLSA verification tests."""

    def test_reject_forged_provenance(self, tmp_path: Path) -> None:
        """Forged provenance is rejected."""
        artifact = tmp_path / "pkg.whl"
        artifact.write_bytes(b"legitimate content")

        # Attacker-crafted provenance
        forged_provenance = tmp_path / "pkg.whl.intoto.jsonl"
        forged_provenance.write_text(
            json.dumps(
                {
                    "predicate": {
                        "builder": {"id": "https://attacker.com/fake-builder"},
                    }
                }
            )
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="FAILED: untrusted builder",
            )

            result = verify_provenance(artifact, forged_provenance)

            assert result.verified is False

    def test_reject_replay_attack(self, tmp_path: Path) -> None:
        """Old provenance cannot be replayed for new artifact."""
        new_artifact = tmp_path / "kekkai-2.0.0.whl"
        new_artifact.write_bytes(b"new version content")

        # Provenance from v1.0.0
        old_provenance = tmp_path / "kekkai-2.0.0.whl.intoto.jsonl"
        old_provenance.write_text(
            json.dumps(
                {
                    "subject": [{"name": "kekkai-1.0.0.whl", "digest": {"sha256": "old"}}],
                    "predicate": {},
                }
            )
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="FAILED: subject mismatch",
            )

            result = verify_provenance(new_artifact, old_provenance)

            assert result.verified is False
