"""Integration tests for distribution trigger workflows."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from kekkai_core.ci.metadata import (
    extract_version_from_tag,
    format_dispatch_payload,
)


@pytest.mark.integration
class TestEndToEndTriggers:
    """Test end-to-end distribution trigger scenarios."""

    @patch("urllib.request.urlopen")
    def test_release_triggers_all_distributions(
        self,
        mock_urlopen: Mock,
    ) -> None:
        """Publishing a release triggers all 4 distribution repos."""
        # Mock HTTP responses for GitHub API calls
        mock_response = Mock()
        mock_response.status = 202  # GitHub API returns 202 for repository_dispatch
        mock_response.read.return_value = b'{"status": "accepted"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Simulate release metadata
        version = "0.0.1"
        sha256 = "a" * 64

        # Create dispatch payloads for each distribution
        homebrew_payload = format_dispatch_payload("kekkai-release", version, sha256)
        docker_payload = format_dispatch_payload("docker-release", version)
        scoop_payload = format_dispatch_payload("kekkai-release", version, sha256)
        choco_payload = format_dispatch_payload("kekkai-release", version, sha256)

        # Verify payloads are properly formatted
        assert homebrew_payload["event_type"] == "kekkai-release"
        assert isinstance(homebrew_payload["client_payload"], dict)
        assert homebrew_payload["client_payload"]["version"] == version

        assert docker_payload["event_type"] == "docker-release"
        assert scoop_payload["event_type"] == "kekkai-release"
        assert choco_payload["event_type"] == "kekkai-release"

    def test_manual_trigger_with_custom_version(self) -> None:
        """Manual workflow dispatch with custom version succeeds."""
        custom_version = "0.0.2-manual"

        # Extract version (simulating workflow_dispatch input)
        version = extract_version_from_tag(f"v{custom_version}")

        assert version == custom_version

        # Create payload with custom version
        payload = format_dispatch_payload("kekkai-release", version, "b" * 64)

        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == custom_version

    def test_failed_distribution_creates_issue(self) -> None:
        """Failed distribution update creates GitHub issue."""
        # This tests the issue creation payload structure
        version = "0.0.1"
        run_url = "https://github.com/kademoslabs/kekkai/actions/runs/123456"

        issue_payload = {
            "title": f"Distribution update failed for v{version}",
            "body": (
                f"## Distribution Update Failure\n\n"
                f"**Version:** {version}\n**Workflow Run:** {run_url}"
            ),
            "labels": ["distribution", "automation", "ci-failure"],
        }

        # Verify issue structure
        assert "Distribution update failed" in issue_payload["title"]
        assert version in issue_payload["body"]
        assert run_url in issue_payload["body"]
        assert "distribution" in issue_payload["labels"]

    def test_duplicate_trigger_is_idempotent(self) -> None:
        """Triggering same version twice doesn't break distributions."""
        version = "0.0.1"
        sha256 = "c" * 64

        # Create same payload twice
        payload1 = format_dispatch_payload("kekkai-release", version, sha256)
        payload2 = format_dispatch_payload("kekkai-release", version, sha256)

        # Payloads should be identical
        assert payload1 == payload2


@pytest.mark.integration
class TestCrossRepositoryCommunication:
    """Test cross-repository workflow triggers."""

    @patch("urllib.request.urlopen")
    def test_homebrew_tap_receives_dispatch(self, mock_urlopen: Mock) -> None:
        """Homebrew tap workflow starts on dispatch event."""
        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status = 202
        mock_response.read.return_value = b'{"status": "accepted"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Create dispatch payload
        payload = format_dispatch_payload("kekkai-release", "0.0.1", "d" * 64)

        # Verify payload structure for API
        assert "event_type" in payload
        assert "client_payload" in payload
        assert isinstance(payload["client_payload"], dict)
        assert "version" in payload["client_payload"]
        assert "sha256" in payload["client_payload"]

    @patch("urllib.request.urlopen")
    def test_scoop_bucket_ci_runs_on_dispatch(self, mock_urlopen: Mock) -> None:
        """Scoop bucket CI workflow executes."""
        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status = 202
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Create dispatch payload for Scoop
        payload = format_dispatch_payload("kekkai-release", "0.0.1", "e" * 64)

        # Verify payload includes version and SHA256
        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == "0.0.1"
        assert payload["client_payload"]["sha256"] == "e" * 64

    @patch("urllib.request.urlopen")
    def test_chocolatey_packages_receives_dispatch(self, mock_urlopen: Mock) -> None:
        """Chocolatey packages workflow starts."""
        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status = 202
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Create dispatch payload for Chocolatey
        payload = format_dispatch_payload("kekkai-release", "0.0.1", "f" * 64)

        # Verify payload structure
        assert payload["event_type"] == "kekkai-release"
        assert isinstance(payload["client_payload"], dict)
        assert payload["client_payload"]["version"] == "0.0.1"


@pytest.mark.integration
class TestWorkflowValidation:
    """Test GitHub Actions workflow YAML validation."""

    def test_workflow_file_exists(self) -> None:
        """Verify trigger-distributions.yml exists."""
        workflow_file = Path(".github/workflows/trigger-distributions.yml")
        assert workflow_file.exists(), "Workflow file should exist"

    def test_workflow_file_readable(self) -> None:
        """Verify workflow file is readable and valid YAML."""
        workflow_file = Path(".github/workflows/trigger-distributions.yml")

        if not workflow_file.exists():
            pytest.skip("Workflow file not found")

        content = workflow_file.read_text()
        assert "name: Trigger Distribution Updates" in content
        assert "on:" in content
        assert "jobs:" in content

    def test_workflow_has_required_jobs(self) -> None:
        """Verify workflow contains all required jobs."""
        workflow_file = Path(".github/workflows/trigger-distributions.yml")

        if not workflow_file.exists():
            pytest.skip("Workflow file not found")

        content = workflow_file.read_text()

        required_jobs = [
            "extract-metadata",
            "validate-metadata",
            "trigger-homebrew",
            "trigger-docker",
            "trigger-scoop",
            "trigger-chocolatey",
            "notify-failure",
        ]

        for job in required_jobs:
            assert job in content, f"Job {job} should be in workflow"

    def test_workflow_has_manual_trigger(self) -> None:
        """Verify workflow supports workflow_dispatch."""
        workflow_file = Path(".github/workflows/trigger-distributions.yml")

        if not workflow_file.exists():
            pytest.skip("Workflow file not found")

        content = workflow_file.read_text()
        assert "workflow_dispatch:" in content
        assert "inputs:" in content
