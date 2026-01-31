"""Regression tests for distribution trigger backwards compatibility."""

from pathlib import Path

import pytest

from kekkai_core.ci.metadata import extract_version_from_tag


@pytest.mark.regression
class TestBackwardsCompatibility:
    """Test backwards compatibility with existing systems."""

    def test_old_tag_format_still_works(self) -> None:
        """Ensure tags from previous releases still trigger correctly."""
        # Test v0.0.0 format (existing release)
        version = extract_version_from_tag("v0.0.0")
        assert version == "0.0.0"

        # Test other historical formats
        historical_tags = [
            ("v0.0.1", "0.0.1"),
            ("v1.0.0", "1.0.0"),
            ("v1.0.0-rc1", "1.0.0-rc1"),
        ]

        for tag, expected in historical_tags:
            version = extract_version_from_tag(tag)
            assert version == expected

    def test_existing_docker_workflow_unchanged(self) -> None:
        """Verify docker-publish.yml still works independently."""
        docker_workflow = Path(".github/workflows/docker-publish.yml")

        if not docker_workflow.exists():
            pytest.skip("Docker workflow not found")

        content = docker_workflow.read_text()

        # Verify key elements unchanged
        assert "name: Publish Docker Image" in content
        assert "docker/build-push-action@v5" in content or "docker/build-push-action@v6" in content
        assert "DOCKERHUB_USERNAME" in content
        assert "DOCKERHUB_TOKEN" in content

        # Verify it can still be triggered independently
        assert "workflow_dispatch:" in content or "push:" in content

    def test_manual_distribution_updates_still_possible(self) -> None:
        """Verify distributions can be updated manually without automation."""
        # Test that version extraction works for manual workflows
        manual_versions = [
            "0.0.1",
            "0.0.2-hotfix",
            "1.0.0-beta.1",
        ]

        for version in manual_versions:
            # Manual updates should accept version with or without 'v' prefix
            extracted_v = extract_version_from_tag(f"v{version}")
            extracted_no_v = extract_version_from_tag(version)

            assert extracted_v == version
            assert extracted_no_v == version

    def test_circleci_workflows_branch_only(self) -> None:
        """Verify CircleCI runs on branches only, not tags (v1.1.0+ architecture).

        As of v1.1.0, CircleCI no longer runs release workflows on tag pushes
        to prevent duplication. GitHub Actions handles all releases:
        - PyPI publishing (release-slsa.yml)
        - Docker publishing (docker-publish.yml)
        - Distribution triggers (trigger-distributions.yml)

        CircleCI workflows:
        - develop branch: test_quick (fast checks)
        - main branch: test_full + build_verification
        """
        circleci_config = Path(".circleci/config.yml")

        if not circleci_config.exists():
            pytest.skip("CircleCI config not found")

        content = circleci_config.read_text()

        # Verify branch-based workflows exist
        assert "develop:" in content, "develop workflow missing"
        assert "main:" in content, "main workflow missing"
        assert "test_full:" in content, "test_full job missing"

        # Verify build verification exists (renamed from build_release)
        assert "build_verification:" in content or "build_release:" in content, "build job missing"

        # Verify release workflow is removed (GitHub Actions handles releases)
        # The config should have a comment explaining the removal
        assert (
            "# Release workflow: REMOVED" in content or "release:" not in content
        ), "Release workflow should be removed (GitHub Actions handles tag-based releases)"


@pytest.mark.regression
class TestVersionCompatibility:
    """Test version handling compatibility."""

    def test_semver_without_v_prefix(self) -> None:
        """Verify versions without 'v' prefix are handled correctly."""
        versions = ["0.0.1", "1.2.3", "2.0.0-rc1"]

        for version in versions:
            extracted = extract_version_from_tag(version)
            assert extracted == version

    def test_semver_with_v_prefix(self) -> None:
        """Verify versions with 'v' prefix are handled correctly."""
        versions = ["v0.0.1", "v1.2.3", "v2.0.0-rc1"]
        expected = ["0.0.1", "1.2.3", "2.0.0-rc1"]

        for tag, expected_version in zip(versions, expected, strict=True):
            extracted = extract_version_from_tag(tag)
            assert extracted == expected_version

    def test_prerelease_versions(self) -> None:
        """Verify pre-release versions work correctly."""
        prerelease_tags = [
            ("v1.0.0-alpha", "1.0.0-alpha"),
            ("v1.0.0-alpha.1", "1.0.0-alpha.1"),
            ("v1.0.0-beta", "1.0.0-beta"),
            ("v1.0.0-rc1", "1.0.0-rc1"),
        ]

        for tag, expected in prerelease_tags:
            version = extract_version_from_tag(tag)
            assert version == expected


@pytest.mark.regression
class TestWorkflowCompatibility:
    """Test workflow compatibility with existing systems."""

    def test_github_actions_coexistence(self) -> None:
        """Verify new workflow doesn't conflict with existing workflows."""
        workflows_dir = Path(".github/workflows")

        if not workflows_dir.exists():
            pytest.skip("Workflows directory not found")

        workflows = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))

        # Should have at least docker-publish and trigger-distributions
        workflow_names = [w.name for w in workflows]
        assert len(workflow_names) >= 2

        # Verify no duplicate workflow names
        assert len(workflow_names) == len(set(workflow_names))

    def test_secrets_requirements_documented(self) -> None:
        """Verify required secrets are documented."""
        trigger_workflow = Path(".github/workflows/trigger-distributions.yml")

        if not trigger_workflow.exists():
            pytest.skip("Trigger workflow not found")

        content = trigger_workflow.read_text()

        # Check that required secrets are referenced
        required_secrets = [
            "TAP_REPO_TOKEN",
            "SCOOP_REPO_TOKEN",
            "CHOCO_REPO_TOKEN",
            "GITHUB_TOKEN",  # Built-in
        ]

        for secret in required_secrets:
            assert secret in content, f"Secret {secret} should be referenced in workflow"

    def test_dry_run_mode_available(self) -> None:
        """Verify dry run mode is available for testing."""
        trigger_workflow = Path(".github/workflows/trigger-distributions.yml")

        if not trigger_workflow.exists():
            pytest.skip("Trigger workflow not found")

        content = trigger_workflow.read_text()

        # Verify dry_run input exists
        assert "dry_run:" in content
        assert "type: boolean" in content
