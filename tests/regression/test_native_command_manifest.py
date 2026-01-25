"""Regression tests for native command manifest generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kekkai.manifest import ScannerManifestEntry, build_manifest, write_manifest
from kekkai.runner import StepResult


@pytest.mark.regression
class TestScannerManifestEntry:
    """Test ScannerManifestEntry creation and serialization."""

    def test_create_scanner_manifest_entry(self) -> None:
        entry = ScannerManifestEntry(
            name="trivy",
            backend="native",
            success=True,
            finding_count=5,
            duration_ms=1234,
            error=None,
        )
        assert entry.name == "trivy"
        assert entry.backend == "native"
        assert entry.success is True
        assert entry.finding_count == 5
        assert entry.duration_ms == 1234
        assert entry.error is None

    def test_create_scanner_manifest_entry_with_error(self) -> None:
        entry = ScannerManifestEntry(
            name="semgrep",
            backend="docker",
            success=False,
            finding_count=0,
            duration_ms=500,
            error="Tool not found",
        )
        assert entry.success is False
        assert entry.error == "Tool not found"


@pytest.mark.regression
class TestManifestWithScanners:
    """Test manifest generation with scanner entries."""

    def test_build_manifest_with_scanners(self, tmp_path: Path) -> None:
        steps = [
            StepResult(
                name="test-step",
                args=["echo", "hello"],
                exit_code=0,
                duration_ms=100,
                stdout="hello",
                stderr="",
                timed_out=False,
            )
        ]

        scanners = [
            ScannerManifestEntry(
                name="trivy",
                backend="native",
                success=True,
                finding_count=3,
                duration_ms=5000,
            ),
            ScannerManifestEntry(
                name="semgrep",
                backend="docker",
                success=True,
                finding_count=1,
                duration_ms=3000,
            ),
        ]

        manifest = build_manifest(
            run_id="test-run-123",
            repo_path=tmp_path,
            run_dir=tmp_path / "runs" / "test-run-123",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:01:00Z",
            steps=steps,
            scanners=scanners,
        )

        assert manifest.schema_version == 2
        assert manifest.scanners is not None
        assert len(manifest.scanners) == 2
        assert manifest.scanners[0]["name"] == "trivy"
        assert manifest.scanners[0]["backend"] == "native"
        assert manifest.scanners[1]["name"] == "semgrep"
        assert manifest.scanners[1]["backend"] == "docker"

    def test_build_manifest_without_scanners(self, tmp_path: Path) -> None:
        steps = [
            StepResult(
                name="test-step",
                args=["echo", "hello"],
                exit_code=0,
                duration_ms=100,
                stdout="hello",
                stderr="",
                timed_out=False,
            )
        ]

        manifest = build_manifest(
            run_id="test-run-123",
            repo_path=tmp_path,
            run_dir=tmp_path / "runs" / "test-run-123",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:01:00Z",
            steps=steps,
        )

        assert manifest.schema_version == 2
        assert manifest.scanners is None

    def test_write_manifest_with_scanners(self, tmp_path: Path) -> None:
        steps = [
            StepResult(
                name="test-step",
                args=["echo", "hello"],
                exit_code=0,
                duration_ms=100,
                stdout="hello",
                stderr="",
                timed_out=False,
            )
        ]

        scanners = [
            ScannerManifestEntry(
                name="gitleaks",
                backend="native",
                success=True,
                finding_count=0,
                duration_ms=2000,
            ),
        ]

        manifest = build_manifest(
            run_id="test-run-123",
            repo_path=tmp_path,
            run_dir=tmp_path / "runs" / "test-run-123",
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:01:00Z",
            steps=steps,
            scanners=scanners,
        )

        manifest_path = tmp_path / "manifest.json"
        write_manifest(manifest_path, manifest)

        assert manifest_path.exists()
        data = json.loads(manifest_path.read_text())
        assert data["schema_version"] == 2
        assert "scanners" in data
        assert len(data["scanners"]) == 1
        assert data["scanners"][0]["name"] == "gitleaks"
        assert data["scanners"][0]["backend"] == "native"


@pytest.mark.regression
class TestManifestGolden:
    """Golden tests for manifest structure."""

    def test_manifest_schema_version_2(self, tmp_path: Path) -> None:
        """Ensure schema version is correctly set to 2."""
        steps: list[StepResult] = []
        manifest = build_manifest(
            run_id="test",
            repo_path=tmp_path,
            run_dir=tmp_path,
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:00:01Z",
            steps=steps,
        )
        assert manifest.schema_version == 2

    def test_manifest_scanner_entry_structure(self) -> None:
        """Verify scanner entry has all required fields."""
        entry = ScannerManifestEntry(
            name="trivy",
            backend="native",
            success=True,
            finding_count=10,
            duration_ms=5000,
            error=None,
        )

        from dataclasses import asdict

        data = asdict(entry)

        required_fields = {"name", "backend", "success", "finding_count", "duration_ms", "error"}
        assert set(data.keys()) == required_fields

    def test_manifest_backward_compatible_without_scanners(self, tmp_path: Path) -> None:
        """Ensure manifests without scanners are still valid."""
        steps = [
            StepResult(
                name="step",
                args=["true"],
                exit_code=0,
                duration_ms=10,
                stdout="",
                stderr="",
                timed_out=False,
            )
        ]

        manifest = build_manifest(
            run_id="test",
            repo_path=tmp_path,
            run_dir=tmp_path,
            started_at="2024-01-01T00:00:00Z",
            finished_at="2024-01-01T00:00:01Z",
            steps=steps,
        )

        manifest_path = tmp_path / "manifest.json"
        write_manifest(manifest_path, manifest)

        data = json.loads(manifest_path.read_text())
        assert "schema_version" in data
        assert "steps" in data
        assert data["scanners"] is None
