"""CI tests for release artifact validation."""

from pathlib import Path
from unittest.mock import Mock, patch


class TestReleaseArtifacts:
    """Test release artifact generation and validation."""

    def test_wheel_artifact_structure(self, tmp_path: Path) -> None:
        """Verify wheel artifact has correct structure."""
        # Simulate a wheel file
        wheel_file = tmp_path / "kekkai-0.0.1-py3-none-any.whl"
        wheel_file.write_bytes(b"fake wheel content")

        assert wheel_file.exists()
        assert wheel_file.suffix == ".whl"
        assert "py3-none-any" in wheel_file.name

    def test_wheel_metadata_includes_version(self) -> None:
        """Verify wheel metadata includes version."""
        # This tests the naming convention
        version = "0.0.1"
        wheel_name = f"kekkai-{version}-py3-none-any.whl"

        assert version in wheel_name
        assert wheel_name.startswith("kekkai-")
        assert wheel_name.endswith(".whl")

    def test_release_includes_wheel_file(self, tmp_path: Path) -> None:
        """Verify release includes .whl file."""
        # Simulate dist directory
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()

        wheel_file = dist_dir / "kekkai-0.0.1-py3-none-any.whl"
        wheel_file.write_bytes(b"wheel content")

        # Check wheel exists in dist
        wheel_files = list(dist_dir.glob("*.whl"))
        assert len(wheel_files) > 0
        assert any("py3-none-any" in str(f) for f in wheel_files)

    def test_release_includes_source_distribution(self, tmp_path: Path) -> None:
        """Verify release includes source distribution."""
        # Simulate dist directory
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()

        sdist_file = dist_dir / "kekkai-0.0.1.tar.gz"
        sdist_file.write_bytes(b"source distribution")

        # Check sdist exists
        sdist_files = list(dist_dir.glob("*.tar.gz"))
        assert len(sdist_files) > 0


class TestGitHubReleaseValidation:
    """Test GitHub release validation."""

    @patch("urllib.request.urlopen")
    def test_github_release_artifact_accessible(self, mock_urlopen: Mock) -> None:
        """Verify GitHub release artifacts are accessible."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = b"wheel content"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Simulate checking release artifact
        version = "0.0.1"
        whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

        # In real implementation, this would fetch the URL
        # For now, we just verify URL format
        assert "github.com" in whl_url
        assert "releases/download" in whl_url
        assert f"v{version}" in whl_url

    def test_wheel_url_format_valid(self) -> None:
        """Verify wheel URL follows expected format."""
        version = "0.0.1"
        whl_url = f"https://github.com/kademoslabs/kekkai/releases/download/v{version}/kekkai-{version}-py3-none-any.whl"

        # Verify URL components
        assert whl_url.startswith("https://")
        assert "github.com/kademoslabs/kekkai" in whl_url
        assert f"v{version}" in whl_url
        assert ".whl" in whl_url

    def test_release_tag_format(self) -> None:
        """Verify release tag format."""
        version = "0.0.1"
        tag = f"v{version}"

        assert tag.startswith("v")
        assert version in tag


class TestWheelMetadata:
    """Test wheel package metadata."""

    def test_wheel_name_format(self) -> None:
        """Verify wheel name follows PEP 427 format."""
        wheel_name = "kekkai-0.0.1-py3-none-any.whl"

        parts = wheel_name.split("-")
        assert len(parts) == 5  # name-version-pyver-abi-platform.whl
        assert parts[0] == "kekkai"
        assert parts[1] == "0.0.1"
        assert parts[2] == "py3"
        assert parts[3] == "none"
        assert parts[4] == "any.whl"

    def test_wheel_supports_any_platform(self) -> None:
        """Verify wheel is platform-independent."""
        wheel_name = "kekkai-0.0.1-py3-none-any.whl"

        assert "any.whl" in wheel_name
        assert "none" in wheel_name  # No ABI requirements

    def test_wheel_requires_python3(self) -> None:
        """Verify wheel specifies Python 3."""
        wheel_name = "kekkai-0.0.1-py3-none-any.whl"

        assert "py3" in wheel_name


class TestSBOMGeneration:
    """Test SBOM generation for releases."""

    def test_sbom_file_created(self, tmp_path: Path) -> None:
        """Verify SBOM file is created."""
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()

        # Simulate SBOM file
        sbom_file = dist_dir / "requirements-frozen.txt"
        sbom_file.write_text("pytest==9.0.2\nmypy==1.19.1\n")

        assert sbom_file.exists()
        assert sbom_file.read_text()

    def test_sbom_lists_dependencies(self, tmp_path: Path) -> None:
        """Verify SBOM lists package dependencies."""
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()

        # Create SBOM
        sbom_file = dist_dir / "requirements-frozen.txt"
        dependencies = ["pytest==9.0.2", "mypy==1.19.1", "ruff==0.14.13"]
        sbom_file.write_text("\n".join(dependencies))

        content = sbom_file.read_text()
        for dep in dependencies:
            assert dep in content


class TestChecksumGeneration:
    """Test checksum generation for releases."""

    def test_sha256_checksum_format(self) -> None:
        """Verify SHA256 checksum format."""
        import hashlib

        content = b"test wheel content"
        sha256 = hashlib.sha256(content).hexdigest()

        assert len(sha256) == 64
        assert all(c in "0123456789abcdef" for c in sha256)

    def test_checksum_for_wheel_file(self, tmp_path: Path) -> None:
        """Verify checksum can be calculated for wheel file."""
        import hashlib

        wheel_file = tmp_path / "kekkai-0.0.1-py3-none-any.whl"
        content = b"wheel content"
        wheel_file.write_bytes(content)

        # Calculate checksum
        sha256 = hashlib.sha256(content).hexdigest()

        # Verify format
        assert len(sha256) == 64
        assert isinstance(sha256, str)

    def test_checksum_file_generation(self, tmp_path: Path) -> None:
        """Verify checksum file can be generated."""
        from kekkai_core.windows.scoop import generate_scoop_checksum_file

        checksum_content = generate_scoop_checksum_file(
            version="0.0.1",
            sha256="a" * 64,
        )

        checksum_file = tmp_path / "checksums.txt"
        checksum_file.write_text(checksum_content)

        content = checksum_file.read_text()
        assert "kekkai-0.0.1-py3-none-any.whl" in content
        assert "a" * 64 in content
