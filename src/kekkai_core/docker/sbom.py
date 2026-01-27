"""SBOM (Software Bill of Materials) generation for Docker images."""

import json
import subprocess
from pathlib import Path
from typing import Any, Literal

SBOMFormat = Literal["spdx", "spdx-json", "cyclonedx", "cyclonedx-json"]


class SBOMError(Exception):
    """Raised when SBOM generation fails."""


def generate_sbom(
    image: str,
    output_format: SBOMFormat = "spdx-json",
    output_file: Path | None = None,
) -> dict[str, Any]:
    """
    Generate SBOM for Docker image using Trivy.

    Args:
        image: Docker image to analyze (e.g., 'kademoslabs/kekkai:latest')
        output_format: SBOM format (spdx-json, cyclonedx-json, etc.)
        output_file: Path to write SBOM (optional)

    Returns:
        SBOM as dictionary

    Raises:
        SBOMError: If SBOM generation fails
    """
    # Map our format to Trivy's format argument
    format_map = {
        "spdx": "spdx",
        "spdx-json": "spdx-json",
        "cyclonedx": "cyclonedx",
        "cyclonedx-json": "cyclonedx-json",
    }

    trivy_format = format_map.get(output_format, "spdx-json")

    cmd = ["trivy", "image", "--format", trivy_format]

    if output_file:
        cmd.extend(["--output", str(output_file)])

    cmd.append(image)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )

        # Parse JSON output
        if output_format.endswith("-json"):
            return json.loads(result.stdout) if result.stdout else {}
        else:
            # For non-JSON formats, return raw output
            return {"sbom": result.stdout}

    except subprocess.CalledProcessError as e:
        raise SBOMError(f"SBOM generation failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise SBOMError("SBOM generation timed out after 300s") from e
    except json.JSONDecodeError as e:
        raise SBOMError(f"Failed to parse SBOM output: {e}") from e


def validate_sbom_format(sbom_data: dict[str, Any], expected_format: SBOMFormat) -> bool:
    """
    Validate SBOM data structure matches expected format.

    Args:
        sbom_data: SBOM dictionary
        expected_format: Expected SBOM format

    Returns:
        True if SBOM structure is valid
    """
    if expected_format == "spdx-json":
        # SPDX must have these fields
        required_fields = ["spdxVersion", "dataLicense", "name", "documentNamespace"]
        return all(field in sbom_data for field in required_fields)

    elif expected_format == "cyclonedx-json":
        # CycloneDX must have these fields
        required_fields = ["bomFormat", "specVersion", "version"]
        return all(field in sbom_data for field in required_fields)

    return False


def extract_dependencies(sbom_data: dict[str, Any], sbom_format: SBOMFormat) -> list[str]:
    """
    Extract package dependencies from SBOM.

    Args:
        sbom_data: SBOM dictionary
        sbom_format: SBOM format

    Returns:
        List of package names
    """
    dependencies: list[str] = []

    if sbom_format == "spdx-json":
        # SPDX packages
        packages = sbom_data.get("packages", [])
        for pkg in packages:
            name = pkg.get("name", "")
            if name:
                dependencies.append(name)

    elif sbom_format == "cyclonedx-json":
        # CycloneDX components
        components = sbom_data.get("components", [])
        for comp in components:
            name = comp.get("name", "")
            if name:
                dependencies.append(name)

    return dependencies


def attach_sbom_to_image(
    image: str,
    sbom_file: Path,
) -> bool:
    """
    Attach SBOM to Docker image using Cosign.

    Args:
        image: Docker image (e.g., 'kademoslabs/kekkai:latest')
        sbom_file: Path to SBOM file

    Returns:
        True if attachment succeeded

    Raises:
        SBOMError: If attachment fails
    """
    if not sbom_file.exists():
        raise SBOMError(f"SBOM file not found: {sbom_file}")

    cmd = [
        "cosign",
        "attach",
        "sbom",
        "--sbom",
        str(sbom_file),
        image,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return result.returncode == 0

    except subprocess.CalledProcessError as e:
        raise SBOMError(f"SBOM attachment failed: {e.stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise SBOMError("SBOM attachment timed out after 120s") from e
