"""Windows distribution integration for Kekkai.

This module provides utilities for Windows package managers:
- Scoop manifest generation and validation
- PowerShell installer script generation
- Windows-specific validation (Python version, PATH)
"""

from kekkai_core.windows.installer import (
    generate_installer_script,
    generate_uninstaller_script,
)
from kekkai_core.windows.scoop import (
    generate_scoop_manifest,
    validate_scoop_manifest,
)
from kekkai_core.windows.validators import (
    validate_python_version,
    validate_windows_path,
)

__all__ = [
    "generate_scoop_manifest",
    "validate_scoop_manifest",
    "generate_installer_script",
    "generate_uninstaller_script",
    "validate_python_version",
    "validate_windows_path",
]
