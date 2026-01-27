"""Custom exceptions for the installer module."""

from __future__ import annotations


class InstallerError(Exception):
    """Base exception for installer errors."""


class SecurityError(InstallerError):
    """Raised on security verification failure (checksum mismatch, etc.)."""


class DownloadError(InstallerError):
    """Raised when download fails."""


class ExtractionError(InstallerError):
    """Raised when archive extraction fails."""


class UnsupportedPlatformError(InstallerError):
    """Raised when the current platform is not supported."""
