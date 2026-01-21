from .base import (
    Finding,
    ScanContext,
    Scanner,
    ScanResult,
    Severity,
    dedupe_findings,
)
from .gitleaks import GitleaksScanner
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner

SCANNER_REGISTRY: dict[str, type] = {
    "trivy": TrivyScanner,
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
}

__all__ = [
    "Finding",
    "GitleaksScanner",
    "ScanContext",
    "ScanResult",
    "Scanner",
    "SCANNER_REGISTRY",
    "SemgrepScanner",
    "Severity",
    "TrivyScanner",
    "dedupe_findings",
]
