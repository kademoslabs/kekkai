from .base import (
    Finding,
    ScanContext,
    Scanner,
    ScanResult,
    Severity,
    dedupe_findings,
)
from .falco import FalcoScanner, create_falco_scanner
from .gitleaks import GitleaksScanner
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner
from .url_policy import UrlPolicy, UrlPolicyError, validate_target_url
from .zap import ZapScanner, create_zap_scanner

# Core scanners (SAST/SCA) - always available
SCANNER_REGISTRY: dict[str, type] = {
    "trivy": TrivyScanner,
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
}

# Optional scanners (DAST/runtime) - require explicit configuration
# These are NOT in the default registry to prevent accidental use
OPTIONAL_SCANNERS: dict[str, type] = {
    "zap": ZapScanner,
    "falco": FalcoScanner,
}

__all__ = [
    "create_falco_scanner",
    "create_zap_scanner",
    "dedupe_findings",
    "FalcoScanner",
    "Finding",
    "GitleaksScanner",
    "OPTIONAL_SCANNERS",
    "ScanContext",
    "ScanResult",
    "Scanner",
    "SCANNER_REGISTRY",
    "SemgrepScanner",
    "Severity",
    "TrivyScanner",
    "UrlPolicy",
    "UrlPolicyError",
    "validate_target_url",
    "ZapScanner",
]
