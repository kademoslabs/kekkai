from __future__ import annotations

import ipaddress
import json
from unittest import mock

import pytest

from kekkai.scanners.base import Severity
from kekkai.scanners.url_policy import UrlPolicy, UrlPolicyError
from kekkai.scanners.zap import ZapScanner, create_zap_scanner


def _mock_resolve_public(*args: object, **kwargs: object) -> list[ipaddress.IPv4Address]:
    """Mock DNS resolution returning a public IP."""
    return [ipaddress.IPv4Address("93.184.216.34")]


SAMPLE_ZAP_OUTPUT: dict[str, object] = {
    "@version": "2.14.0",
    "site": [
        {
            "@name": "https://example.com",
            "@host": "example.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {
                    "pluginid": "10038",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "riskcode": "2",
                    "confidence": "3",
                    "desc": "CSP header missing",
                    "count": "5",
                    "solution": "Add CSP header",
                    "reference": "https://owasp.org/csp",
                    "cweid": "693",
                    "instances": [
                        {"uri": "https://example.com/page1"},
                        {"uri": "https://example.com/page2"},
                    ],
                },
                {
                    "pluginid": "10020",
                    "name": "X-Frame-Options Header Not Set",
                    "riskcode": "1",
                    "confidence": "2",
                    "desc": "X-Frame-Options missing",
                    "count": "1",
                    "instances": [
                        {"uri": "https://example.com/"},
                    ],
                },
            ],
        }
    ],
}


class TestZapScannerParse:
    def test_parse_alerts(self) -> None:
        scanner = ZapScanner()
        findings = scanner.parse(json.dumps(SAMPLE_ZAP_OUTPUT))

        assert len(findings) == 2

        csp = findings[0]
        assert csp.scanner == "zap"
        assert csp.title == "Content Security Policy (CSP) Header Not Set"
        assert csp.severity == Severity.MEDIUM  # riskcode 2
        assert csp.cwe == "CWE-693"
        assert csp.rule_id == "10038"
        assert "CSP header missing" in csp.description

        xframe = findings[1]
        assert xframe.title == "X-Frame-Options Header Not Set"
        assert xframe.severity == Severity.LOW  # riskcode 1

    def test_parse_empty_site(self) -> None:
        scanner = ZapScanner()
        output: dict[str, list[object]] = {"site": []}
        findings = scanner.parse(json.dumps(output))
        assert findings == []

    def test_parse_no_alerts(self) -> None:
        scanner = ZapScanner()
        output: dict[str, list[dict[str, object]]] = {
            "site": [{"@name": "https://example.com", "alerts": []}]
        }
        findings = scanner.parse(json.dumps(output))
        assert findings == []


class TestZapScannerRiskMapping:
    def test_risk_3_is_high(self) -> None:
        scanner = ZapScanner()
        assert scanner._map_risk_to_severity("3") == Severity.HIGH
        assert scanner._map_risk_to_severity(3) == Severity.HIGH

    def test_risk_2_is_medium(self) -> None:
        scanner = ZapScanner()
        assert scanner._map_risk_to_severity("2") == Severity.MEDIUM

    def test_risk_1_is_low(self) -> None:
        scanner = ZapScanner()
        assert scanner._map_risk_to_severity("1") == Severity.LOW

    def test_risk_0_is_info(self) -> None:
        scanner = ZapScanner()
        assert scanner._map_risk_to_severity("0") == Severity.INFO


class TestZapScannerTargetValidation:
    def test_requires_target_url(self) -> None:
        scanner = ZapScanner(target_url=None)
        with pytest.raises(UrlPolicyError, match="requires explicit"):
            scanner.validate_target()

    def test_validates_url_policy(self) -> None:
        scanner = ZapScanner(target_url="http://192.168.1.1/")
        with pytest.raises(UrlPolicyError, match="private/internal IP"):
            scanner.validate_target()

    def test_accepts_valid_public_url(self) -> None:
        scanner = ZapScanner(target_url="https://example.com/app")
        with mock.patch("kekkai.scanners.url_policy._resolve_host", _mock_resolve_public):
            url = scanner.validate_target()
            assert url == "https://example.com/app"

    def test_allows_private_with_policy(self) -> None:
        policy = UrlPolicy(allow_private_ips=True)
        scanner = ZapScanner(target_url="http://192.168.1.1/", policy=policy)
        url = scanner.validate_target()
        assert url == "http://192.168.1.1/"


class TestCreateZapScanner:
    def test_creates_scanner_with_target(self) -> None:
        scanner = create_zap_scanner(target_url="https://example.com")
        assert scanner._target_url == "https://example.com"

    def test_creates_scanner_with_private_ips_allowed(self) -> None:
        scanner = create_zap_scanner(
            target_url="http://127.0.0.1/",
            allow_private_ips=True,
        )
        # Should not raise during validation (loopback IP, not localhost hostname)
        url = scanner.validate_target()
        assert "127.0.0.1" in url

    def test_creates_scanner_with_domain_allowlist(self) -> None:
        scanner = create_zap_scanner(
            target_url="https://test.example.com/",
            allowed_domains=["example.com"],
        )
        with mock.patch("kekkai.scanners.url_policy._resolve_host", _mock_resolve_public):
            url = scanner.validate_target()
            assert url == "https://test.example.com/"


class TestZapScannerProperties:
    def test_name(self) -> None:
        scanner = ZapScanner()
        assert scanner.name == "zap"

    def test_scan_type(self) -> None:
        scanner = ZapScanner()
        assert scanner.scan_type == "ZAP Scan"
