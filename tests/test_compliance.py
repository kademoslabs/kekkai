"""Unit tests for the compliance mapping module."""

from __future__ import annotations

from kekkai.compliance import (
    ComplianceMapping,
    FrameworkControl,
    map_findings_to_all_frameworks,
    map_to_hipaa,
    map_to_owasp,
    map_to_owasp_agentic,
    map_to_pci_dss,
    map_to_soc2,
)
from kekkai.scanners.base import Finding, Severity


class TestOWASPMapping:
    """Tests for OWASP Top 10 2025 mapping."""

    def test_map_injection_finding_by_cwe(self) -> None:
        """Test mapping SQL injection finding via CWE."""
        finding = Finding(
            scanner="semgrep",
            title="SQL Injection vulnerability",
            severity=Severity.HIGH,
            description="SQL injection detected",
            cwe="CWE-89",
            rule_id="python.lang.security.audit.dangerous-sql",
        )

        controls = map_to_owasp(finding)

        # Should map to A05:2025 (Injection) - moved from A03 in 2021
        assert any(c.control_id == "A05:2025" for c in controls)
        assert any("Injection" in c.title for c in controls)

    def test_map_xss_finding_by_rule_pattern(self) -> None:
        """Test mapping XSS finding via rule pattern."""
        finding = Finding(
            scanner="semgrep",
            title="Cross-site scripting (XSS) vulnerability",
            severity=Severity.MEDIUM,
            description="XSS detected",
            rule_id="javascript.browser.security.dom-xss",
        )

        controls = map_to_owasp(finding)

        # Should map to A05:2025 (Injection) due to 'xss' pattern
        assert any(c.control_id == "A05:2025" for c in controls)

    def test_map_cve_to_supply_chain(self) -> None:
        """Test CVE findings map to A03:2025 (Software Supply Chain Failures)."""
        finding = Finding(
            scanner="trivy",
            title="CVE-2021-44228",
            severity=Severity.CRITICAL,
            description="Log4j RCE vulnerability",
            cve="CVE-2021-44228",
        )

        controls = map_to_owasp(finding)

        # Should map to A03:2025 (Software Supply Chain Failures)
        assert any(c.control_id == "A03:2025" for c in controls)

    def test_map_authentication_finding(self) -> None:
        """Test authentication finding maps to A07:2025."""
        finding = Finding(
            scanner="semgrep",
            title="Hardcoded password detected",
            severity=Severity.HIGH,
            description="Password hardcoded in source code",
            cwe="CWE-798",
            rule_id="python.lang.security.audit.hardcoded-password",
        )

        controls = map_to_owasp(finding)

        # Should map to A07:2025 (Authentication Failures)
        assert any(c.control_id == "A07:2025" for c in controls)

    def test_map_ssrf_to_broken_access_control(self) -> None:
        """Test SSRF maps to A01:2025 (was A10 in 2021)."""
        finding = Finding(
            scanner="semgrep",
            title="Server-Side Request Forgery",
            severity=Severity.HIGH,
            description="SSRF vulnerability detected",
            cwe="CWE-918",
            rule_id="python.requests.security.ssrf",
        )

        controls = map_to_owasp(finding)

        # Should map to A01:2025 (Broken Access Control) - SSRF merged in
        assert any(c.control_id == "A01:2025" for c in controls)

    def test_map_security_misconfiguration(self) -> None:
        """Test security misconfiguration maps to A02:2025."""
        finding = Finding(
            scanner="semgrep",
            title="Debug mode enabled",
            severity=Severity.MEDIUM,
            description="Debug mode enabled in production",
            rule_id="python.flask.security.debug-enabled",
        )

        controls = map_to_owasp(finding)

        # Should map to A02:2025 (Security Misconfiguration) - now #2
        assert any(c.control_id == "A02:2025" for c in controls)

    def test_map_exception_handling(self) -> None:
        """Test exception handling maps to A10:2025 (NEW)."""
        finding = Finding(
            scanner="semgrep",
            title="Uncaught exception in error handler",
            severity=Severity.MEDIUM,
            description="Exception not properly handled",
            cwe="CWE-755",
            rule_id="python.lang.security.audit.unhandled-exception",
        )

        controls = map_to_owasp(finding)

        # Should map to A10:2025 (Mishandling of Exceptional Conditions) - NEW
        assert any(c.control_id == "A10:2025" for c in controls)


class TestOWASPAgenticMapping:
    """Tests for OWASP Agentic AI Top 10 mapping."""

    def test_map_prompt_injection(self) -> None:
        """Test prompt injection maps to AA01 (Agent Goal Hijack)."""
        finding = Finding(
            scanner="llm",
            title="Prompt injection vulnerability",
            severity=Severity.HIGH,
            description="User input can manipulate LLM behavior",
            rule_id="llm.security.prompt-injection",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA01:2025" for c in controls)
        assert any("Goal Hijack" in c.title for c in controls)

    def test_map_tool_misuse(self) -> None:
        """Test tool misuse maps to AA02."""
        finding = Finding(
            scanner="agent",
            title="Unsafe tool invocation",
            severity=Severity.HIGH,
            description="Agent can be manipulated to misuse tool-use capabilities",
            rule_id="agent.security.tool-misuse",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA02:2025" for c in controls)

    def test_map_privilege_abuse(self) -> None:
        """Test privilege abuse maps to AA03."""
        finding = Finding(
            scanner="ai",
            title="Over-privileged agent credentials",
            severity=Severity.HIGH,
            description="Agent has excessive permissions beyond least-privilege",
            rule_id="ai.security.over-privileged",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA03:2025" for c in controls)

    def test_map_code_execution(self) -> None:
        """Test code execution maps to AA05."""
        finding = Finding(
            scanner="genai",
            title="Unsafe code generation",
            severity=Severity.CRITICAL,
            description="Agent generates executable code without sandboxing",
            rule_id="genai.security.code-execution",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA05:2025" for c in controls)

    def test_map_memory_poisoning(self) -> None:
        """Test memory poisoning maps to AA06."""
        finding = Finding(
            scanner="llm",
            title="RAG poisoning vulnerability",
            severity=Severity.HIGH,
            description="Retrieval system can be poisoned with malicious context",
            rule_id="llm.security.rag-poisoning",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA06:2025" for c in controls)

    def test_map_inter_agent_communication(self) -> None:
        """Test inter-agent communication maps to AA07."""
        finding = Finding(
            scanner="agent",
            title="Insecure multi-agent messaging",
            severity=Severity.MEDIUM,
            description="No authentication between agents in multi-agent system",
            rule_id="agent.security.inter-agent-auth",
        )

        controls = map_to_owasp_agentic(finding)

        assert any(c.control_id == "AA07:2025" for c in controls)

    def test_non_ai_scanner_with_ai_content(self) -> None:
        """Test that non-AI scanners can match if content is AI-related."""
        finding = Finding(
            scanner="semgrep",
            title="LLM prompt injection in API endpoint",
            severity=Severity.HIGH,
            description="User input passed directly to LLM prompt",
            rule_id="python.llm.security.prompt-injection",
        )

        controls = map_to_owasp_agentic(finding)

        # Should match due to 'llm' and 'prompt-injection' in content
        assert any(c.control_id == "AA01:2025" for c in controls)

    def test_non_ai_scanner_no_match(self) -> None:
        """Test that non-AI findings don't map to agentic categories."""
        finding = Finding(
            scanner="semgrep",
            title="SQL Injection",
            severity=Severity.HIGH,
            description="User input in SQL query",
            cwe="CWE-89",
            rule_id="python.sql.injection",
        )

        controls = map_to_owasp_agentic(finding)

        # Should not match any agentic categories
        assert len(controls) == 0


class TestPCIDSSMapping:
    """Tests for PCI-DSS v4.0 mapping."""

    def test_map_injection_to_requirement_6_2_4(self) -> None:
        """Test injection findings map to PCI-DSS 6.2.4."""
        finding = Finding(
            scanner="semgrep",
            title="Command injection vulnerability",
            severity=Severity.HIGH,
            description="os.system with user input",
            cwe="CWE-78",
            rule_id="python.lang.security.audit.dangerous-system-call",
        )

        controls = map_to_pci_dss(finding)

        # Should map to 6.2.4 (Software engineering techniques)
        assert any(c.control_id == "6.2.4" for c in controls)

    def test_map_cve_to_requirement_6_3_1(self) -> None:
        """Test CVE findings map to PCI-DSS 6.3.1."""
        finding = Finding(
            scanner="trivy",
            title="CVE-2023-1234",
            severity=Severity.HIGH,
            description="Known vulnerability",
            cve="CVE-2023-1234",
        )

        controls = map_to_pci_dss(finding)

        # Should map to 6.3.1 (Security vulnerabilities are identified)
        assert any(c.control_id == "6.3.1" for c in controls)

    def test_map_encryption_finding(self) -> None:
        """Test weak encryption maps to PCI-DSS 3.5 or 4.2."""
        finding = Finding(
            scanner="semgrep",
            title="Weak cryptographic algorithm",
            severity=Severity.MEDIUM,
            description="Using MD5 for hashing",
            cwe="CWE-327",
            rule_id="python.lang.security.audit.weak-crypto",
        )

        controls = map_to_pci_dss(finding)

        # Should map to 3.5 (PAN is secured) due to crypto CWE
        assert any(c.control_id == "3.5" for c in controls)

    def test_map_hardcoded_password_to_8_3(self) -> None:
        """Test hardcoded credentials map to PCI-DSS 8.3."""
        finding = Finding(
            scanner="gitleaks",
            title="Hardcoded password in config",
            severity=Severity.HIGH,
            description="Password detected in source",
            rule_id="generic-password",
        )

        controls = map_to_pci_dss(finding)

        # Should map to 8.3 (Strong authentication) due to 'password' pattern
        assert any(c.control_id == "8.3" for c in controls)


class TestSOC2Mapping:
    """Tests for SOC 2 mapping."""

    def test_map_access_control_finding(self) -> None:
        """Test access control findings map to CC6.1."""
        finding = Finding(
            scanner="semgrep",
            title="Insecure direct object reference",
            severity=Severity.HIGH,
            description="IDOR vulnerability detected",
            cwe="CWE-639",
            rule_id="python.django.security.idor",
        )

        controls = map_to_soc2(finding)

        # Should map to CC6.1 (Logical and Physical Access Controls)
        assert any(c.control_id == "CC6.1" for c in controls)

    def test_map_logging_finding(self) -> None:
        """Test logging findings map to CC6.6."""
        finding = Finding(
            scanner="semgrep",
            title="Log injection vulnerability",
            severity=Severity.MEDIUM,
            description="User input in log statement",
            cwe="CWE-117",
            rule_id="python.lang.security.audit.log-injection",
        )

        controls = map_to_soc2(finding)

        # Should map to CC6.6 (Security Events Detection)
        assert any(c.control_id == "CC6.6" for c in controls)

    def test_map_input_validation_finding(self) -> None:
        """Test input validation findings map to PI1.2."""
        finding = Finding(
            scanner="semgrep",
            title="Missing input validation",
            severity=Severity.MEDIUM,
            description="User input not validated",
            cwe="CWE-20",
            rule_id="python.lang.security.audit.no-validation",
        )

        controls = map_to_soc2(finding)

        # Should map to PI1.2 (Input Validation)
        assert any(c.control_id == "PI1.2" for c in controls)


class TestHIPAAMapping:
    """Tests for HIPAA Security Rule mapping."""

    def test_map_access_control_finding(self) -> None:
        """Test access control findings map to 164.312(a)(1)."""
        finding = Finding(
            scanner="semgrep",
            title="Missing authorization check",
            severity=Severity.HIGH,
            description="No authorization before accessing PHI",
            cwe="CWE-862",
            rule_id="python.flask.security.missing-authorization",
        )

        controls = map_to_hipaa(finding)

        # Should map to 164.312(a)(1) (Access Control)
        assert any(c.control_id == "164.312(a)(1)" for c in controls)

    def test_map_encryption_finding(self) -> None:
        """Test encryption findings map to 164.312(a)(2)(iv)."""
        finding = Finding(
            scanner="semgrep",
            title="Data transmitted without encryption",
            severity=Severity.HIGH,
            description="ePHI sent over HTTP",
            cwe="CWE-319",
            rule_id="python.requests.security.no-tls",
        )

        controls = map_to_hipaa(finding)

        # Should map to 164.312(a)(2)(iv) (Encryption and Decryption)
        assert any(c.control_id == "164.312(a)(2)(iv)" for c in controls)

    def test_map_audit_finding(self) -> None:
        """Test audit control findings map to 164.312(b)."""
        finding = Finding(
            scanner="semgrep",
            title="Missing audit logging",
            severity=Severity.MEDIUM,
            description="PHI access not logged",
            cwe="CWE-778",
            rule_id="python.logging.security.missing-audit",
        )

        controls = map_to_hipaa(finding)

        # Should map to 164.312(b) (Audit Controls)
        assert any(c.control_id == "164.312(b)" for c in controls)


class TestComplianceMappingResult:
    """Tests for the overall compliance mapping result."""

    def test_map_findings_to_all_frameworks(self) -> None:
        """Test mapping multiple findings to all frameworks."""
        findings = [
            Finding(
                scanner="semgrep",
                title="SQL Injection",
                severity=Severity.HIGH,
                description="SQL injection",
                cwe="CWE-89",
            ),
            Finding(
                scanner="trivy",
                title="CVE-2021-44228",
                severity=Severity.CRITICAL,
                description="Log4j vulnerability",
                cve="CVE-2021-44228",
            ),
        ]

        result = map_findings_to_all_frameworks(findings)

        assert result.total_findings == 2
        assert len(result.mappings) == 2
        assert result.framework_summary["OWASP"] > 0
        assert result.framework_summary["PCI-DSS"] > 0

    def test_map_findings_includes_agentic(self) -> None:
        """Test that agentic framework is included in results."""
        findings = [
            Finding(
                scanner="llm",
                title="Prompt injection vulnerability",
                severity=Severity.HIGH,
                description="LLM prompt manipulation",
                rule_id="llm.prompt-injection",
            ),
        ]

        result = map_findings_to_all_frameworks(findings)

        assert "OWASP-Agentic" in result.framework_summary
        assert result.framework_summary["OWASP-Agentic"] > 0

    def test_get_controls_by_framework(self) -> None:
        """Test retrieving controls for a specific framework."""
        findings = [
            Finding(
                scanner="semgrep",
                title="XSS",
                severity=Severity.MEDIUM,
                description="Cross-site scripting",
                cwe="CWE-79",
            ),
        ]

        result = map_findings_to_all_frameworks(findings)

        owasp_controls = result.get_controls_by_framework("OWASP")
        assert len(owasp_controls) > 0
        assert all(c.framework == "OWASP" for c in owasp_controls)

    def test_get_findings_for_control(self) -> None:
        """Test retrieving findings for a specific control."""
        findings = [
            Finding(
                scanner="semgrep",
                title="SQL Injection 1",
                severity=Severity.HIGH,
                description="SQL injection",
                cwe="CWE-89",
            ),
            Finding(
                scanner="semgrep",
                title="SQL Injection 2",
                severity=Severity.HIGH,
                description="Another SQL injection",
                cwe="CWE-89",
            ),
        ]

        result = map_findings_to_all_frameworks(findings)

        # Both should map to A05:2025 (Injection)
        injection_findings = result.get_findings_for_control("OWASP", "A05:2025")
        assert len(injection_findings) == 2


class TestComplianceMappingClass:
    """Tests for ComplianceMapping class."""

    def test_add_control(self) -> None:
        """Test adding controls to a mapping."""
        mapping = ComplianceMapping(
            finding_hash="abc123",
            finding_title="Test Finding",
            finding_severity="high",
        )

        mapping.add_control(
            FrameworkControl(
                framework="OWASP",
                control_id="A05:2025",
                title="Injection",
                description="Test",
            )
        )

        assert len(mapping.controls) == 1
        assert mapping.has_framework("OWASP")
        assert not mapping.has_framework("PCI-DSS")


class TestCWEExtraction:
    """Tests for CWE ID extraction."""

    def test_cwe_with_prefix(self) -> None:
        """Test CWE extraction with CWE- prefix."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            cwe="CWE-79",
        )

        controls = map_to_owasp(finding)
        # CWE-79 is XSS, maps to A05:2025 (Injection)
        assert any(c.control_id == "A05:2025" for c in controls)

    def test_cwe_numeric_only(self) -> None:
        """Test CWE extraction with numeric only."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            cwe="79",
        )

        controls = map_to_owasp(finding)
        assert any(c.control_id == "A05:2025" for c in controls)

    def test_invalid_cwe(self) -> None:
        """Test handling of invalid CWE string."""
        finding = Finding(
            scanner="test",
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            cwe="invalid",
        )

        # Should not crash, just not match by CWE
        controls = map_to_owasp(finding)
        # May still match by other criteria
        assert isinstance(controls, list)
