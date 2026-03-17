"""
Automated tests to verify expected vulnerabilities are detected.
Run this after executing kekkai scan.
"""

import json
import pytest
from pathlib import Path


class TestScanResults:
    """Test that Kekkai detects expected vulnerabilities."""
    
    @pytest.fixture
    def results_dir(self):
        """Get the results directory."""
        return Path(__file__).parent.parent
    
    def test_trivy_results_exist(self, results_dir):
        """Verify Trivy results file exists and has content."""
        trivy_file = results_dir / "trivy-results.json"
        assert trivy_file.exists(), "trivy-results.json not found"
        assert trivy_file.stat().st_size > 0, "trivy-results.json is empty"
    
    def test_semgrep_results_exist(self, results_dir):
        """Verify Semgrep results file exists and has content."""
        semgrep_file = results_dir / "semgrep-results.json"
        assert semgrep_file.exists(), "semgrep-results.json not found"
        assert semgrep_file.stat().st_size > 0, "semgrep-results.json is empty"
    
    def test_gitleaks_results_exist(self, results_dir):
        """Verify Gitleaks results file exists and has content."""
        gitleaks_file = results_dir / "gitleaks-results.json"
        assert gitleaks_file.exists(), "gitleaks-results.json not found"
        assert gitleaks_file.stat().st_size > 0, "gitleaks-results.json is empty"
    
    def test_unified_report_exists(self, results_dir):
        """Verify unified report exists and has correct structure."""
        report_file = results_dir / "kekkai-report.json"
        assert report_file.exists(), "kekkai-report.json not found"
        
        with open(report_file) as f:
            data = json.load(f)
        
        assert "findings" in data, "Missing 'findings' field"
        assert "scan_metadata" in data, "Missing 'scan_metadata' field"
        assert isinstance(data["findings"], list), "findings should be a list"
    
    def test_trivy_detects_vulnerabilities(self, results_dir):
        """Verify Trivy detects dependency vulnerabilities."""
        trivy_file = results_dir / "trivy-results.json"
        
        with open(trivy_file) as f:
            data = json.load(f)
        
        vuln_count = 0
        for result in data.get("Results", []):
            vulns = result.get("Vulnerabilities") or []
            vuln_count += len(vulns)
        
        assert vuln_count >= 10, f"Expected 10+ CVEs, found {vuln_count}"
    
    def test_semgrep_detects_code_issues(self, results_dir):
        """Verify Semgrep detects code vulnerabilities."""
        semgrep_file = results_dir / "semgrep-results.json"
        
        with open(semgrep_file) as f:
            data = json.load(f)
        
        results = data.get("results", [])
        assert len(results) >= 30, f"Expected 30+ code issues, found {len(results)}"
    
    def test_gitleaks_detects_secrets(self, results_dir):
        """Verify Gitleaks detects hardcoded secrets."""
        gitleaks_file = results_dir / "gitleaks-results.json"
        
        with open(gitleaks_file) as f:
            data = json.load(f)
        
        secret_count = len(data) if isinstance(data, list) else 0
        assert secret_count >= 20, f"Expected 20+ secrets, found {secret_count}"
    
    def test_sql_injection_detected(self, results_dir):
        """Verify SQL injection vulnerabilities are detected."""
        semgrep_file = results_dir / "semgrep-results.json"
        
        with open(semgrep_file) as f:
            data = json.load(f)
        
        sql_findings = [
            r for r in data.get("results", [])
            if "sql" in r.get("check_id", "").lower()
        ]
        
        assert len(sql_findings) > 0, "No SQL injection findings detected"
    
    def test_command_injection_detected(self, results_dir):
        """Verify command injection vulnerabilities are detected."""
        semgrep_file = results_dir / "semgrep-results.json"
        
        with open(semgrep_file) as f:
            data = json.load(f)
        
        cmd_findings = [
            r for r in data.get("results", [])
            if any(keyword in r.get("check_id", "").lower() 
                   for keyword in ["injection", "command", "exec", "system"])
        ]
        
        assert len(cmd_findings) > 0, "No command injection findings detected"
    
    def test_hardcoded_secrets_detected(self, results_dir):
        """Verify hardcoded secrets in Python files are detected."""
        gitleaks_file = results_dir / "gitleaks-results.json"
        
        with open(gitleaks_file) as f:
            data = json.load(f)
        
        if isinstance(data, list):
            python_files = [
                item for item in data
                if "hardcoded_secrets.py" in item.get("File", "")
            ]
            
            assert len(python_files) > 0, "No secrets detected in hardcoded_secrets.py"
    
    def test_unified_report_aggregates_findings(self, results_dir):
        """Verify unified report aggregates all scanner findings."""
        report_file = results_dir / "kekkai-report.json"
        
        with open(report_file) as f:
            data = json.load(f)
        
        findings = data.get("findings", [])
        
        # Should have findings from all scanners
        scanners = {f.get("scanner") for f in findings}
        
        # At minimum, should have trivy, semgrep, or gitleaks
        assert len(scanners) > 0, "No scanner findings in unified report"
        assert len(findings) >= 60, f"Expected 60+ total findings, found {len(findings)}"
