from __future__ import annotations

from kekkai.scanners.base import Finding, Severity, dedupe_findings


class TestSeverity:
    def test_from_string_critical(self) -> None:
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL

    def test_from_string_high(self) -> None:
        assert Severity.from_string("high") == Severity.HIGH

    def test_from_string_medium(self) -> None:
        assert Severity.from_string("medium") == Severity.MEDIUM
        assert Severity.from_string("moderate") == Severity.MEDIUM

    def test_from_string_low(self) -> None:
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("warning") == Severity.LOW

    def test_from_string_info(self) -> None:
        assert Severity.from_string("info") == Severity.INFO
        assert Severity.from_string("informational") == Severity.INFO

    def test_from_string_unknown(self) -> None:
        assert Severity.from_string("xyz") == Severity.UNKNOWN


class TestFinding:
    def test_dedupe_hash_deterministic(self) -> None:
        finding = Finding(
            scanner="trivy",
            title="CVE-2023-1234",
            severity=Severity.HIGH,
            description="Test",
            file_path="package.json",
            cve="CVE-2023-1234",
        )
        h1 = finding.dedupe_hash()
        h2 = finding.dedupe_hash()
        assert h1 == h2
        assert len(h1) == 16

    def test_dedupe_hash_differs_for_different_findings(self) -> None:
        f1 = Finding(
            scanner="trivy",
            title="CVE-2023-1234",
            severity=Severity.HIGH,
            description="Test",
            cve="CVE-2023-1234",
        )
        f2 = Finding(
            scanner="trivy",
            title="CVE-2023-5678",
            severity=Severity.HIGH,
            description="Test",
            cve="CVE-2023-5678",
        )
        assert f1.dedupe_hash() != f2.dedupe_hash()


class TestDedupe:
    def test_dedupe_removes_duplicates(self) -> None:
        f1 = Finding(
            scanner="trivy",
            title="CVE-2023-1234",
            severity=Severity.HIGH,
            description="Test",
            cve="CVE-2023-1234",
        )
        f2 = Finding(
            scanner="trivy",
            title="CVE-2023-1234",
            severity=Severity.HIGH,
            description="Different desc",  # Same hash fields
            cve="CVE-2023-1234",
        )
        f3 = Finding(
            scanner="trivy",
            title="CVE-2023-5678",
            severity=Severity.HIGH,
            description="Test",
            cve="CVE-2023-5678",
        )

        result = dedupe_findings([f1, f2, f3])
        assert len(result) == 2

    def test_dedupe_preserves_order(self) -> None:
        findings = [
            Finding(scanner="s", title=f"t{i}", severity=Severity.LOW, description="")
            for i in range(5)
        ]
        result = dedupe_findings(findings)
        assert [f.title for f in result] == ["t0", "t1", "t2", "t3", "t4"]

    def test_dedupe_empty_list(self) -> None:
        assert dedupe_findings([]) == []

    def test_dedupe_collapses_semgrep_family_duplicates_same_line(self) -> None:
        f1 = Finding(
            scanner="semgrep",
            title="python.flask.security.injection.tainted-sql-string",
            severity=Severity.HIGH,
            description="Detected user input used to manually construct a SQL string.",
            file_path="/repo/app.py",
            line=100,
            rule_id="python.flask.security.injection.tainted-sql-string",
        )
        f2 = Finding(
            scanner="semgrep",
            title="python.django.security.injection.tainted-sql-string",
            severity=Severity.HIGH,
            description="Detected user input used to manually construct a SQL string.",
            file_path="/repo/app.py",
            line=100,
            rule_id="python.django.security.injection.tainted-sql-string",
        )
        result = dedupe_findings([f1, f2])
        assert len(result) == 1

    def test_dedupe_keeps_semgrep_findings_if_line_differs(self) -> None:
        f1 = Finding(
            scanner="semgrep",
            title="python.flask.security.injection.tainted-sql-string",
            severity=Severity.HIGH,
            description="Detected user input used to manually construct a SQL string.",
            file_path="/repo/app.py",
            line=100,
            rule_id="python.flask.security.injection.tainted-sql-string",
        )
        f2 = Finding(
            scanner="semgrep",
            title="python.django.security.injection.tainted-sql-string",
            severity=Severity.HIGH,
            description="Detected user input used to manually construct a SQL string.",
            file_path="/repo/app.py",
            line=101,
            rule_id="python.django.security.injection.tainted-sql-string",
        )
        result = dedupe_findings([f1, f2])
        assert len(result) == 2
