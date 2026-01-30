"""Compliance matrix report generator.

Generates a compliance-focused report showing control mappings
across all frameworks with finding counts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape


def generate_compliance_matrix(report_data: dict[str, Any], output_dir: Path) -> Path:
    """Generate compliance matrix report.

    Creates an HTML report focused on compliance framework mappings,
    showing which controls are affected by findings.
    """
    env = Environment(
        loader=PackageLoader("kekkai.report", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template("compliance_matrix.html")

    compliance_result = report_data["compliance"]

    # Build matrix data for each framework
    framework_matrices = {}
    for framework in ["PCI-DSS", "SOC2", "OWASP", "HIPAA"]:
        controls = compliance_result.get_controls_by_framework(framework)
        matrix_rows = []
        for control in controls:
            affected_findings = compliance_result.get_findings_for_control(
                framework, control.control_id
            )
            severity_counts = _count_severities(affected_findings)
            matrix_rows.append(
                {
                    "control_id": control.control_id,
                    "title": control.title,
                    "description": control.description,
                    "requirement_level": control.requirement_level,
                    "finding_count": len(affected_findings),
                    "severity_counts": severity_counts,
                    "status": _determine_status(affected_findings),
                }
            )
        framework_matrices[framework] = {
            "rows": matrix_rows,
            "total_controls": len(controls),
            "affected_controls": len([r for r in matrix_rows if r["finding_count"] > 0]),
        }

    html_content = template.render(
        metadata=report_data["metadata"],
        config=report_data["config"],
        framework_matrices=framework_matrices,
        executive_summary=report_data["executive_summary"],
    )

    output_path = output_dir / "compliance-matrix.html"
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def _count_severities(mappings: list[Any]) -> dict[str, int]:
    """Count findings by severity in mappings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for mapping in mappings:
        severity = mapping.finding_severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _determine_status(mappings: list[Any]) -> str:
    """Determine compliance status based on findings.

    Returns:
        'compliant': No findings
        'at_risk': Only low/info findings
        'non_compliant': Medium+ severity findings
    """
    if not mappings:
        return "compliant"

    severities = {m.finding_severity.lower() for m in mappings}

    if severities & {"critical", "high", "medium"}:
        return "non_compliant"
    if severities & {"low", "info"}:
        return "at_risk"
    return "compliant"
