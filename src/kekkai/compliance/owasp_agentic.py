"""OWASP Top 10 for Agentic AI mapping for security findings.

Maps findings to OWASP Agentic AI Top 10 categories based on rule patterns.
Reference: https://genai.owasp.org/initiatives/agentic-security-initiative/

Released: December 2025 at Black Hat Europe

This framework addresses security risks specific to autonomous AI agents
that make decisions and take actions in real-world environments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .mappings import FrameworkControl

if TYPE_CHECKING:
    from kekkai.scanners.base import Finding


@dataclass(frozen=True)
class OWASPAgenticCategory:
    """OWASP Agentic AI Top 10 category definition."""

    id: str
    name: str
    description: str
    rule_patterns: tuple[str, ...]
    scanner_types: tuple[str, ...]  # Only apply to these scanner types


# OWASP Top 10 for Agentic AI (December 2025)
OWASP_AGENTIC_TOP_10: dict[str, OWASPAgenticCategory] = {
    "AA01": OWASPAgenticCategory(
        id="AA01:2025",
        name="Agent Goal Hijack",
        description=(
            "Attackers alter an agent's objectives through malicious content, "
            "prompt injection, or manipulated inputs causing the agent to "
            "act against the user's intent."
        ),
        rule_patterns=(
            "goal-hijack",
            "prompt-injection",
            "jailbreak",
            "objective-manipulation",
            "instruction-override",
            "system-prompt",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep"),
    ),
    "AA02": OWASPAgenticCategory(
        id="AA02:2025",
        name="Tool Misuse and Exploitation",
        description=(
            "Agents use legitimate tools in unsafe or unintended ways, "
            "potentially causing harmful actions through manipulation "
            "of tool parameters or abuse of tool capabilities."
        ),
        rule_patterns=(
            "tool-misuse",
            "tool-abuse",
            "function-call",
            "api-abuse",
            "unsafe-tool",
            "tool-injection",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep"),
    ),
    "AA03": OWASPAgenticCategory(
        id="AA03:2025",
        name="Identity and Privilege Abuse",
        description=(
            "Agents inherit or escalate high-privilege credentials, "
            "risking unauthorized access to sensitive systems, data, "
            "or operations beyond their intended scope."
        ),
        rule_patterns=(
            "privilege-escalation",
            "identity-abuse",
            "credential-inheritance",
            "over-privileged",
            "least-privilege",
            "agent-permission",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep"),
    ),
    "AA04": OWASPAgenticCategory(
        id="AA04:2025",
        name="Agentic Supply Chain Vulnerabilities",
        description=(
            "Compromised external components, plugins, or third-party "
            "agents can affect the security and behavior of the entire "
            "agentic system."
        ),
        rule_patterns=(
            "agent-supply-chain",
            "plugin-vulnerability",
            "external-agent",
            "third-party-agent",
            "model-supply-chain",
            "compromised-plugin",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep", "trivy"),
    ),
    "AA05": OWASPAgenticCategory(
        id="AA05:2025",
        name="Unexpected Code Execution",
        description=(
            "Agents generate or execute code unsafely, potentially "
            "running malicious code, accessing unauthorized resources, "
            "or causing system compromise."
        ),
        rule_patterns=(
            "code-execution",
            "code-generation",
            "unsafe-eval",
            "dynamic-execution",
            "sandbox-escape",
            "code-injection",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep"),
    ),
    "AA06": OWASPAgenticCategory(
        id="AA06:2025",
        name="Memory and Context Poisoning",
        description=(
            "Attackers corrupt an agent's memory systems or context "
            "window to influence future behavior, decisions, or outputs "
            "across sessions."
        ),
        rule_patterns=(
            "memory-poisoning",
            "context-poisoning",
            "context-manipulation",
            "memory-injection",
            "persistent-attack",
            "rag-poisoning",
        ),
        scanner_types=("llm", "ai", "genai", "agent"),
    ),
    "AA07": OWASPAgenticCategory(
        id="AA07:2025",
        name="Insecure Inter-Agent Communication",
        description=(
            "Risks of spoofing, tampering, and man-in-the-middle attacks "
            "in multi-agent systems due to weak authentication or "
            "encryption between agents."
        ),
        rule_patterns=(
            "inter-agent",
            "multi-agent",
            "agent-communication",
            "agent-spoofing",
            "agent-tampering",
            "agent-auth",
        ),
        scanner_types=("llm", "ai", "genai", "agent"),
    ),
    "AA08": OWASPAgenticCategory(
        id="AA08:2025",
        name="Cascading Failures",
        description=(
            "Small errors or failures in one part of an agentic system "
            "can propagate and cause larger, widespread failures across "
            "the entire system."
        ),
        rule_patterns=(
            "cascading-failure",
            "error-propagation",
            "fault-tolerance",
            "failure-isolation",
            "circuit-breaker",
            "retry-storm",
        ),
        scanner_types=("llm", "ai", "genai", "agent", "semgrep"),
    ),
    "AA09": OWASPAgenticCategory(
        id="AA09:2025",
        name="Human-Agent Trust Exploitation",
        description=(
            "Users place excessive trust in agent recommendations, "
            "leading to social engineering attacks, manipulation, "
            "or harmful decisions based on agent outputs."
        ),
        rule_patterns=(
            "trust-exploitation",
            "over-trust",
            "social-engineering",
            "manipulation",
            "deception",
            "human-override",
        ),
        scanner_types=("llm", "ai", "genai", "agent"),
    ),
    "AA10": OWASPAgenticCategory(
        id="AA10:2025",
        name="Rogue Agents",
        description=(
            "Compromised agents act maliciously while appearing legitimate, "
            "potentially exfiltrating data, causing damage, or subverting "
            "system controls."
        ),
        rule_patterns=(
            "rogue-agent",
            "compromised-agent",
            "malicious-agent",
            "agent-takeover",
            "agent-backdoor",
            "agent-exfiltration",
        ),
        scanner_types=("llm", "ai", "genai", "agent"),
    ),
}


def map_to_owasp_agentic(finding: Finding) -> list[FrameworkControl]:
    """Map a finding to OWASP Agentic AI Top 10 categories.

    Agentic AI mappings are primarily pattern-based since there are
    few established CWEs for these emerging risks. Mappings are also
    filtered by scanner type to avoid false positives.
    """
    controls: list[FrameworkControl] = []

    # Check rule_id patterns
    rule_id_lower = (finding.rule_id or "").lower()
    title_lower = finding.title.lower()
    description_lower = finding.description.lower()
    scanner_lower = finding.scanner.lower()

    for category in OWASP_AGENTIC_TOP_10.values():
        matched = False

        # Check if scanner type is relevant for this category
        scanner_relevant = any(st in scanner_lower for st in category.scanner_types)

        # For generic scanners like semgrep, also check if the finding
        # is related to AI/LLM based on content
        if not scanner_relevant:
            ai_keywords = ("llm", "agent", "ai", "model", "prompt", "genai")
            if any(kw in title_lower or kw in description_lower for kw in ai_keywords):
                scanner_relevant = True

        if not scanner_relevant:
            continue

        # Match by rule pattern
        for pattern in category.rule_patterns:
            if pattern in rule_id_lower or pattern in title_lower or pattern in description_lower:
                matched = True
                break

        if matched:
            controls.append(
                FrameworkControl(
                    framework="OWASP-Agentic",
                    control_id=category.id,
                    title=category.name,
                    description=category.description,
                    requirement_level="required",
                )
            )

    return controls
