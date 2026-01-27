"""ThreatFlow - Agentic threat modeling with local-first LLM support.

Security-conscious threat modeling that:
- Never executes repository code
- Redacts secrets before LLM processing
- Defends against prompt injection
- Supports local models by default
"""

from __future__ import annotations

from .artifacts import (
    ArtifactGenerator,
    DataFlowEntry,
    ThreatEntry,
    ThreatModelArtifacts,
)
from .chunking import ChunkingConfig, FileChunk, chunk_files
from .core import ThreatFlow, ThreatFlowConfig, ThreatFlowResult
from .mermaid import (
    MermaidDFDGenerator,
    MermaidEdge,
    MermaidNode,
    NodeType,
    generate_dfd_mermaid,
)
from .model_adapter import (
    LocalModelAdapter,
    MockModelAdapter,
    ModelAdapter,
    ModelResponse,
    RemoteModelAdapter,
)
from .prompts import PromptBuilder, STRIDECategory
from .redaction import ThreatFlowRedactor
from .sanitizer import (
    ClassifierResult,
    DefenseLayer,
    InjectionClassifier,
    InjectionPattern,
    InjectionRisk,
    OutputValidationResult,
    SanitizeConfig,
    Sanitizer,
    SanitizeResult,
    TieredSanitizer,
    TieredSanitizeResult,
)

__all__ = [
    # Core
    "ThreatFlow",
    "ThreatFlowConfig",
    "ThreatFlowResult",
    # Artifacts
    "ArtifactGenerator",
    "ThreatModelArtifacts",
    "ThreatEntry",
    "DataFlowEntry",
    # Chunking
    "ChunkingConfig",
    "FileChunk",
    "chunk_files",
    # Model adapters
    "ModelAdapter",
    "ModelResponse",
    "LocalModelAdapter",
    "RemoteModelAdapter",
    "MockModelAdapter",
    # Prompts
    "PromptBuilder",
    "STRIDECategory",
    # Redaction
    "ThreatFlowRedactor",
    # Sanitizer
    "Sanitizer",
    "SanitizeResult",
    "InjectionPattern",
    "InjectionRisk",
    # Tiered Sanitizer (Milestone 5)
    "TieredSanitizer",
    "TieredSanitizeResult",
    "SanitizeConfig",
    "DefenseLayer",
    "InjectionClassifier",
    "ClassifierResult",
    "OutputValidationResult",
    # Mermaid DFD (Milestone 3)
    "MermaidDFDGenerator",
    "MermaidNode",
    "MermaidEdge",
    "NodeType",
    "generate_dfd_mermaid",
]
