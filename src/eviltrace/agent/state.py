from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eviltrace.findings.registry import FindingRegistry
from eviltrace.graph.model import EvidenceGraph


@dataclass
class RunState:
    case_id: str
    run_id: str
    profile: str
    max_iterations: int
    manifest: dict[str, Any] | None = None
    iteration: int = 0
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    validation_results: list[dict[str, Any]] = field(default_factory=list)
    corrections: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    targeted_replan: dict[str, Any] | None = None
    tried_alternate: dict[str, bool] = field(default_factory=dict)
    stop_reason: str = "completed"
    graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    registry: FindingRegistry | None = None

