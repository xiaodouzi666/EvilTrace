from __future__ import annotations

from typing import Any

from eviltrace.findings.model import Finding
from eviltrace.findings.registry import FindingRegistry, FindingRegistryError
from eviltrace.graph.correlate import add_network_artifact
from eviltrace.graph.model import EvidenceGraph
from eviltrace.validators.finding_validator import FindingValidator

from .common import ToolContext, structured_tool_event


_REGISTRIES: dict[str, FindingRegistry] = {}
_GRAPHS: dict[str, EvidenceGraph] = {}


def finding_propose(
    ctx: ToolContext,
    *,
    case_id: str,
    title: str,
    summary: str,
    category: str,
    supporting_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    registry = _REGISTRIES.setdefault(case_id, FindingRegistry(case_id))
    graph = _GRAPHS.setdefault(case_id, EvidenceGraph())
    artifacts = supporting_artifacts or []
    finding = Finding(
        finding_id=f"finding-{len(registry.all_for_validation()) + 1:04d}",
        case_id=case_id,
        title=title,
        summary=summary,
        category=category,
        status="candidate",
        confidence=0.55,
        artifacts=artifacts,
    )
    # Populate the per-case graph so finding_validate's hallucination check has real
    # entities to compare against instead of an empty graph.
    for artifact in artifacts:
        if artifact.get("artifact_id"):
            add_network_artifact(graph, artifact)
    try:
        registry.add(finding)
        output = {"finding_id": finding.finding_id, "status": finding.status, "confidence": finding.confidence, "validation_required": True}
        status = "success"
    except FindingRegistryError as exc:
        output = {"reason": str(exc)}
        status = "blocked"
    return structured_tool_event(ctx, mcp_tool="finding_propose", input_data={"case_id": case_id, "title": title}, output=output, status=status)


def finding_validate(ctx: ToolContext, *, case_id: str, finding_id: str, required_corroboration: int = 2) -> dict[str, Any]:
    registry = _REGISTRIES.get(case_id)
    if registry is None or finding_id not in registry.findings:
        return structured_tool_event(
            ctx,
            mcp_tool="finding_validate",
            input_data={"case_id": case_id, "finding_id": finding_id, "required_corroboration": required_corroboration},
            output={"reason": "Finding is not registered"},
            status="needs_review",
        )
    graph = _GRAPHS.get(case_id, EvidenceGraph())
    finding = registry.findings[finding_id]
    outcome = FindingValidator().validate(finding, graph, ctx.manifest)
    return structured_tool_event(
        ctx,
        mcp_tool="finding_validate",
        input_data={"case_id": case_id, "finding_id": finding_id, "required_corroboration": required_corroboration},
        output=outcome.to_dict(),
        status="success",
    )
