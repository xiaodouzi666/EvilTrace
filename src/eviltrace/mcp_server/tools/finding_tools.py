from __future__ import annotations

from typing import Any

from eviltrace.findings.model import Finding
from eviltrace.findings.registry import FindingRegistry, FindingRegistryError
from eviltrace.validators.finding_validator import FindingValidator
from eviltrace.graph.model import EvidenceGraph

from .common import ToolContext, structured_tool_event


_REGISTRIES: dict[str, FindingRegistry] = {}


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
    finding = Finding(
        finding_id=f"finding-{len(registry.all_for_validation()) + 1:04d}",
        case_id=case_id,
        title=title,
        summary=summary,
        category=category,
        status="candidate",
        confidence=0.55,
        artifacts=supporting_artifacts or [],
    )
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
    graph = EvidenceGraph()
    finding = registry.findings[finding_id]
    outcome = FindingValidator().validate(finding, graph)
    return structured_tool_event(
        ctx,
        mcp_tool="finding_validate",
        input_data={"case_id": case_id, "finding_id": finding_id, "required_corroboration": required_corroboration},
        output=outcome.to_dict(),
        status="success",
    )

