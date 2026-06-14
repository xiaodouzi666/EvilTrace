from __future__ import annotations

from pathlib import Path
from typing import Any

from eviltrace.evidence.hashing import sha256_file
from eviltrace.evidence.registry import EvidenceRegistry

from .common import ToolContext, structured_tool_event, workspace_path


def evidence_hash(ctx: ToolContext, *, path: str, algorithm: str = "sha256") -> dict[str, Any]:
    if algorithm != "sha256":
        return structured_tool_event(
            ctx,
            mcp_tool="evidence_hash",
            input_data={"path": path, "algorithm": algorithm},
            output={"path": path, "reason": "Only sha256 is supported"},
            status="needs_review",
        )
    resolved = workspace_path(ctx.paths, path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="evidence_hash",
            input_data={"path": path, "algorithm": algorithm},
            output={"path": path, "reason": "Evidence path does not exist"},
            status="needs_review",
        )
    digest = sha256_file(resolved)
    result = structured_tool_event(
        ctx,
        mcp_tool="evidence_hash",
        input_data={"path": path, "algorithm": algorithm},
        output={"sha256": digest, "tool": "python.sha256", "path": ctx.paths.relative_to_workspace(resolved)},
        status="success",
    )
    ctx.logger.log_event("evidence_hashed", iteration=ctx.iteration, input_data={"path": path}, output_summary={"sha256": digest})
    return result


def evidence_verify_integrity(ctx: ToolContext, *, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    target = manifest or ctx.manifest or {"case_id": ctx.logger.case_id, "evidence": []}
    registry = EvidenceRegistry.from_manifest(target)
    output = registry.verify(ctx.paths.workspace)
    output = dict(output)
    output["integrity_status"] = output["status"]
    return structured_tool_event(
        ctx,
        mcp_tool="evidence_verify_integrity",
        input_data={"case_id": target.get("case_id")},
        output=output,
        status="success" if output["integrity_status"] == "passed" else "failed",
    )

