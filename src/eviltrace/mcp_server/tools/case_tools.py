from __future__ import annotations

from pathlib import Path
from typing import Any

from eviltrace.evidence.manifest import build_case_manifest, write_manifest

from .common import ToolContext, structured_tool_event


def case_register(
    ctx: ToolContext,
    *,
    case_id: str,
    case_root: str,
    case_type: str = "unknown",
    description: str = "",
) -> dict[str, Any]:
    ctx.paths.ensure()
    manifest = build_case_manifest(case_id, case_root, ctx.paths, case_type=case_type, description=description)
    manifest_path = ctx.paths.reports_dir / f"{case_id}.case.json"
    write_manifest(manifest, manifest_path)
    ctx.manifest = manifest
    output = {
        "case_id": case_id,
        "case_root": manifest["case_root"],
        "registered_at": manifest["registered_at"],
        "evidence_count": manifest["evidence_count"],
        "manifest_path": ctx.paths.relative_to_workspace(manifest_path),
    }
    result = structured_tool_event(
        ctx,
        mcp_tool="case_register",
        input_data={"case_id": case_id, "case_root": case_root, "case_type": case_type},
        output=output,
        status="success",
    )
    ctx.logger.log_event("case_registered", iteration=ctx.iteration, input_data={"case_id": case_id}, output_summary=output)
    return result


def case_manifest(ctx: ToolContext, *, case_id: str, case_root: str) -> dict[str, Any]:
    manifest = build_case_manifest(case_id, case_root, ctx.paths)
    ctx.manifest = manifest
    return structured_tool_event(
        ctx,
        mcp_tool="case_manifest",
        input_data={"case_id": case_id, "case_root": case_root},
        output=manifest,
        status="success",
    )

