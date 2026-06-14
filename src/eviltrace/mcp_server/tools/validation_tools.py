from __future__ import annotations

from typing import Any

from eviltrace.validators.evidence_integrity import verify_manifest_integrity

from .common import ToolContext, structured_tool_event


def validate_manifest_integrity(ctx: ToolContext, *, manifest: dict[str, Any]) -> dict[str, Any]:
    output = verify_manifest_integrity(manifest, ctx.paths.workspace)
    return structured_tool_event(
        ctx,
        mcp_tool="validate_manifest_integrity",
        input_data={"case_id": manifest.get("case_id")},
        output=output,
        status="success" if output.get("status") == "passed" else "failed",
    )

