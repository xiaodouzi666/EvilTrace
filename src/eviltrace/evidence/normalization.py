from __future__ import annotations

from typing import Any


def artifact_from_tool_result(
    *,
    artifact_id: str,
    artifact_type: str,
    source_path: str,
    source_sha256: str,
    tool: str,
    mcp_tool: str,
    audit_id: str,
    raw_output_path: str | None = None,
    offset_or_record: str | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "source_path": source_path,
        "source_sha256": source_sha256,
        "tool": tool,
        "mcp_tool": mcp_tool,
        "audit_id": audit_id,
        "offset_or_record": offset_or_record,
        "raw_output_path": raw_output_path,
        "summary": summary or {},
    }

