from __future__ import annotations

from typing import Any

from .common import ToolContext, structured_tool_event, workspace_path


def disk_image_info(ctx: ToolContext, *, image_path: str) -> dict[str, Any]:
    resolved = workspace_path(ctx.paths, image_path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="disk_image_info",
            input_data={"image_path": image_path},
            output={"image_path": image_path, "reason": "Disk image does not exist"},
            status="needs_review",
        )
    result = ctx.runner.run(["file", str(resolved)], mcp_tool="disk_image_info", input_data={"image_path": image_path}, iteration=ctx.iteration)
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "image_type": result.stdout.strip(),
        "partitions": [],
        "raw_output_path": result.raw_output_path,
    }


def disk_timeline(
    ctx: ToolContext,
    *,
    image_path: str,
    partition_offset: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    return structured_tool_event(
        ctx,
        mcp_tool="disk_timeline",
        input_data={
            "image_path": image_path,
            "partition_offset": partition_offset,
            "start_time": start_time,
            "end_time": end_time,
        },
        output={
            "timeline_path": None,
            "event_count": 0,
            "suspicious_windows": [],
            "reason": "Timeline generation requires case-specific Sleuth Kit extraction parameters; no timeline was generated without local evidence validation.",
        },
        status="needs_review",
    )


def disk_search_files(ctx: ToolContext, *, image_path: str, partition_offset: int | None = None, patterns: list[str] | None = None) -> dict[str, Any]:
    return structured_tool_event(
        ctx,
        mcp_tool="disk_search_files",
        input_data={"image_path": image_path, "partition_offset": partition_offset, "patterns": patterns or []},
        output={"matches": [], "reason": "File search is available after a disk image is provided and mounted/extracted read-only."},
        status="needs_review",
    )

