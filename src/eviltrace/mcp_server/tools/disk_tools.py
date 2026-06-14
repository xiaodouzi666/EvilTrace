from __future__ import annotations

import fnmatch
import shutil
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
    partitions: list[dict[str, Any]] = []
    if shutil.which("mmls") is not None:
        mmls = ctx.runner.run(["mmls", str(resolved)], mcp_tool="disk_image_info", input_data={"image_path": image_path}, iteration=ctx.iteration)
        for line in mmls.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
                partitions.append({"slot": parts[0].rstrip(":"), "start_sector": parts[2], "description": " ".join(parts[5:])})
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "image_type": result.stdout.strip(),
        "partitions": partitions,
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
    input_data = {"image_path": image_path, "partition_offset": partition_offset, "start_time": start_time, "end_time": end_time}
    resolved = workspace_path(ctx.paths, image_path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="disk_timeline",
            input_data=input_data,
            output={"timeline_path": None, "event_count": 0, "suspicious_windows": [], "reason": "Disk image does not exist"},
            status="needs_review",
        )
    if shutil.which("fls") is None or shutil.which("mactime") is None:
        return structured_tool_event(
            ctx,
            mcp_tool="disk_timeline",
            input_data=input_data,
            output={
                "timeline_path": None,
                "event_count": 0,
                "suspicious_windows": [],
                "fallback_reason": "Sleuth Kit fls/mactime is not installed; timeline generation is unavailable on this host.",
            },
            status="needs_review",
        )
    fls_cmd = ["fls", "-r", "-m", "/"]
    if partition_offset is not None:
        fls_cmd += ["-o", str(partition_offset)]
    fls_cmd.append(str(resolved))
    fls_result = ctx.runner.run(fls_cmd, mcp_tool="disk_timeline", input_data=input_data, iteration=ctx.iteration)
    if fls_result.status != "success":
        return {"audit_id": fls_result.audit_id, "status": fls_result.status, "timeline_path": None, "event_count": 0, "reason": fls_result.stderr[:500], "raw_output_path": fls_result.raw_output_path}
    timelines_dir = ctx.guardrails.ensure_write_path(ctx.paths.raw_dir / "timelines")
    timelines_dir.mkdir(parents=True, exist_ok=True)
    body_path = timelines_dir / f"{fls_result.audit_id}.body"
    body_path.write_text(fls_result.stdout, encoding="utf-8")
    mac_result = ctx.runner.run(["mactime", "-b", str(body_path), "-d"], mcp_tool="disk_timeline", input_data=input_data, iteration=ctx.iteration)
    csv_path = timelines_dir / f"{mac_result.audit_id}.csv"
    csv_path.write_text(mac_result.stdout, encoding="utf-8")
    event_count = max(0, len([line for line in mac_result.stdout.splitlines() if line.strip()]) - 1)
    return {
        "audit_id": mac_result.audit_id,
        "status": mac_result.status,
        "timeline_path": ctx.paths.relative_to_workspace(csv_path),
        "event_count": event_count,
        "suspicious_windows": [],
        "underlying_tool": "sleuthkit.fls+mactime",
        "raw_output_path": mac_result.raw_output_path,
    }


def disk_search_files(ctx: ToolContext, *, image_path: str, partition_offset: int | None = None, patterns: list[str] | None = None) -> dict[str, Any]:
    patterns = patterns or []
    input_data = {"image_path": image_path, "partition_offset": partition_offset, "patterns": patterns}
    resolved = workspace_path(ctx.paths, image_path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="disk_search_files",
            input_data=input_data,
            output={"matches": [], "reason": "Disk image does not exist"},
            status="needs_review",
        )
    if shutil.which("fls") is None:
        return structured_tool_event(
            ctx,
            mcp_tool="disk_search_files",
            input_data=input_data,
            output={"matches": [], "fallback_reason": "Sleuth Kit fls is not installed; file search is unavailable on this host."},
            status="needs_review",
        )
    fls_cmd = ["fls", "-r", "-p"]
    if partition_offset is not None:
        fls_cmd += ["-o", str(partition_offset)]
    fls_cmd.append(str(resolved))
    result = ctx.runner.run(fls_cmd, mcp_tool="disk_search_files", input_data=input_data, iteration=ctx.iteration)
    if result.status != "success":
        return {"audit_id": result.audit_id, "status": result.status, "matches": [], "reason": result.stderr[:500], "raw_output_path": result.raw_output_path}
    matches: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        entry = line.strip()
        if not entry:
            continue
        path_part = entry.split("\t", 1)[-1]
        name = path_part.rsplit("/", 1)[-1]
        for pattern in patterns:
            if fnmatch.fnmatch(name.lower(), pattern.lower()) or pattern.lower() in path_part.lower():
                matches.append({"path": path_part, "matched_pattern": pattern})
                break
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "matches": matches[:500],
        "match_count": len(matches),
        "underlying_tool": "sleuthkit.fls",
        "raw_output_path": result.raw_output_path,
    }
