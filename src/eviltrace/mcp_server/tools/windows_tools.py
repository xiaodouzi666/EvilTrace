from __future__ import annotations

from .common import ToolContext, structured_tool_event, workspace_path


def windows_evtx_query(ctx: ToolContext, *, evtx_path: str, event_ids: list[int] | None = None, time_range: dict | None = None) -> dict:
    resolved = workspace_path(ctx.paths, evtx_path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="windows_evtx_query",
            input_data={"evtx_path": evtx_path, "event_ids": event_ids or [], "time_range": time_range or {}},
            output={"events": [], "reason": "EVTX path does not exist"},
            status="needs_review",
        )
    result = ctx.runner.run(["evtx_dump", str(resolved)], mcp_tool="windows_evtx_query", input_data={"evtx_path": evtx_path}, iteration=ctx.iteration)
    output = {"audit_id": result.audit_id, "status": result.status, "events": [], "raw_output_path": result.raw_output_path}
    if result.status == "tool_missing":
        output["fallback_reason"] = "evtx_dump is not installed; EVTX parsing is unavailable on this host."
    return output


def windows_prefetch_summary(ctx: ToolContext, *, prefetch_dir: str) -> dict:
    resolved = workspace_path(ctx.paths, prefetch_dir)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="windows_prefetch_summary",
            input_data={"prefetch_dir": prefetch_dir},
            output={"executions": [], "reason": "Prefetch directory does not exist"},
            status="needs_review",
        )
    executions = [{"executable": path.name.split("-")[0], "run_count": None, "last_run": None, "source_file": path.name} for path in sorted(resolved.glob("*.pf"))]
    return structured_tool_event(
        ctx,
        mcp_tool="windows_prefetch_summary",
        input_data={"prefetch_dir": prefetch_dir},
        output={
            "executions": executions,
            "depth": "filename_enumeration_only",
            "note": "Run counts and last-run timestamps are not parsed from the prefetch binary format; only filenames are enumerated. Downstream findings must not assert execution counts/timestamps from this artifact.",
        },
        status="success",
    )


def windows_usb_history(ctx: ToolContext, *, system_hive: str, software_hive: str | None = None) -> dict:
    return structured_tool_event(
        ctx,
        mcp_tool="windows_usb_history",
        input_data={"system_hive": system_hive, "software_hive": software_hive},
        output={"usb_devices": [], "reason": "Registry hive parsing requires validated local hives and reglookup support."},
        status="needs_review",
    )


def windows_run_keys(ctx: ToolContext, *, software_hive: str | None = None, ntuser_hives: list[str] | None = None) -> dict:
    return structured_tool_event(
        ctx,
        mcp_tool="windows_run_keys",
        input_data={"software_hive": software_hive, "ntuser_hives": ntuser_hives or []},
        output={"run_keys": [], "reason": "Run key parsing requires validated local hives and reglookup support."},
        status="needs_review",
    )

