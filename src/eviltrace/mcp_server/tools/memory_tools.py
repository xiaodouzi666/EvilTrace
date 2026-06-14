from __future__ import annotations

from .common import ToolContext, structured_tool_event, workspace_path


ALLOWED_VOLATILITY_PLUGINS = {
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.malfind",
    "windows.dlllist",
}


def memory_volatility_plugin(ctx: ToolContext, *, memory_path: str, plugin: str, args: dict | None = None) -> dict:
    if plugin not in ALLOWED_VOLATILITY_PLUGINS:
        return structured_tool_event(
            ctx,
            mcp_tool="memory_volatility_plugin",
            input_data={"memory_path": memory_path, "plugin": plugin, "args": args or {}},
            output={"rows": [], "reason": "Volatility plugin is not allowlisted"},
            status="blocked",
        )
    resolved = workspace_path(ctx.paths, memory_path)
    if not resolved.exists():
        return structured_tool_event(
            ctx,
            mcp_tool="memory_volatility_plugin",
            input_data={"memory_path": memory_path, "plugin": plugin, "args": args or {}},
            output={"rows": [], "reason": "Memory image does not exist"},
            status="needs_review",
        )
    command = ["volatility3", "-f", str(resolved), plugin]
    for key, value in (args or {}).items():
        command.extend([f"--{key}", str(value)])
    result = ctx.runner.run(command, mcp_tool="memory_volatility_plugin", input_data={"memory_path": memory_path, "plugin": plugin}, iteration=ctx.iteration)
    output = {"audit_id": result.audit_id, "status": result.status, "plugin": plugin, "rows": [], "raw_output_path": result.raw_output_path}
    if result.status == "tool_missing":
        output["fallback_reason"] = "volatility3 is not installed; memory analysis is unavailable on this host."
    return output

