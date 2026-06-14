from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from eviltrace.evidence.hashing import sha256_text
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.logging.audit_logger import AuditLogger
from eviltrace.mcp_server.command_runner import CommandRunner
from eviltrace.mcp_server.guardrails import GuardrailConfig


@dataclass
class ToolContext:
    paths: WorkspacePaths
    logger: AuditLogger
    guardrails: GuardrailConfig
    runner: CommandRunner
    iteration: int = 0
    manifest: dict[str, Any] | None = None


def structured_tool_event(
    ctx: ToolContext,
    *,
    mcp_tool: str,
    input_data: dict[str, Any],
    output: dict[str, Any],
    status: str,
    raw_suffix: str = "json",
) -> dict[str, Any]:
    audit_id = ctx.logger.next_audit_id()
    raw_path = ctx.paths.tool_outputs_dir / f"{audit_id}.{raw_suffix}"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if raw_suffix == "json":
        raw_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        raw_path.write_text(str(output) + "\n", encoding="utf-8")
    ctx.logger.log_event(
        "tool_call",
        iteration=ctx.iteration,
        input_data=input_data,
        output_summary={"structured": True},
        audit_id=audit_id,
        status="started",
        mcp_tool=mcp_tool,
    )
    ctx.logger.log_event(
        "tool_result",
        iteration=ctx.iteration,
        input_data=input_data,
        output_summary={
            "raw_output_path": ctx.paths.relative_to_workspace(raw_path),
            "stdout_sha256": sha256_text(raw_path.read_text(encoding="utf-8")),
        },
        audit_id=audit_id,
        status=status,
        mcp_tool=mcp_tool,
    )
    output = dict(output)
    output.update({"audit_id": audit_id, "raw_output_path": ctx.paths.relative_to_workspace(raw_path), "status": status})
    return output


def workspace_path(paths: WorkspacePaths, path: str | Path) -> Path:
    candidate = Path(path)
    return candidate.resolve() if candidate.is_absolute() else (paths.workspace / candidate).resolve()

