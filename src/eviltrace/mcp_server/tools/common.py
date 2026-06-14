from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any

from eviltrace.evidence.hashing import sha256_text
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.findings.provenance import build_provenance_record
from eviltrace.logging.audit_logger import AuditLogger, utc_now
from eviltrace.logging.run_logger import RunLogger
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
    provenance: RunLogger | None = None


def structured_tool_event(
    ctx: ToolContext,
    *,
    mcp_tool: str,
    input_data: dict[str, Any],
    output: dict[str, Any],
    status: str,
    raw_suffix: str = "json",
) -> dict[str, Any]:
    started = time.monotonic()
    audit_id = ctx.logger.next_audit_id()
    raw_path = ctx.paths.tool_outputs_dir / f"{audit_id}.{raw_suffix}"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if raw_suffix == "json":
        raw_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        raw_path.write_text(str(output) + "\n", encoding="utf-8")
    underlying_tool = str(output.get("underlying_tool") or "python.structured")
    ctx.logger.log_event(
        "tool_call",
        iteration=ctx.iteration,
        input_data=input_data,
        output_summary={"structured": True, "command_redacted": underlying_tool, "operation": mcp_tool},
        audit_id=audit_id,
        status="started",
        mcp_tool=mcp_tool,
    )
    stdout_sha256 = sha256_text(raw_path.read_text(encoding="utf-8"))
    stderr_sha256 = sha256_text("")
    duration_ms = int((time.monotonic() - started) * 1000)
    exit_code = 0 if status == "success" else 1
    rel_raw = ctx.paths.relative_to_workspace(raw_path)
    ctx.logger.log_event(
        "tool_result",
        iteration=ctx.iteration,
        input_data=input_data,
        output_summary={
            "raw_output_path": rel_raw,
            "stdout_sha256": stdout_sha256,
            "stderr_sha256": stderr_sha256,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        },
        audit_id=audit_id,
        status=status,
        mcp_tool=mcp_tool,
    )
    if ctx.provenance is not None:
        ctx.provenance.write_provenance(
            build_provenance_record(
                audit_id=audit_id,
                case_id=ctx.logger.case_id,
                mcp_tool=mcp_tool,
                tool_layer="mcp-builtin" if underlying_tool.startswith("python.") else "mcp-structured",
                timestamp_utc=utc_now(),
                stdout_sha256=stdout_sha256,
                stderr_sha256=stderr_sha256,
                exit_code=exit_code,
                duration_ms=duration_ms,
                source_path=str(output.get("source_path") or ""),
                source_sha256=str(output.get("source_sha256") or ""),
                underlying_tool=underlying_tool,
                command_redacted=underlying_tool,
                raw_output_path=rel_raw,
            )
        )
    output = dict(output)
    output.update({"audit_id": audit_id, "raw_output_path": rel_raw, "status": status})
    return output


def workspace_path(paths: WorkspacePaths, path: str | Path) -> Path:
    candidate = Path(path)
    return candidate.resolve() if candidate.is_absolute() else (paths.workspace / candidate).resolve()
