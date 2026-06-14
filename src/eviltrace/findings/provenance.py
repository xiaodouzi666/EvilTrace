from __future__ import annotations

from typing import Any


def artifact_audit_ids(artifacts: list[dict[str, Any]]) -> list[str]:
    return sorted({artifact.get("audit_id", "") for artifact in artifacts if artifact.get("audit_id")})


def provenance_complete(artifact: dict[str, Any]) -> bool:
    required = ["artifact_id", "source_path", "source_sha256", "mcp_tool", "audit_id"]
    return all(bool(artifact.get(key)) for key in required)


_PROV_COUNTER = {"n": 0}


def _next_provenance_id() -> str:
    _PROV_COUNTER["n"] += 1
    return f"prov-{_PROV_COUNTER['n']:06d}"


def reset_provenance_ids() -> None:
    _PROV_COUNTER["n"] = 0


def build_provenance_record(
    *,
    audit_id: str,
    case_id: str,
    mcp_tool: str,
    tool_layer: str,
    timestamp_utc: str,
    stdout_sha256: str,
    stderr_sha256: str,
    exit_code: int,
    duration_ms: int,
    source_path: str = "",
    source_sha256: str = "",
    evidence_id: str | None = None,
    underlying_tool: str = "",
    command_template: str = "",
    command_redacted: str = "",
    raw_output_path: str | None = None,
) -> dict[str, Any]:
    """Build one ``provenance.schema.json``-conformant record for a tool execution.

    Required-field defaults are empty strings (schema-valid) when a value is not
    applicable, so every tool execution produces a record even when it has no
    single source file (e.g. case_register, graph_export)."""
    record: dict[str, Any] = {
        "provenance_id": _next_provenance_id(),
        "audit_id": audit_id,
        "case_id": case_id,
        "source_path": source_path or "",
        "source_sha256": source_sha256 or "",
        "tool_layer": tool_layer,
        "mcp_tool": mcp_tool,
        "underlying_tool": underlying_tool or "",
        "command_template": command_template or "",
        "command_redacted": command_redacted or "",
        "timestamp_utc": timestamp_utc,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "exit_code": int(exit_code),
        "duration_ms": int(duration_ms),
    }
    if evidence_id:
        record["evidence_id"] = evidence_id
    if raw_output_path:
        record["raw_output_path"] = raw_output_path
    return record
