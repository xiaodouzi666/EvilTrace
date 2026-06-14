from __future__ import annotations

from typing import Any


def artifact_audit_ids(artifacts: list[dict[str, Any]]) -> list[str]:
    return sorted({artifact.get("audit_id", "") for artifact in artifacts if artifact.get("audit_id")})


def provenance_complete(artifact: dict[str, Any]) -> bool:
    required = ["artifact_id", "source_path", "source_sha256", "mcp_tool", "audit_id"]
    return all(bool(artifact.get(key)) for key in required)

