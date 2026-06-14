from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_json_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class AuditLogger:
    """Append-only JSONL audit logger used by the orchestrator and tool layer."""

    log_path: Path
    run_id: str
    case_id: str
    actor: str = "eviltrace-agent"
    _event_counter: int = field(default=0, init=False)
    _audit_counter: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def next_event_id(self) -> str:
        self._event_counter += 1
        return f"event-{self._event_counter:06d}"

    def next_audit_id(self) -> str:
        self._audit_counter += 1
        return f"audit-{self._audit_counter:06d}"

    def log_event(
        self,
        event_type: str,
        *,
        iteration: int = 0,
        input_data: dict[str, Any] | None = None,
        output_summary: dict[str, Any] | None = None,
        audit_id: str | None = None,
        token_usage: dict[str, int] | None = None,
        cost_usd: float = 0.0,
        status: str = "success",
        mcp_tool: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_id": self.next_event_id(),
            "run_id": self.run_id,
            "case_id": self.case_id,
            "iteration": iteration,
            "timestamp_utc": utc_now(),
            "event_type": event_type,
            "actor": self.actor,
            "mcp_tool": mcp_tool,
            "input": input_data or {},
            "output_summary": output_summary or {},
            "audit_id": audit_id,
            "token_usage": token_usage or {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "cost_usd": cost_usd,
            "status": status,
        }
        if extra:
            event.update(extra)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
        return event

