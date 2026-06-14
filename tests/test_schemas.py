import json
from pathlib import Path

import pytest


SCHEMA_DIR = Path("src/eviltrace/schemas")


def test_all_schema_files_are_valid_json() -> None:
    for path in SCHEMA_DIR.glob("*.schema.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["$schema"].startswith("https://json-schema.org/")
        assert "title" in data


def test_audit_event_schema_accepts_sample() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMA_DIR / "audit_event.schema.json").read_text(encoding="utf-8"))
    sample = {
        "event_id": "event-000001",
        "run_id": "run-test",
        "case_id": "demo",
        "iteration": 1,
        "timestamp_utc": "2026-06-14T00:00:00Z",
        "event_type": "tool_call",
        "actor": "eviltrace-agent",
        "mcp_tool": "pcap_summary",
        "input": {},
        "output_summary": {},
        "audit_id": "audit-000001",
        "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        "cost_usd": 0.0,
        "status": "success",
    }
    jsonschema.validate(sample, schema)

