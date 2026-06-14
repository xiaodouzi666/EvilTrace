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


def test_audit_event_schema_rejects_malformed_event() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((SCHEMA_DIR / "audit_event.schema.json").read_text(encoding="utf-8"))
    bad = {"event_id": "event-000001"}  # missing all other required fields
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_finding_model_output_matches_finding_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    from eviltrace.findings.model import Finding

    resources = [(p.name, referencing.Resource.from_contents(json.loads(p.read_text(encoding="utf-8")))) for p in SCHEMA_DIR.glob("*.schema.json")]
    registry = referencing.Registry().with_resources(resources)
    schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="DNS activity",
        category="network",
        status="confirmed",
        confidence=0.86,
        summary="Observed DNS queries.",
        artifacts=[
            {
                "artifact_id": "artifact-0001",
                "artifact_type": "dns_query",
                "source_path": "cases/sample/dns.cap",
                "source_sha256": "a" * 64,
                "tool": "python.pcap_builtin",
                "mcp_tool": "pcap_dns_queries",
                "audit_id": "audit-000003",
                "raw_output_path": "artifacts/raw/tool-outputs/audit-000003.json",
            }
        ],
    )
    jsonschema.Draft202012Validator(schema, registry=registry).validate(finding.to_dict())

