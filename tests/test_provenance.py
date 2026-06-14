from __future__ import annotations

import json
from pathlib import Path

import pytest

from eviltrace.agent.orchestrator import EvilTraceOrchestrator
from eviltrace.findings.provenance import artifact_audit_ids, build_provenance_record, provenance_complete


def _artifact(**overrides):
    base = {
        "artifact_id": "artifact-0001",
        "source_path": "cases/sample/dns.cap",
        "source_sha256": "a" * 64,
        "mcp_tool": "pcap_summary",
        "audit_id": "audit-000002",
    }
    base.update(overrides)
    return base


def test_provenance_complete_true_and_false() -> None:
    assert provenance_complete(_artifact()) is True
    assert provenance_complete(_artifact(audit_id="")) is False
    assert provenance_complete(_artifact(source_sha256="")) is False
    incomplete = _artifact()
    del incomplete["mcp_tool"]
    assert provenance_complete(incomplete) is False


def test_artifact_audit_ids_dedup_and_sort() -> None:
    arts = [_artifact(audit_id="audit-000003"), _artifact(audit_id="audit-000001"), _artifact(audit_id="audit-000001")]
    assert artifact_audit_ids(arts) == ["audit-000001", "audit-000003"]


def test_build_provenance_record_is_schema_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(Path("src/eviltrace/schemas/provenance.schema.json").read_text(encoding="utf-8"))
    record = build_provenance_record(
        audit_id="audit-000002",
        case_id="sample",
        mcp_tool="pcap_summary",
        tool_layer="mcp-builtin",
        timestamp_utc="2026-06-15T00:00:00Z",
        stdout_sha256="b" * 64,
        stderr_sha256="c" * 64,
        exit_code=0,
        duration_ms=12,
        source_path="cases/sample/dns.cap",
        source_sha256="a" * 64,
    )
    jsonschema.Draft202012Validator(schema).validate(record)


def test_end_to_end_provenance_chain(workspace_with_pcap: Path) -> None:
    result = EvilTraceOrchestrator(workspace=workspace_with_pcap).run(
        case_id="sample", case_root="cases/sample", profile="network-first", max_iterations=2
    )
    findings = json.loads((workspace_with_pcap / result["findings_path"]).read_text(encoding="utf-8"))
    graph = json.loads((workspace_with_pcap / result["graph_path"]).read_text(encoding="utf-8"))
    log_audit_ids = {
        json.loads(l).get("audit_id")
        for l in (workspace_with_pcap / result["log_path"]).read_text(encoding="utf-8").splitlines()
        if l.strip()
    }
    node_types = {n["id"]: n["type"] for n in graph["nodes"]}
    produced_by = {(e["source"], e["target"]) for e in graph["edges"] if e["type"] == "PRODUCED_BY"}

    assert findings["findings"], "the sample run must produce at least one final finding"
    for finding in findings["findings"]:
        assert finding["audit_ids"], "confirmed finding must carry audit_ids"
        # every finding audit_id resolves to a logged tool execution
        assert set(finding["audit_ids"]).issubset(log_audit_ids)
        for artifact in finding["artifacts"]:
            tool_node = f"tool-{artifact['audit_id']}"
            assert node_types.get(tool_node) == "ToolExecution"
            assert (artifact["artifact_id"], tool_node) in produced_by


def test_run_emits_provenance_ledger(workspace_with_pcap: Path) -> None:
    result = EvilTraceOrchestrator(workspace=workspace_with_pcap).run(
        case_id="sample", case_root="cases/sample", max_iterations=2
    )
    prov_path = workspace_with_pcap / result["provenance_path"]
    rows = [json.loads(l) for l in prov_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows and all(r.get("provenance_id") and r.get("audit_id") for r in rows)
