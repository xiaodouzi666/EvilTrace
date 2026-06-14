from __future__ import annotations

import json
from pathlib import Path

import pytest

from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.logging.audit_logger import AuditLogger
from eviltrace.logging.run_logger import RunLogger
from eviltrace.mcp_server.command_runner import CommandRunner
from eviltrace.mcp_server.guardrails import GuardrailConfig
from eviltrace.mcp_server.tool_registry import TOOL_NAMES
from eviltrace.mcp_server.tools.case_tools import case_register
from eviltrace.mcp_server.tools.common import ToolContext
from eviltrace.mcp_server.tools.evidence_tools import evidence_verify_integrity
from eviltrace.mcp_server.tools.network_tools import pcap_dns_queries, pcap_summary


def _context(workspace: Path) -> ToolContext:
    paths = WorkspacePaths.from_workspace(workspace)
    paths.ensure()
    logger = AuditLogger(paths.logs_dir / "mcp.jsonl", run_id="mcp-test", case_id="sample")
    provenance = RunLogger(paths, "sample")
    guardrails = GuardrailConfig(paths)
    runner = CommandRunner(guardrails, logger, provenance)
    return ToolContext(paths, logger, guardrails, runner, provenance=provenance)


def test_typed_tools_emit_unique_audit_ids_and_provenance(workspace_with_pcap: Path) -> None:
    ctx = _context(workspace_with_pcap)
    pcap = "cases/sample/dns.cap"
    case = case_register(ctx, case_id="sample", case_root="cases/sample", case_type="network")
    summary = pcap_summary(ctx, pcap_path=pcap)
    dns = pcap_dns_queries(ctx, pcap_path=pcap)

    audit_ids = [case["audit_id"], summary["audit_id"], dns["audit_id"]]
    assert len(set(audit_ids)) == len(audit_ids), "tool calls must have unique audit_ids"
    assert dns["status"] == "success" and dns["queries"], "real PCAP must yield DNS queries via builtin parser"

    # every tool call wrote a JSONL audit event and a provenance record
    log_lines = (ctx.paths.logs_dir / "mcp.jsonl").read_text(encoding="utf-8").splitlines()
    logged_audit_ids = {json.loads(l).get("audit_id") for l in log_lines if l.strip()}
    assert set(audit_ids).issubset(logged_audit_ids)
    prov = [json.loads(l) for l in ctx.provenance.provenance_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert {r["audit_id"] for r in prov} >= set(audit_ids)


def test_tool_names_match_server_dispatch() -> None:
    from eviltrace.mcp_server import server

    src = Path(server.__file__).read_text(encoding="utf-8")
    # every registered tool name should be invoked by a wrapper in the server module
    for name in TOOL_NAMES:
        assert f"{name}(build_context" in src, f"{name} is in TOOL_NAMES but not wired in server.py"


def test_evidence_verify_integrity_passes_for_unmodified_evidence(workspace_with_pcap: Path) -> None:
    ctx = _context(workspace_with_pcap)
    case_register(ctx, case_id="sample", case_root="cases/sample", case_type="network")
    result = evidence_verify_integrity(ctx, manifest=ctx.manifest)
    assert result["integrity_status"] == "passed"
    assert result["changed_files"] == [] and result["missing_files"] == []


def test_missing_pcap_degrades_to_needs_review(workspace_with_pcap: Path) -> None:
    ctx = _context(workspace_with_pcap)
    result = pcap_summary(ctx, pcap_path="cases/sample/does-not-exist.pcap")
    assert result["status"] == "needs_review"
