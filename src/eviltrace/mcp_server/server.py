from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.logging.audit_logger import AuditLogger
from eviltrace.logging.run_logger import RunLogger
from eviltrace.mcp_server.command_runner import CommandRunner
from eviltrace.mcp_server.guardrails import GuardrailConfig
from eviltrace.mcp_server.tool_registry import TOOL_NAMES
from eviltrace.mcp_server.tools.case_tools import case_manifest, case_register
from eviltrace.mcp_server.tools.common import ToolContext
from eviltrace.mcp_server.tools.disk_tools import disk_image_info, disk_search_files, disk_timeline
from eviltrace.mcp_server.tools.evidence_tools import evidence_hash, evidence_verify_integrity
from eviltrace.mcp_server.tools.finding_tools import finding_propose, finding_validate
from eviltrace.mcp_server.tools.graph_tools import graph_export
from eviltrace.mcp_server.tools.memory_tools import memory_volatility_plugin
from eviltrace.mcp_server.tools.network_tools import pcap_dns_queries, pcap_follow_stream, pcap_http_objects, pcap_summary
from eviltrace.mcp_server.tools.validation_tools import validate_manifest_integrity
from eviltrace.mcp_server.tools.windows_tools import windows_evtx_query, windows_prefetch_summary, windows_run_keys, windows_usb_history


_CONTEXTS: dict[str, ToolContext] = {}


def build_context(case_id: str = "mcp-session") -> ToolContext:
    """Return a per-case ToolContext, cached for the life of the server process so
    audit/event counters and the provenance ledger persist across tool calls
    (one stdio session may invoke many tools for the same case)."""
    if case_id in _CONTEXTS:
        return _CONTEXTS[case_id]
    workspace = os.environ.get("EVILTRACE_WORKSPACE", ".")
    evidence_root = os.environ.get("EVILTRACE_EVIDENCE_ROOT", "./cases")
    artifact_root = os.environ.get("EVILTRACE_ARTIFACT_ROOT", "./artifacts")
    paths = WorkspacePaths.from_workspace(workspace, evidence_root, artifact_root)
    paths.ensure()
    logger = AuditLogger(paths.logs_dir / f"{case_id}.mcp.jsonl", run_id="mcp-session", case_id=case_id)
    provenance = RunLogger(paths, case_id)
    guardrails = GuardrailConfig(paths)
    runner = CommandRunner(guardrails, logger, provenance)
    ctx = ToolContext(paths, logger, guardrails, runner, provenance=provenance)
    _CONTEXTS[case_id] = ctx
    return ctx


def _run_fallback() -> None:
    print(json.dumps({"server": "eviltrace", "mode": "fallback", "tools": TOOL_NAMES}, indent=2))


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
    except Exception:
        _run_fallback()
        return

    mcp = FastMCP("eviltrace")

    @mcp.tool()
    def case_register_tool(case_id: str, case_root: str, case_type: str = "unknown", description: str = "") -> dict[str, Any]:
        return case_register(build_context(case_id), case_id=case_id, case_root=case_root, case_type=case_type, description=description)

    @mcp.tool()
    def case_manifest_tool(case_id: str, case_root: str) -> dict[str, Any]:
        return case_manifest(build_context(case_id), case_id=case_id, case_root=case_root)

    @mcp.tool()
    def evidence_hash_tool(case_id: str, path: str, algorithm: str = "sha256") -> dict[str, Any]:
        return evidence_hash(build_context(case_id), path=path, algorithm=algorithm)

    @mcp.tool()
    def evidence_verify_integrity_tool(case_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return evidence_verify_integrity(build_context(case_id), manifest=manifest)

    @mcp.tool()
    def pcap_summary_tool(case_id: str, pcap_path: str, limit: int = 200) -> dict[str, Any]:
        return pcap_summary(build_context(case_id), pcap_path=pcap_path, limit=limit)

    @mcp.tool()
    def pcap_dns_queries_tool(case_id: str, pcap_path: str, domain_filter: str | None = None) -> dict[str, Any]:
        return pcap_dns_queries(build_context(case_id), pcap_path=pcap_path, domain_filter=domain_filter)

    @mcp.tool()
    def pcap_http_objects_tool(case_id: str, pcap_path: str, export_dir: str = "artifacts/raw/http-objects") -> dict[str, Any]:
        return pcap_http_objects(build_context(case_id), pcap_path=pcap_path, export_dir=export_dir)

    @mcp.tool()
    def pcap_follow_stream_tool(case_id: str, pcap_path: str, stream_id: int, protocol: str = "tcp") -> dict[str, Any]:
        return pcap_follow_stream(build_context(case_id), pcap_path=pcap_path, stream_id=stream_id, protocol=protocol)

    @mcp.tool()
    def disk_image_info_tool(case_id: str, image_path: str) -> dict[str, Any]:
        return disk_image_info(build_context(case_id), image_path=image_path)

    @mcp.tool()
    def disk_timeline_tool(case_id: str, image_path: str, partition_offset: int | None = None) -> dict[str, Any]:
        return disk_timeline(build_context(case_id), image_path=image_path, partition_offset=partition_offset)

    @mcp.tool()
    def disk_search_files_tool(case_id: str, image_path: str, patterns: list[str] | None = None, partition_offset: int | None = None) -> dict[str, Any]:
        return disk_search_files(build_context(case_id), image_path=image_path, partition_offset=partition_offset, patterns=patterns)

    @mcp.tool()
    def windows_evtx_query_tool(case_id: str, evtx_path: str, event_ids: list[int] | None = None, time_range: dict | None = None) -> dict[str, Any]:
        return windows_evtx_query(build_context(case_id), evtx_path=evtx_path, event_ids=event_ids, time_range=time_range)

    @mcp.tool()
    def windows_prefetch_summary_tool(case_id: str, prefetch_dir: str) -> dict[str, Any]:
        return windows_prefetch_summary(build_context(case_id), prefetch_dir=prefetch_dir)

    @mcp.tool()
    def windows_usb_history_tool(case_id: str, system_hive: str, software_hive: str | None = None) -> dict[str, Any]:
        return windows_usb_history(build_context(case_id), system_hive=system_hive, software_hive=software_hive)

    @mcp.tool()
    def windows_run_keys_tool(case_id: str, software_hive: str | None = None, ntuser_hives: list[str] | None = None) -> dict[str, Any]:
        return windows_run_keys(build_context(case_id), software_hive=software_hive, ntuser_hives=ntuser_hives)

    @mcp.tool()
    def memory_volatility_plugin_tool(case_id: str, memory_path: str, plugin: str, args: dict | None = None) -> dict[str, Any]:
        return memory_volatility_plugin(build_context(case_id), memory_path=memory_path, plugin=plugin, args=args)

    @mcp.tool()
    def finding_propose_tool(case_id: str, title: str, summary: str, category: str, supporting_artifacts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return finding_propose(build_context(case_id), case_id=case_id, title=title, summary=summary, category=category, supporting_artifacts=supporting_artifacts)

    @mcp.tool()
    def finding_validate_tool(case_id: str, finding_id: str, required_corroboration: int = 2) -> dict[str, Any]:
        return finding_validate(build_context(case_id), case_id=case_id, finding_id=finding_id, required_corroboration=required_corroboration)

    @mcp.tool()
    def graph_export_tool(case_id: str, graph: dict[str, Any], output_path: str) -> dict[str, Any]:
        return graph_export(build_context(case_id), graph=graph, output_path=output_path)

    @mcp.tool()
    def validate_manifest_integrity_tool(case_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        return validate_manifest_integrity(build_context(case_id), manifest=manifest)

    mcp.run()


if __name__ == "__main__":
    main()

