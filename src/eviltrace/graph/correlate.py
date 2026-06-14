from __future__ import annotations

from typing import Any

from .model import EvidenceGraph


def add_case_manifest(graph: EvidenceGraph, manifest: dict[str, Any]) -> None:
    case_id = manifest["case_id"]
    case_node = f"case-{case_id}"
    graph.add_node(case_node, "Case", case_id=case_id, case_type=manifest.get("case_type"))
    for row in manifest.get("evidence", []):
        evidence_node = row["evidence_id"]
        graph.add_node(
            evidence_node,
            "EvidenceFile",
            path=row["path"],
            sha256=row["sha256"],
            detected_type=row.get("detected_type"),
            size_bytes=row.get("size_bytes"),
        )
        graph.add_edge(case_node, evidence_node, "CONTAINS")


def add_tool_execution(graph: EvidenceGraph, audit_id: str, mcp_tool: str, **properties: Any) -> str:
    node_id = f"tool-{audit_id}"
    graph.add_node(node_id, "ToolExecution", audit_id=audit_id, mcp_tool=mcp_tool, **properties)
    return node_id


_INDICATOR_NODE_TYPE = {
    "dns_query": "DNSQuery",
    "http_object": "HTTPObject",
}


def add_network_artifact(graph: EvidenceGraph, artifact: dict[str, Any]) -> None:
    artifact_id = artifact["artifact_id"]
    graph.add_node(
        artifact_id,
        "Artifact",
        artifact_type=artifact.get("artifact_type"),
        source_path=artifact.get("source_path"),
        source_sha256=artifact.get("source_sha256"),
        mcp_tool=artifact.get("mcp_tool"),
        audit_id=artifact.get("audit_id"),
        raw_output_path=artifact.get("raw_output_path"),
    )

    # Artifact -PRODUCED_BY-> ToolExecution: every artifact traces to the tool execution.
    if artifact.get("audit_id"):
        tool_node = add_tool_execution(graph, artifact["audit_id"], artifact.get("mcp_tool", "unknown"))
        graph.add_edge(artifact_id, tool_node, "PRODUCED_BY")

    # Artifact -OBSERVED_IN-> EvidenceFile: resolve the path to the real EvidenceFile node id
    # (falls back to creating one keyed on path if the manifest was not loaded into the graph).
    source_path = artifact.get("source_path")
    if source_path:
        evidence_node = graph.evidence_node_for_path(source_path)
        if evidence_node is None:
            evidence_node = source_path
            graph.add_node(evidence_node, "EvidenceFile", path=source_path)
        graph.add_edge(artifact_id, evidence_node, "OBSERVED_IN")

    summary = artifact.get("summary", {})
    for host in summary.get("hosts", []):
        host_id = f"host-{host}"
        graph.add_node(host_id, "Host", ip=host)
        graph.add_edge(host_id, artifact_id, "OBSERVED_IN")

    indicator_type = _INDICATOR_NODE_TYPE.get(artifact.get("artifact_type"), "NetworkSession")
    for indicator in summary.get("network_indicators", []):
        indicator_id = f"indicator-{indicator}"
        graph.add_node(indicator_id, indicator_type, indicator=indicator)
        graph.add_edge(indicator_id, artifact_id, "OBSERVED_IN")


def link_corroborations(graph: EvidenceGraph) -> None:
    """Add CORROBORATES edges between artifacts that observe the same indicator/host."""
    observers: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge["type"] == "OBSERVED_IN":
            source = edge["source"]
            target = edge["target"]
            if source.startswith(("indicator-", "host-")) and target.startswith("artifact-"):
                observers.setdefault(source, []).append(target)
    for artifacts in observers.values():
        unique = sorted(set(artifacts))
        for i in range(len(unique)):
            for j in range(i + 1, len(unique)):
                graph.add_edge(unique[i], unique[j], "CORROBORATES")


def add_finding(graph: EvidenceGraph, finding: dict[str, Any]) -> None:
    finding_id = finding["finding_id"]
    graph.add_node(
        finding_id,
        "Finding",
        status=finding.get("status"),
        confidence=finding.get("confidence"),
        title=finding.get("title"),
    )
    for artifact in finding.get("artifacts", []):
        graph.add_edge(artifact["artifact_id"], finding_id, "SUPPORTS_FINDING")

    contradicted_by = finding.get("validation", {}).get("contradicted_by", [])
    for marker in contradicted_by:
        contradiction_node = f"contradiction-{marker}"
        graph.add_node(contradiction_node, "Contradiction", marker=marker)
        graph.add_edge(contradiction_node, finding_id, "CONTRADICTS")
