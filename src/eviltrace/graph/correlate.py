from __future__ import annotations

from typing import Any

from .model import EvidenceGraph


def add_case_manifest(graph: EvidenceGraph, manifest: dict[str, Any]) -> None:
    case_id = manifest["case_id"]
    graph.add_node(f"case-{case_id}", "Case", case_id=case_id, case_type=manifest.get("case_type"))
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
        graph.add_edge(f"case-{case_id}", evidence_node, "CONTAINS")


def add_network_artifact(graph: EvidenceGraph, artifact: dict[str, Any]) -> None:
    artifact_id = artifact["artifact_id"]
    graph.add_node(artifact_id, "Artifact", **artifact)
    if artifact.get("source_path"):
        graph.add_edge(artifact.get("source_path"), artifact_id, "OBSERVED_IN")
    summary = artifact.get("summary", {})
    for host in summary.get("hosts", []):
        host_id = f"host-{host}"
        graph.add_node(host_id, "Host", ip=host)
        graph.add_edge(host_id, artifact_id, "OBSERVED_IN")
    for indicator in summary.get("network_indicators", []):
        indicator_id = f"indicator-{indicator}"
        graph.add_node(indicator_id, "NetworkSession", indicator=indicator)
        graph.add_edge(indicator_id, artifact_id, "OBSERVED_IN")


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

