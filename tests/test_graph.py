from __future__ import annotations

from eviltrace.graph.correlate import add_case_manifest, add_finding, add_network_artifact, link_corroborations
from eviltrace.graph.model import EvidenceGraph


def _manifest():
    return {
        "case_id": "sample",
        "case_type": "network",
        "evidence": [{"evidence_id": "ev-0001", "path": "cases/sample/dns.cap", "sha256": "a" * 64, "detected_type": "pcap"}],
    }


def _artifact(artifact_id, audit_id, atype="dns_query", indicators=None):
    return {
        "artifact_id": artifact_id,
        "artifact_type": atype,
        "source_path": "cases/sample/dns.cap",
        "source_sha256": "a" * 64,
        "mcp_tool": "pcap_dns_queries",
        "audit_id": audit_id,
        "summary": {"network_indicators": indicators or []},
    }


def test_artifact_produced_by_tool_execution_and_observed_in_evidence() -> None:
    g = EvidenceGraph()
    add_case_manifest(g, _manifest())
    add_network_artifact(g, _artifact("artifact-0001", "audit-000002", indicators=["google.com"]))

    node_types = {n["id"]: n["type"] for n in g.to_dict()["nodes"]}
    edges = {(e["source"], e["target"], e["type"]) for e in g.edges}

    # PRODUCED_BY -> ToolExecution
    assert node_types.get("tool-audit-000002") == "ToolExecution"
    assert ("artifact-0001", "tool-audit-000002", "PRODUCED_BY") in edges
    # OBSERVED_IN resolves to the real EvidenceFile node id, not a dangling path string
    assert ("artifact-0001", "ev-0001", "OBSERVED_IN") in edges
    # DNS indicator typed as DNSQuery
    assert node_types.get("indicator-google.com") == "DNSQuery"
    # no dangling edges
    ids = set(node_types)
    assert all(e["source"] in ids and e["target"] in ids for e in g.edges)


def test_corroboration_links_artifacts_sharing_an_indicator() -> None:
    g = EvidenceGraph()
    add_case_manifest(g, _manifest())
    add_network_artifact(g, _artifact("artifact-0001", "audit-000002", indicators=["google.com"]))
    add_network_artifact(g, _artifact("artifact-0002", "audit-000003", atype="pcap_summary", indicators=["google.com"]))
    link_corroborations(g)
    corro = {(e["source"], e["target"], e["type"]) for e in g.edges if e["type"] == "CORROBORATES"}
    assert ("artifact-0001", "artifact-0002", "CORROBORATES") in corro


def test_finding_supports_edge_and_contradiction_node() -> None:
    g = EvidenceGraph()
    add_case_manifest(g, _manifest())
    add_network_artifact(g, _artifact("artifact-0001", "audit-000002"))
    finding = {
        "finding_id": "finding-0001",
        "status": "needs_review",
        "confidence": 0.4,
        "title": "x",
        "artifacts": [_artifact("artifact-0001", "audit-000002")],
        "validation": {"contradicted_by": ["execution_claim_without_execution_artifact"]},
    }
    add_finding(g, finding)
    edges = {(e["source"], e["target"], e["type"]) for e in g.edges}
    assert ("artifact-0001", "finding-0001", "SUPPORTS_FINDING") in edges
    assert ("contradiction-execution_claim_without_execution_artifact", "finding-0001", "CONTRADICTS") in edges


def test_add_edge_dedups_on_source_target_type() -> None:
    g = EvidenceGraph()
    g.add_edge("a", "b", "X", weight=1)
    g.add_edge("a", "b", "X", weight=2)
    xs = [e for e in g.edges if e["type"] == "X"]
    assert len(xs) == 1
    assert xs[0]["properties"]["weight"] == 2
