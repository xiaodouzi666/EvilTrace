from eviltrace.agent.self_correction import SelfCorrectionEngine
from eviltrace.findings.model import Finding
from eviltrace.validators.finding_validator import FindingValidator
from eviltrace.graph.model import EvidenceGraph


def test_rejects_unsupported_candidate() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Unsupported incident claim",
        category="case_intake",
        status="candidate",
        confidence=0.2,
        summary="No evidence is available.",
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    decision = SelfCorrectionEngine().decide(finding, outcome)
    assert decision.action == "reject_finding"
    assert decision.new_status == "rejected"


def test_downgrades_single_source_claim_and_targets_stream() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Suspicious network metadata",
        category="network",
        status="confirmed",
        confidence=0.62,
        summary="One weak artifact was treated as confirmed.",
        artifacts=[
            {
                "artifact_id": "artifact-0001",
                "artifact_type": "pcap_summary",
                "source_path": "cases/demo/capture.pcap",
                "source_sha256": "a" * 64,
                "tool": "tshark",
                "mcp_tool": "pcap_summary",
                "audit_id": "audit-000001",
            }
        ],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    decision = SelfCorrectionEngine().decide(finding, outcome)
    assert decision.action == "downgrade_to_inferred"
    # a summary-only claim is corroborated by extracting the actual DNS queries
    assert decision.targeted_replan["tool"] == "pcap_dns_queries"


def test_needs_review_targets_replan_then_finalizes_at_budget() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Binary was executed on the host",
        category="endpoint",
        status="inferred",
        confidence=0.6,
        summary="The sample was executed but only a network artifact exists.",
        artifacts=[
            {
                "artifact_id": "artifact-0001",
                "artifact_type": "pcap_summary",
                "source_path": "cases/demo/capture.pcap",
                "source_sha256": "a" * 64,
                "tool": "tshark",
                "mcp_tool": "pcap_summary",
                "audit_id": "audit-000001",
            }
        ],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "needs_review"
    mid = SelfCorrectionEngine().decide(finding, outcome, max_iterations_reached=False)
    assert mid.action == "targeted_replan"
    end = SelfCorrectionEngine().decide(finding, outcome, max_iterations_reached=True)
    assert end.action == "finalize_with_limitations"


def test_alternate_tool_decision_for_recoverable_failure() -> None:
    engine = SelfCorrectionEngine()
    recoverable = engine.decide_tool_failure(tool="pcap_http_objects", status="needs_review", reason="requires tshark")
    assert recoverable.action == "alternate_tool"
    assert recoverable.targeted_replan["tool"] == "pcap_follow_stream"
    unrecoverable = engine.decide_tool_failure(tool="windows_evtx_query", status="tool_missing", reason="evtx_dump missing")
    assert unrecoverable.action == "finalize_with_limitations"


def test_rejects_exfiltration_overclaim() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Possible exfiltration",
        category="network",
        status="confirmed",
        confidence=0.62,
        summary="Exfiltration language from one weak artifact.",
        artifacts=[
            {
                "artifact_id": "artifact-0001",
                "artifact_type": "pcap_summary",
                "source_path": "cases/demo/capture.pcap",
                "source_sha256": "a" * 64,
                "tool": "tshark",
                "mcp_tool": "pcap_summary",
                "audit_id": "audit-000001",
            }
        ],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    decision = SelfCorrectionEngine().decide(finding, outcome)
    assert decision.action == "reject_finding"
    assert decision.new_status == "rejected"

