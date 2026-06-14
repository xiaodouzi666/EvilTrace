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
    assert decision.targeted_replan["tool"] == "pcap_follow_stream"


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

