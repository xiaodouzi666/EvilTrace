from eviltrace.findings.model import Finding
from eviltrace.graph.model import EvidenceGraph
from eviltrace.validators.finding_validator import FindingValidator


def artifact(artifact_type: str = "pcap_summary") -> dict:
    return {
        "artifact_id": "artifact-0001",
        "artifact_type": artifact_type,
        "source_path": "cases/demo/capture.pcap",
        "source_sha256": "a" * 64,
        "tool": "tshark",
        "mcp_tool": "pcap_summary",
        "audit_id": "audit-000001",
        "raw_output_path": "artifacts/raw/tool-outputs/audit-000001.txt",
    }


def test_rejects_finding_without_artifacts() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Unsupported claim",
        category="network",
        status="candidate",
        confidence=0.4,
        summary="No artifact supports this claim.",
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "rejected"
    assert "finding_has_no_artifacts" in outcome.unsupported_claims


def test_downgrades_single_source_confirmed_claim() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Suspicious network metadata",
        category="network",
        status="confirmed",
        confidence=0.7,
        summary="One weak artifact was treated as confirmed.",
        artifacts=[artifact("pcap_summary")],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "inferred"
    assert "single_source_overclaim" in outcome.unsupported_claims


def test_rejects_exfiltration_without_direct_support() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Possible exfiltration",
        category="network",
        status="confirmed",
        confidence=0.7,
        summary="Exfiltration was claimed from one weak artifact.",
        artifacts=[artifact("pcap_summary")],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "rejected"
    assert "overclaim:exfiltration_without_direct_support" in outcome.unsupported_claims


def test_confirms_strong_artifact() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Suspicious stream content",
        category="network",
        status="confirmed",
        confidence=0.8,
        summary="A reconstructed stream provides direct support.",
        artifacts=[artifact("pcap_stream")],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "confirmed"
    assert outcome.unsupported_claims == []

