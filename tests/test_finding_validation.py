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


def test_contradiction_execution_claim_without_artifact_is_needs_review() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Binary was executed on the host",
        category="endpoint",
        status="inferred",
        confidence=0.6,
        summary="The sample was executed but only a network artifact exists.",
        artifacts=[artifact("pcap_summary")],
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert "execution_claim_without_execution_artifact" in outcome.contradicted_by
    assert outcome.recommended_status == "needs_review"


def test_hallucinated_entity_is_rejected() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Host activity",
        category="network",
        status="inferred",
        confidence=0.6,
        summary="A host not present in the evidence graph is referenced.",
        artifacts=[artifact("pcap_summary")],
        entities={"hosts": ["10.0.0.250"], "users": [], "processes": [], "files": [], "network_indicators": []},
    )
    outcome = FindingValidator().validate(finding, EvidenceGraph())
    assert outcome.recommended_status == "rejected"
    assert outcome.hallucination_check == "failed"
    assert "entity_not_in_graph:10.0.0.250" in outcome.unsupported_claims


def test_manifest_sha256_mismatch_is_rejected() -> None:
    finding = Finding(
        finding_id="finding-0001",
        case_id="demo",
        title="Network metadata",
        category="network",
        status="inferred",
        confidence=0.6,
        summary="Artifact cites a sha256 that does not match the manifest.",
        artifacts=[artifact("pcap_summary")],  # source_sha256 = 'a'*64
    )
    manifest = {"case_id": "demo", "evidence": [{"path": "cases/demo/capture.pcap", "sha256": "b" * 64}]}
    outcome = FindingValidator().validate(finding, EvidenceGraph(), manifest)
    assert outcome.recommended_status == "rejected"
    assert "artifact-0001:source_sha256_mismatch" in outcome.unsupported_claims

