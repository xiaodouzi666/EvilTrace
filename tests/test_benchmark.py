from __future__ import annotations

from eviltrace.validators.benchmark import compute_metrics


def _final(unsupported=0, indicators=None):
    return {
        "finding_id": "finding-0002",
        "status": "confirmed",
        "audit_ids": ["audit-000002"],
        "artifacts": [{"artifact_id": "artifact-0001", "source_path": "p", "source_sha256": "a" * 64, "mcp_tool": "pcap_dns_queries", "audit_id": "audit-000002"}],
        "entities": {"network_indicators": indicators or []},
        "validation": {"unsupported_claims": ["x"] * unsupported},
    }


def _rejected():
    return {"finding_id": "finding-0001", "status": "rejected", "validation": {"unsupported_claims": ["overclaim:exfiltration_without_direct_support"]}}


def test_hallucination_rate_never_exceeds_one() -> None:
    findings = [_final(unsupported=3)]  # one finding carrying several unsupported claims
    metrics = compute_metrics(findings)
    assert 0.0 <= metrics["hallucination_rate"] <= 1.0
    assert metrics["hallucination_rate"] == 1.0


def test_clean_final_findings_have_zero_hallucination() -> None:
    metrics = compute_metrics([_final(), _rejected()])
    assert metrics["hallucination_rate"] == 0.0
    assert metrics["self_correction_success"] == 1.0
    assert metrics["finding_precision"] == 1.0
    assert metrics["provenance_completeness"] == 1.0


def test_artifact_recall_computed_from_expected_indicators() -> None:
    findings = [_final(indicators=["google.com", "www.netbsd.org"])]
    expected = {"expected_indicators": ["google.com", "www.netbsd.org", "missing.example"]}
    metrics = compute_metrics(findings, expected)
    assert metrics["artifact_recall"] == round(2 / 3, 3)


def test_artifact_recall_not_measured_without_ground_truth() -> None:
    metrics = compute_metrics([_final()])
    assert metrics["artifact_recall"] == "not_measured_without_known_answer_case"


def test_evidence_integrity_metric_present_and_in_range() -> None:
    integrity = {"status": "passed", "checked_count": 4, "changed_files": [], "missing_files": []}
    metrics = compute_metrics([_final()], None, integrity)
    assert metrics["evidence_integrity"] == 1.0
    integrity2 = {"status": "failed", "checked_count": 4, "changed_files": [{"path": "x"}], "missing_files": []}
    assert compute_metrics([_final()], None, integrity2)["evidence_integrity"] == 0.75
