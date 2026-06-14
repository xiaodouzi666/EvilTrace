from __future__ import annotations

from typing import Any


def compute_metrics(findings: list[dict[str, Any]], expected: dict[str, Any] | None = None) -> dict[str, Any]:
    expected = expected or {}
    asserted = [finding for finding in findings if finding.get("status") in {"confirmed", "inferred"}]
    supported = [finding for finding in asserted if finding.get("artifacts")]
    rejected = [finding for finding in findings if finding.get("status") == "rejected"]
    precision = len(supported) / len(asserted) if asserted else 1.0
    provenance = sum(1 for finding in asserted if finding.get("audit_ids")) / len(asserted) if asserted else 1.0
    unsupported_final_claims = sum(len(finding.get("validation", {}).get("unsupported_claims", [])) for finding in asserted)
    unsupported_rejected_claims = sum(len(finding.get("validation", {}).get("unsupported_claims", [])) for finding in rejected)
    final_claim_count = max(len(asserted), 1)
    corrected = sum(1 for finding in rejected if finding.get("validation", {}).get("unsupported_claims"))
    detected = corrected + unsupported_final_claims
    self_correction_success = (corrected / detected) if detected else 1.0
    return {
        "finding_precision": round(precision, 3),
        "artifact_recall": expected.get("artifact_recall", "not_measured_without_known_answer_case"),
        "hallucination_rate": round(unsupported_final_claims / final_claim_count, 3),
        "self_correction_success": round(self_correction_success, 3),
        "provenance_completeness": round(provenance, 3),
        "rejected_findings": len(rejected),
        "unsupported_rejected_claims": unsupported_rejected_claims,
    }

