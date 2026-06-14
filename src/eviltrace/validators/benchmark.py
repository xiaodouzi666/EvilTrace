from __future__ import annotations

from typing import Any

from eviltrace.findings.provenance import provenance_complete


def _observed_indicators(findings: list[dict[str, Any]]) -> set[str]:
    observed: set[str] = set()
    for finding in findings:
        entities = finding.get("entities", {}) or {}
        for values in entities.values():
            if isinstance(values, list):
                observed.update(str(v).lower() for v in values if v)
        for artifact in finding.get("artifacts", []):
            for value in artifact.get("summary", {}).get("network_indicators", []) or []:
                if value:
                    observed.add(str(value).lower())
    return observed


def compute_metrics(
    findings: list[dict[str, Any]],
    expected: dict[str, Any] | None = None,
    integrity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected = expected or {}
    asserted = [finding for finding in findings if finding.get("status") in {"confirmed", "inferred"}]
    supported = [finding for finding in asserted if finding.get("artifacts")]
    rejected = [finding for finding in findings if finding.get("status") == "rejected"]

    precision = len(supported) / len(asserted) if asserted else 1.0

    # provenance_completeness: an asserted finding is complete only if it has audit_ids
    # AND every cited artifact carries a full provenance chain (finding -> artifact -> audit_id -> sha256).
    def _complete(finding: dict[str, Any]) -> bool:
        if not finding.get("audit_ids"):
            return False
        artifacts = finding.get("artifacts", [])
        return bool(artifacts) and all(provenance_complete(a) for a in artifacts)

    provenance = (sum(1 for f in asserted if _complete(f)) / len(asserted)) if asserted else 1.0

    # hallucination_rate: fraction of FINAL (asserted) claims that still carry unsupported claims.
    # Bounded to [0, 1] by construction (numerator counts findings, not claim tokens).
    total_claims = max(len(asserted), 1)
    unsupported_final = sum(1 for f in asserted if f.get("validation", {}).get("unsupported_claims"))
    hallucination_rate = min(1.0, unsupported_final / total_claims)

    # self_correction_success: of the errors EvilTrace detected (unsupported claims it caught and
    # rejected, plus any that leaked into final findings), how many were corrected (rejected).
    corrected = sum(1 for f in rejected if f.get("validation", {}).get("unsupported_claims"))
    detected = corrected + unsupported_final
    self_correction_success = (corrected / detected) if detected else 1.0
    unsupported_rejected_claims = sum(len(f.get("validation", {}).get("unsupported_claims", [])) for f in rejected)

    # artifact_recall: only computed when machine-comparable ground truth is supplied.
    expected_indicators = [str(v).lower() for v in expected.get("expected_indicators", []) if v]
    if expected_indicators:
        observed = _observed_indicators(asserted)
        matched = sorted({ind for ind in expected_indicators if ind in observed})
        artifact_recall: Any = round(len(matched) / len(expected_indicators), 3)
    else:
        artifact_recall = "not_measured_without_known_answer_case"

    metrics: dict[str, Any] = {
        "finding_precision": round(precision, 3),
        "artifact_recall": artifact_recall,
        "hallucination_rate": round(hallucination_rate, 3),
        "self_correction_success": round(self_correction_success, 3),
        "provenance_completeness": round(provenance, 3),
        "rejected_findings": len(rejected),
        "unsupported_rejected_claims": unsupported_rejected_claims,
    }

    # evidence_integrity = unchanged evidence files / all evidence files.
    if integrity is not None:
        checked = int(integrity.get("checked_count", 0) or 0)
        changed = len(integrity.get("changed_files", []) or [])
        missing = len(integrity.get("missing_files", []) or [])
        metrics["evidence_integrity"] = round((checked - changed - missing) / checked, 3) if checked else 1.0
        metrics["evidence_integrity_status"] = integrity.get("integrity_status") or integrity.get("status", "unknown")
    return metrics
