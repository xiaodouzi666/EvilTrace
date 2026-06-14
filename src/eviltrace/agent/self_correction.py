from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eviltrace.findings.model import Finding
from eviltrace.validators.finding_validator import ValidationOutcome


@dataclass
class CorrectionDecision:
    needs_replan: bool
    action: str
    finding_id: str
    reason: str
    previous_status: str
    new_status: str
    next_action: str | None = None
    targeted_replan: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "needs_replan": self.needs_replan,
            "action": self.action,
            "finding_id": self.finding_id,
            "reason": self.reason,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "next_action": self.next_action,
            "targeted_replan": self.targeted_replan,
        }


class SelfCorrectionEngine:
    def decide(self, finding: Finding, validation: ValidationOutcome, *, max_iterations_reached: bool = False) -> CorrectionDecision:
        unsupported = set(validation.unsupported_claims)
        if "finding_has_no_artifacts" in unsupported or "finding_has_no_audit_ids" in unsupported:
            return CorrectionDecision(
                needs_replan=False,
                action="reject_finding",
                finding_id=finding.finding_id,
                reason=validation.reason,
                previous_status=finding.status,
                new_status="rejected",
                next_action="Do not include this claim in final findings.",
            )
        if validation.recommended_status == "rejected":
            return CorrectionDecision(
                needs_replan=False,
                action="reject_finding",
                finding_id=finding.finding_id,
                reason=validation.reason,
                previous_status=finding.status,
                new_status="rejected",
                next_action="Reject unsupported claim.",
            )
        if validation.recommended_status == "needs_review":
            return CorrectionDecision(
                needs_replan=not max_iterations_reached,
                action="targeted_replan" if not max_iterations_reached else "finalize_with_limitations",
                finding_id=finding.finding_id,
                reason=validation.reason,
                previous_status=finding.status,
                new_status="needs_review",
                next_action="Run targeted corroboration if iteration budget remains.",
            )
        if validation.recommended_status == "inferred" and finding.status == "confirmed":
            pcap_artifact = next((artifact for artifact in finding.artifacts if artifact.get("artifact_type") in {"pcap_summary", "dns_query"}), None)
            target = None
            if pcap_artifact:
                target = {"tool": "pcap_follow_stream", "pcap_path": pcap_artifact.get("source_path"), "stream_id": 0}
            return CorrectionDecision(
                needs_replan=bool(target) and not max_iterations_reached,
                action="downgrade_to_inferred",
                finding_id=finding.finding_id,
                reason=validation.reason,
                previous_status=finding.status,
                new_status="inferred",
                next_action="Run stream reconstruction to seek corroborating evidence." if target else "Finalize as inferred with limitations.",
                targeted_replan=target,
            )
        return CorrectionDecision(
            needs_replan=False,
            action="accept_validation",
            finding_id=finding.finding_id,
            reason=validation.reason,
            previous_status=finding.status,
            new_status=validation.recommended_status,
            next_action=None,
        )

