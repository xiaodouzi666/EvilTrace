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


# Maps a failed tool to an alternate tool (and the binary it needs) the engine can retry with.
# Only mappings the orchestrator can actually re-plan are listed; unmapped tools yield
# finalize_with_limitations. (pcap_http_objects -> pcap_follow_stream is wired in
# orchestrator._handle_tool_failures and runs when tshark is available.)
ALTERNATE_TOOLS: dict[str, dict[str, str | None]] = {
    "pcap_http_objects": {"tool": "pcap_follow_stream", "binary": "tshark"},
}


class SelfCorrectionEngine:
    def decide_tool_failure(
        self,
        *,
        tool: str,
        status: str,
        reason: str,
        max_iterations_reached: bool = False,
    ) -> CorrectionDecision:
        """When a tool fails (tool_missing/tool_error/timeout/needs_review), propose an
        alternate tool if one is mapped, otherwise finalize the gap as a limitation."""
        alternate = ALTERNATE_TOOLS.get(tool) or {}
        alternate_tool = alternate.get("tool")
        has_alternate = bool(alternate_tool)
        return CorrectionDecision(
            needs_replan=has_alternate and not max_iterations_reached,
            action="alternate_tool" if has_alternate else "finalize_with_limitations",
            finding_id="",
            reason=f"Tool {tool} returned {status}: {reason}",
            previous_status="n/a",
            new_status="n/a",
            next_action=(
                f"Retry with alternate tool {alternate_tool}." if has_alternate
                else "No alternate tool is available; record as a limitation."
            ),
            targeted_replan={"tool": alternate_tool, "binary": alternate.get("binary")} if has_alternate else None,
        )

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
            summary_artifact = next((a for a in finding.artifacts if a.get("artifact_type") == "pcap_summary"), None)
            dns_artifact = next((a for a in finding.artifacts if a.get("artifact_type") == "dns_query"), None)
            target = None
            next_action = "Finalize as inferred with limitations."
            if summary_artifact:
                # Corroborate a summary-only claim by extracting the actual DNS queries.
                target = {"tool": "pcap_dns_queries", "pcap_path": summary_artifact.get("source_path")}
                next_action = "Re-plan a targeted DNS extraction to corroborate the summary-level claim."
            elif dns_artifact:
                target = {"tool": "pcap_follow_stream", "pcap_path": dns_artifact.get("source_path"), "stream_id": 0}
                next_action = "Run stream reconstruction to seek corroborating evidence."
            return CorrectionDecision(
                needs_replan=bool(target) and not max_iterations_reached,
                action="downgrade_to_inferred",
                finding_id=finding.finding_id,
                reason=validation.reason,
                previous_status=finding.status,
                new_status="inferred",
                next_action=next_action,
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

