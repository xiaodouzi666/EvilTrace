from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from eviltrace.findings.model import Finding
from eviltrace.graph.model import EvidenceGraph

from .contradiction_detector import detect_contradictions
from .hallucination_checker import hallucinated_entities


OVERCLAIM_TERMS = {"exfiltration", "malware", "compromise", "execution", "confirmed"}
STRONG_ARTIFACT_TYPES = {"pcap_stream", "http_object", "evtx_record", "prefetch", "memory_process"}


@dataclass
class ValidationOutcome:
    finding_id: str
    status: str
    confidence: float
    corroborated_by: list[str]
    contradicted_by: list[str]
    unsupported_claims: list[str]
    hallucination_check: str
    recommended_status: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "confidence": self.confidence,
            "corroborated_by": self.corroborated_by,
            "contradicted_by": self.contradicted_by,
            "unsupported_claims": self.unsupported_claims,
            "hallucination_check": self.hallucination_check,
            "recommended_status": self.recommended_status,
            "reason": self.reason,
        }


class FindingValidator:
    def validate(self, finding: Finding, graph: EvidenceGraph) -> ValidationOutcome:
        unsupported: list[str] = []
        if not finding.artifacts:
            unsupported.append("finding_has_no_artifacts")
        if finding.status in {"confirmed", "inferred", "candidate"} and not finding.audit_ids:
            unsupported.append("finding_has_no_audit_ids")
        for artifact in finding.artifacts:
            if not artifact.get("source_path"):
                unsupported.append(f"{artifact.get('artifact_id', 'artifact')}:missing_source_path")
            if not artifact.get("source_sha256"):
                unsupported.append(f"{artifact.get('artifact_id', 'artifact')}:missing_source_sha256")
            if not artifact.get("audit_id"):
                unsupported.append(f"{artifact.get('artifact_id', 'artifact')}:missing_audit_id")
        unsupported_entities = hallucinated_entities(finding, graph)
        unsupported.extend([f"entity_not_in_graph:{entity}" for entity in unsupported_entities])

        contradictions = detect_contradictions(finding)
        artifact_ids = [artifact.get("artifact_id", "") for artifact in finding.artifacts if artifact.get("artifact_id")]
        strong = any(artifact.get("artifact_type") in STRONG_ARTIFACT_TYPES for artifact in finding.artifacts)
        text = f"{finding.title} {finding.summary}".lower()
        overclaim = sorted(term for term in OVERCLAIM_TERMS if term in text)

        direct_exfiltration_support = any(artifact.get("artifact_type") in {"pcap_stream", "http_object", "endpoint_file", "event_log"} for artifact in finding.artifacts)

        if unsupported:
            recommended = "rejected"
            reason = "Unsupported claims or missing provenance were detected."
        elif "exfiltration" in overclaim and not direct_exfiltration_support:
            recommended = "rejected"
            reason = "Exfiltration language requires stream, object, or endpoint evidence; none is present."
            unsupported.append("overclaim:exfiltration_without_direct_support")
        elif contradictions:
            recommended = "needs_review"
            reason = "Contradictory evidence markers were detected."
        elif finding.status == "confirmed" and len(artifact_ids) < 2 and not strong:
            recommended = "inferred"
            reason = "Confirmed status requires two artifacts or one strong artifact."
            unsupported.append("single_source_overclaim")
        elif overclaim and len(artifact_ids) < 2 and not strong:
            recommended = "inferred"
            reason = "Conclusion language is stronger than the available evidence."
            unsupported.append("overclaim:" + ",".join(overclaim))
        else:
            recommended = "confirmed" if (len(artifact_ids) >= 2 or strong) and finding.status == "confirmed" else finding.status
            reason = "Finding has required provenance and no contradictions."

        hallucination_check = "passed" if not unsupported_entities else "failed"
        confidence = finding.confidence
        if recommended == "rejected":
            confidence = min(confidence, 0.1)
        elif recommended == "inferred":
            confidence = min(confidence, 0.59)
        elif recommended == "needs_review":
            confidence = min(confidence, 0.45)

        return ValidationOutcome(
            finding_id=finding.finding_id,
            status=finding.status,
            confidence=round(confidence, 3),
            corroborated_by=artifact_ids,
            contradicted_by=contradictions,
            unsupported_claims=sorted(set(unsupported)),
            hallucination_check=hallucination_check,
            recommended_status=recommended,
            reason=reason,
        )

