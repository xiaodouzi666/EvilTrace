from __future__ import annotations

from eviltrace.findings.model import Finding


def detect_contradictions(finding: Finding) -> list[str]:
    contradictions: list[str] = []
    validation = finding.validation or {}
    contradictions.extend(validation.get("contradicted_by", []))
    text = f"{finding.title} {finding.summary}".lower()
    if "executed" in text and not any(a.get("artifact_type") in {"prefetch", "process", "event_log", "memory_process"} for a in finding.artifacts):
        contradictions.append("execution_claim_without_execution_artifact")
    return sorted(set(contradictions))

