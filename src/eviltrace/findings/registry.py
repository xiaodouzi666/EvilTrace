from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Finding


class FindingRegistryError(ValueError):
    pass


@dataclass
class FindingRegistry:
    case_id: str
    findings: dict[str, Finding] = field(default_factory=dict)
    rejected_findings: dict[str, Finding] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        if finding.case_id != self.case_id:
            raise FindingRegistryError("Finding case_id does not match registry case_id")
        if finding.status in {"confirmed", "inferred"}:
            if not finding.artifacts:
                raise FindingRegistryError("Confirmed or inferred findings require artifacts")
            if not finding.audit_ids:
                raise FindingRegistryError("Confirmed or inferred findings require audit_ids")
        if finding.status == "rejected":
            self.rejected_findings[finding.finding_id] = finding
            self.findings.pop(finding.finding_id, None)
        else:
            self.findings[finding.finding_id] = finding

    def update(self, finding: Finding) -> None:
        self.add(finding)

    def all_for_validation(self) -> list[Finding]:
        return list(self.findings.values()) + list(self.rejected_findings.values())

    def final_findings(self) -> list[Finding]:
        return [finding for finding in self.findings.values() if finding.status in {"confirmed", "inferred", "needs_review"}]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "findings": [finding.to_dict() for finding in self.final_findings()],
            "rejected_findings": [finding.to_dict() for finding in self.rejected_findings.values()],
        }

