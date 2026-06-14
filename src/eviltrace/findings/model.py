from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


FINDING_STATUSES = {"confirmed", "inferred", "rejected", "needs_review", "candidate"}


@dataclass
class Finding:
    finding_id: str
    case_id: str
    title: str
    category: str
    status: str
    confidence: float
    summary: str
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=lambda: {"hosts": [], "users": [], "processes": [], "files": [], "network_indicators": []})
    time_range: dict[str, str | None] = field(default_factory=lambda: {"start": None, "end": None})
    validation: dict[str, Any] = field(default_factory=dict)
    reasoning_note: str = ""
    limitations: str = ""

    def __post_init__(self) -> None:
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"Unsupported finding status: {self.status}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("Finding confidence must be between 0 and 1")

    @property
    def audit_ids(self) -> list[str]:
        return sorted({artifact.get("audit_id", "") for artifact in self.artifacts if artifact.get("audit_id")})

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "confidence": round(float(self.confidence), 3),
            "summary": self.summary,
            "time_range": self.time_range,
            "entities": self.entities,
            "artifacts": self.artifacts,
            "audit_ids": self.audit_ids,
            "validation": self.validation,
            "reasoning_note": self.reasoning_note,
            "limitations": self.limitations,
        }

