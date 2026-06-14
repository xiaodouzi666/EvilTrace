from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .hashing import sha256_file


@dataclass
class EvidenceRegistry:
    case_id: str
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_manifest(cls, manifest: dict[str, Any]) -> "EvidenceRegistry":
        return cls(case_id=manifest["case_id"], evidence=list(manifest.get("evidence", [])))

    def by_id(self, evidence_id: str) -> dict[str, Any] | None:
        return next((row for row in self.evidence if row.get("evidence_id") == evidence_id), None)

    def by_path(self, path: str) -> dict[str, Any] | None:
        return next((row for row in self.evidence if row.get("path") == path), None)

    def verify(self, workspace: str | Path = ".") -> dict[str, Any]:
        root = Path(workspace).resolve()
        changed: list[dict[str, str]] = []
        missing: list[str] = []
        for row in self.evidence:
            path = Path(row["path"])
            resolved = path if path.is_absolute() else root / path
            if not resolved.exists():
                missing.append(row["path"])
                continue
            actual = sha256_file(resolved)
            if actual != row.get("sha256"):
                changed.append({"path": row["path"], "expected": row.get("sha256", ""), "actual": actual})
        status = "passed" if not changed and not missing else "failed"
        return {
            "case_id": self.case_id,
            "status": status,
            "changed_files": changed,
            "missing_files": missing,
            "checked_count": len(self.evidence),
        }

