from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from eviltrace.evidence.paths import WorkspacePaths


@dataclass
class RunLogger:
    """Writes the per-tool provenance ledger and the per-run summary.

    The provenance ledger (``artifacts/raw/provenance/<case>.provenance.jsonl``)
    holds one record per tool execution conforming to ``provenance.schema.json``,
    so any finding's ``audit_id`` resolves to a full command/exit-code/hash record.
    The run summary (``artifacts/reports/<case>.run.json``) records the overall
    lifecycle: iterations, stop reason, finding counts, and token totals.
    """

    paths: WorkspacePaths
    case_id: str

    @property
    def provenance_path(self) -> Path:
        return self.paths.provenance_dir / f"{self.case_id}.provenance.jsonl"

    @property
    def run_summary_path(self) -> Path:
        return self.paths.reports_dir / f"{self.case_id}.run.json"

    def reset(self) -> None:
        self.provenance_path.parent.mkdir(parents=True, exist_ok=True)
        if self.provenance_path.exists():
            self.provenance_path.unlink()

    def write_provenance(self, record: dict[str, Any]) -> None:
        self.provenance_path.parent.mkdir(parents=True, exist_ok=True)
        with self.provenance_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")

    def write_run_summary(self, summary: dict[str, Any]) -> Path:
        target = self.run_summary_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target
