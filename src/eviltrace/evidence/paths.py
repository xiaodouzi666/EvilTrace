from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspacePaths:
    workspace: Path
    evidence_root: Path
    artifact_root: Path

    @classmethod
    def from_workspace(
        cls,
        workspace: str | Path = ".",
        evidence_root: str | Path = "cases",
        artifact_root: str | Path = "artifacts",
    ) -> "WorkspacePaths":
        root = Path(workspace).resolve()
        evidence = (root / evidence_root).resolve() if not Path(evidence_root).is_absolute() else Path(evidence_root).resolve()
        artifacts = (root / artifact_root).resolve() if not Path(artifact_root).is_absolute() else Path(artifact_root).resolve()
        return cls(workspace=root, evidence_root=evidence, artifact_root=artifacts)

    @property
    def logs_dir(self) -> Path:
        return self.artifact_root / "logs"

    @property
    def reports_dir(self) -> Path:
        return self.artifact_root / "reports"

    @property
    def graphs_dir(self) -> Path:
        return self.artifact_root / "graphs"

    @property
    def raw_dir(self) -> Path:
        return self.artifact_root / "raw"

    @property
    def tool_outputs_dir(self) -> Path:
        return self.raw_dir / "tool-outputs"

    def ensure(self) -> None:
        for path in [
            self.evidence_root,
            self.logs_dir,
            self.reports_dir,
            self.graphs_dir,
            self.tool_outputs_dir,
            self.raw_dir / "http-objects",
            self.artifact_root / "benchmarks",
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def relative_to_workspace(self, path: str | Path) -> str:
        resolved = Path(path).resolve()
        try:
            return str(resolved.relative_to(self.workspace))
        except ValueError:
            return str(resolved)

