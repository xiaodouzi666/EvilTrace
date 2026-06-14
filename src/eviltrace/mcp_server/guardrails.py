from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Iterable

from eviltrace.evidence.paths import WorkspacePaths


class GuardrailError(RuntimeError):
    """Raised when a requested evidence or command operation violates policy."""


DEFAULT_ALLOWED_COMMANDS = {
    "capinfos",
    "evtx_dump",
    "file",
    "fls",
    "fsstat",
    "icat",
    "mactime",
    "mmls",
    "reglookup",
    "sha256sum",
    "tsk_recover",
    "tshark",
    "vol",
    "volatility3",
}

DENIED_COMMAND_PATTERNS = [
    r"\brm\b",
    r"\bmv\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bdd\b",
    r"\bmkfs(?:\.[A-Za-z0-9]+)?\b",
    r"\bmount\b.*\b(rw|remount)\b",
    r">\s*(?:cases|evidence)/",
    r"\|\s*sh\b",
    r"\|\s*bash\b",
]


@dataclass
class GuardrailConfig:
    paths: WorkspacePaths
    allowed_commands: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_COMMANDS))
    timeout_seconds: int = 120
    max_output_bytes: int = 2 * 1024 * 1024

    def resolve(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.paths.workspace / candidate
        return candidate.resolve()

    def _is_under(self, child: Path, parent: Path) -> bool:
        try:
            child.resolve().relative_to(parent.resolve())
            return True
        except ValueError:
            return False

    def is_evidence_path(self, path: str | Path) -> bool:
        return self._is_under(self.resolve(path), self.paths.evidence_root)

    def is_artifact_path(self, path: str | Path) -> bool:
        return self._is_under(self.resolve(path), self.paths.artifact_root)

    def is_docs_path(self, path: str | Path) -> bool:
        return self._is_under(self.resolve(path), self.paths.workspace / "docs")

    def ensure_read_path(self, path: str | Path) -> Path:
        resolved = self.resolve(path)
        if not self._is_under(resolved, self.paths.workspace):
            raise GuardrailError(f"Read path escapes workspace: {path}")
        if not resolved.exists():
            raise GuardrailError(f"Read path does not exist: {path}")
        return resolved

    def ensure_write_path(self, path: str | Path) -> Path:
        resolved = self.resolve(path)
        if self.is_evidence_path(resolved):
            raise GuardrailError(f"Evidence path is read-only: {path}")
        if not (self.is_artifact_path(resolved) or self.is_docs_path(resolved)):
            raise GuardrailError(f"Write path must be under artifacts/ or docs/: {path}")
        return resolved

    def validate_command(self, argv: Iterable[str]) -> list[str]:
        command = [str(part) for part in argv]
        if not command:
            raise GuardrailError("Empty command is not allowed")
        executable = Path(command[0]).name
        if executable not in self.allowed_commands:
            raise GuardrailError(f"Command is not allowlisted: {executable}")
        rendered = " ".join(command)
        for pattern in DENIED_COMMAND_PATTERNS:
            if re.search(pattern, rendered):
                raise GuardrailError(f"Command matches denied pattern: {pattern}")
        return command

