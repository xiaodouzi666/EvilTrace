from __future__ import annotations

from pathlib import Path
from typing import Any

from eviltrace.evidence.registry import EvidenceRegistry


def verify_manifest_integrity(manifest: dict[str, Any], workspace: str | Path = ".") -> dict[str, Any]:
    return EvidenceRegistry.from_manifest(manifest).verify(workspace)

