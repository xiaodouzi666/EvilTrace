from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .hashing import sha256_file
from .paths import WorkspacePaths


TYPE_BY_SUFFIX = {
    ".pcap": "pcap",
    ".pcapng": "pcap",
    ".cap": "pcap",
    ".e01": "ewf_disk_image",
    ".raw": "raw_image",
    ".dd": "raw_image",
    ".aff": "aff_image",
    ".evtx": "windows_event_log",
    ".pf": "windows_prefetch",
    ".dat": "windows_registry_hive",
    ".zip": "archive",
    ".gz": "archive",
}


def detect_evidence_type(path: Path) -> str:
    return TYPE_BY_SUFFIX.get(path.suffix.lower(), "generic_file")


def discover_evidence(case_root: str | Path, paths: WorkspacePaths) -> list[dict[str, Any]]:
    root = Path(case_root)
    if not root.is_absolute():
        root = (paths.workspace / root).resolve()
    if not root.exists() or not root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for index, path in enumerate(sorted(p for p in root.rglob("*") if p.is_file()), start=1):
        if path.name == ".gitkeep":
            continue
        stat = path.stat()
        rows.append(
            {
                "evidence_id": f"ev-{index:04d}",
                "path": paths.relative_to_workspace(path),
                "sha256": sha256_file(path),
                "size_bytes": stat.st_size,
                "detected_type": detect_evidence_type(path),
                "read_only": True,
            }
        )
    return rows


def build_case_manifest(
    case_id: str,
    case_root: str | Path,
    paths: WorkspacePaths,
    *,
    case_type: str = "unknown",
    description: str = "",
) -> dict[str, Any]:
    root = Path(case_root)
    if not root.is_absolute():
        root = (paths.workspace / root).resolve()
    evidence = discover_evidence(root, paths)
    return {
        "case_id": case_id,
        "case_root": paths.relative_to_workspace(root),
        "case_type": case_type,
        "description": description,
        "registered_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "evidence_count": len(evidence),
        "evidence": evidence,
    }


def write_manifest(manifest: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

