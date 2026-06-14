from __future__ import annotations

from pathlib import Path

from .store import GraphStore


def export_graph(store: GraphStore, output_path: str | Path) -> Path:
    return store.export_json(output_path)

