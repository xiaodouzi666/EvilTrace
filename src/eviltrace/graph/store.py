from __future__ import annotations

import json
from pathlib import Path

from .model import EvidenceGraph


class GraphStore:
    def __init__(self, graph: EvidenceGraph | None = None):
        self.graph = graph or EvidenceGraph()

    def export_json(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.graph.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target

    @classmethod
    def load_json(cls, path: str | Path) -> "GraphStore":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        graph = EvidenceGraph()
        for node in data.get("nodes", []):
            graph.nodes[node["id"]] = node
        graph.edges = data.get("edges", [])
        return cls(graph)

