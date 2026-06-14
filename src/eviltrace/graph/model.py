from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, **properties: Any) -> None:
        current = self.nodes.get(node_id, {"id": node_id, "type": node_type, "properties": {}})
        current["type"] = node_type
        current.setdefault("properties", {}).update(properties)
        self.nodes[node_id] = current

    def add_edge(self, source: str, target: str, edge_type: str, **properties: Any) -> None:
        edge = {"source": source, "target": target, "type": edge_type, "properties": properties}
        if edge not in self.edges:
            self.edges.append(edge)

    def has_entity(self, value: str) -> bool:
        if not value:
            return True
        for node in self.nodes.values():
            if value == node.get("id"):
                return True
            props = node.get("properties", {})
            if value in {str(v) for v in props.values()}:
                return True
            for item in props.values():
                if isinstance(item, list) and value in {str(v) for v in item}:
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

