from __future__ import annotations

from typing import Any

from eviltrace.graph.model import EvidenceGraph
from eviltrace.graph.store import GraphStore

from .common import ToolContext, structured_tool_event


def graph_export(ctx: ToolContext, *, graph: dict[str, Any], output_path: str) -> dict[str, Any]:
    target = ctx.guardrails.ensure_write_path(output_path)
    model = EvidenceGraph()
    for node in graph.get("nodes", []):
        model.nodes[node["id"]] = node
    model.edges = graph.get("edges", [])
    GraphStore(model).export_json(target)
    return structured_tool_event(
        ctx,
        mcp_tool="graph_export",
        input_data={"output_path": output_path},
        output={"output_path": ctx.paths.relative_to_workspace(target), "nodes": len(model.nodes), "edges": len(model.edges)},
        status="success",
    )

