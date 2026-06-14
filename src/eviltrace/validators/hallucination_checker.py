from __future__ import annotations

from eviltrace.graph.model import EvidenceGraph
from eviltrace.findings.model import Finding


def hallucinated_entities(finding: Finding, graph: EvidenceGraph) -> list[str]:
    unsupported: list[str] = []
    for values in finding.entities.values():
        for value in values:
            if value and not graph.has_entity(value):
                unsupported.append(value)
    return sorted(set(unsupported))

