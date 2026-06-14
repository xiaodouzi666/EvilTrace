from __future__ import annotations

from typing import Any


def score_finding(artifacts: list[dict[str, Any]], contradictions: list[str] | None = None, strong_artifact: bool = False) -> float:
    contradictions = contradictions or []
    score = 0.3 + min(len(artifacts), 3) * 0.18
    if strong_artifact:
        score += 0.18
    score -= min(len(contradictions), 3) * 0.2
    return max(0.0, min(0.95, score))

