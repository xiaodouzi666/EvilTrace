from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TokenLogger:
    """Aggregates token usage and cost across a run.

    EvilTrace exposes two execution modes that share the same typed MCP tools,
    validators, and audit log (see docs/architecture.md):

    * the deterministic reference orchestrator (``eviltrace run``), which performs
      rule-based planning and validation with **no LLM inference in the loop**, so
      its token usage is legitimately zero; and
    * Claude Code headless driving the same MCP server, where per-turn usage
      metadata is recorded via :meth:`record`.

    This logger keeps the accounting honest: it reports the real totals it was
    given rather than fabricating non-zero values for the deterministic path.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    llm_calls: int = 0
    mode: str = "deterministic-reference-orchestrator"
    _events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, token_usage: dict[str, int] | None, cost_usd: float = 0.0) -> None:
        usage = token_usage or {}
        added_in = int(usage.get("input_tokens", 0) or 0)
        added_out = int(usage.get("output_tokens", 0) or 0)
        self.input_tokens += added_in
        self.output_tokens += added_out
        self.cost_usd = round(self.cost_usd + float(cost_usd or 0.0), 6)
        if added_in or added_out or cost_usd:
            self.llm_calls += 1
        self._events.append({"input_tokens": added_in, "output_tokens": added_out, "cost_usd": cost_usd})

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def summary(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "llm_calls": self.llm_calls,
            "token_usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.total_tokens,
            },
            "cost_usd": self.cost_usd,
            "note": (
                "The deterministic reference orchestrator performs no LLM inference, "
                "so token usage is zero by construction; usage is captured when the "
                "same typed MCP tools are driven by Claude Code headless."
            ),
        }
