from __future__ import annotations

from pathlib import Path


DEVPOST_STORY = """# EvilTrace Project Story

## What it does

EvilTrace turns Protocol SIFT into a more autonomous DFIR investigator. Claude Code handles orchestration, but evidence access is routed through a typed MCP server instead of unrestricted shell commands. The agent registers and hashes evidence, builds an investigation plan, executes read-only forensic tools, normalizes artifacts into an evidence graph, validates candidate findings, detects contradictions or unsupported claims, self-corrects, and produces a report where every finding traces back to specific tool executions.

## How we built it

EvilTrace has three layers: a Claude Code orchestration layer, a typed MCP evidence layer, and a validation/reporting layer. The MCP layer exposes structured forensic functions such as `pcap_summary`, `pcap_follow_stream`, `disk_timeline`, `windows_evtx_query`, and `memory_volatility_plugin`. The validation layer enforces a strict finding schema with status, confidence, audit IDs, artifacts, and hallucination checks.

## Challenges

The hardest design challenge was preventing overclaiming. EvilTrace separates hypothesis generation from evidence validation and records every correction in JSONL logs.

## Accomplishments

- Typed MCP boundary for forensic evidence access.
- Bounded self-correction loop with max-iteration controls.
- Finding registry that rejects findings without provenance.
- JSONL execution logs linking findings to tool executions.
- Evidence integrity checks using before/after hashes.

## What is next

- Expand typed MCP coverage across more SIFT tools.
- Add deeper disk and memory correlation.
- Add more known-answer validation cases.
"""


def write_project_story(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEVPOST_STORY, encoding="utf-8")
    return target

