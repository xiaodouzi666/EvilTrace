from __future__ import annotations

from pathlib import Path


DEVPOST_STORY = """# EvilTrace Project Story

## What it does

EvilTrace makes Protocol SIFT a more autonomous DFIR investigator while keeping a human in the loop. Forensic evidence access is routed through a typed MCP server instead of unrestricted shell commands. The agent registers and hashes evidence, builds an investigation plan, executes read-only forensic tools, normalizes artifacts into an evidence graph, proposes candidate findings, validates each one, detects contradictions or unsupported claims, self-corrects, and produces a report where every finding traces back to a specific tool execution and the original evidence hash.

EvilTrace is decision-support and triage: it generates and validates hypotheses and preserves a complete trace, but the report is meant to be reviewed by an investigator. This matches the SANS Protocol SIFT research-stage framing (augment, never replace the practitioner; not validated for forensic soundness or evidentiary use) while delivering the hackathon's "more autonomous" goal.

## How we built it

EvilTrace implements the FIND EVIL "Custom MCP Server" approach (the one the hackathon calls the most sound architecture): forensic capability is exposed as typed function wrappers, never an execute_shell tool, so destructive actions are architecturally impossible. It has two execution modes that share one typed MCP evidence layer, one validation/reporting layer, and one append-only JSONL audit log:

1. A deterministic reference orchestrator (`eviltrace run`) that plans, executes typed tools, validates, and self-corrects with no LLM inference in the loop. It is fully reproducible and runs the bundled sample in seconds.
2. Claude Code headless driving the same MCP server (`.claude/mcp.json` + `prompts/`), where per-turn token usage is captured into the same logs.

The MCP layer exposes structured forensic functions such as `pcap_summary`, `pcap_dns_queries`, `pcap_follow_stream`, `disk_timeline`, `disk_search_files`, `windows_evtx_query`, and `memory_volatility_plugin`. The validation layer enforces a strict finding schema with confirmed/inferred/rejected/needs_review status, confidence, audit IDs, artifacts verified against the manifest sha256, contradiction detection, and hallucination (entity-not-in-graph) checks. Every tool execution writes a `provenance.schema.json` record (command, exit code, durations, stdout/stderr hashes) keyed by audit id.

## Challenges

The hardest design challenge was preventing overclaiming. Instead of relying on prompt instructions, EvilTrace separates hypothesis generation from evidence validation: the agent may propose, but the system only finalizes findings that survive provenance, manifest-hash, contradiction, and corroboration checks, and it records every correction in the JSONL log.

## Accomplishments

- Typed MCP boundary for forensic evidence access — the trust boundary between the untrusted reasoning zone and the read-only evidence zone.
- Bounded self-correction loop with a hard `--max-iterations` cap and graceful degradation.
- Finding registry that rejects findings without provenance and never lets rejected findings into the final report.
- JSONL execution logs plus a per-tool provenance ledger linking every finding to a tool execution and evidence hash.
- Evidence-integrity checks using before/after SHA256 and a machine-comparable known-answer benchmark on the bundled sample (artifact recall 1.0).

## What is next

- Validate the disk/Windows/memory typed wrappers against NIST known-answer cases (they are implemented and degrade to `needs_review` until local evidence and SIFT binaries are present).
- Add more machine-comparable ground-truth sets.
- Add OpenSearch indexing for larger cases.
"""


def write_project_story(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEVPOST_STORY, encoding="utf-8")
    return target


DEVPOST_SUBMISSION = """# EvilTrace Devpost Submission Fields

Copy these fields into the Devpost submission form. The demo video URL must be a
public YouTube/Vimeo link before submitting (see docs/demo-video.md).

## Project name

EvilTrace

## Tagline

A self-correcting, evidence-grounded DFIR agent for Protocol SIFT.

## Built with

python, claude-code, mcp, tshark, sleuthkit, volatility3, typer

## Links

- Code repository: <public GitHub URL>
- Demo video (public, < 5 min): <YouTube/Vimeo URL>

## Required components map

| Required component | Location |
|---|---|
| Code repository | this repository |
| Demo video | docs/demo-video.md (public URL) |
| Architecture diagram | docs/architecture.md, docs/architecture.svg |
| Written project description | docs/project-story.md |
| Dataset documentation | docs/dataset-documentation.md |
| Accuracy report | docs/accuracy-report.md |
| Try-it-out instructions | docs/try-it-out.md |
| Agent execution logs | artifacts/logs/sample.agent.jsonl |

The "What it does / How we built it / Challenges / Accomplishments / What's next"
narrative is in docs/project-story.md.
"""


def write_devpost_submission(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(DEVPOST_SUBMISSION, encoding="utf-8")
    return target

