# EvilTrace Project Story

## What it does

EvilTrace makes Protocol SIFT a more autonomous DFIR investigator while keeping a human in the loop. Forensic evidence access is routed through a typed MCP server instead of unrestricted shell commands. The agent registers and hashes evidence, builds an investigation plan, executes read-only forensic tools, normalizes artifacts into an evidence graph, proposes candidate findings, validates each one, detects contradictions or unsupported claims, self-corrects, and produces a report where every finding traces back to a specific tool execution and the original evidence hash.

EvilTrace is decision-support and triage: it generates and validates hypotheses and preserves a complete trace, but the report is meant to be reviewed by an investigator. This matches the SANS Protocol SIFT research-stage framing (augment, never replace the practitioner; not validated for forensic soundness or evidentiary use) while delivering the hackathon's "more autonomous" goal.

## How we built it

EvilTrace has two execution modes that share one typed MCP evidence layer, one validation/reporting layer, and one append-only JSONL audit log:

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
