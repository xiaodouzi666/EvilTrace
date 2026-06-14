# EvilTrace

Self-correcting, evidence-grounded DFIR agent for Protocol SIFT.

EvilTrace routes all forensic evidence access through a **typed MCP server** behind a hard
**trust boundary**: the reasoning layer is untrusted and cannot touch evidence directly, while
a read-only evidence layer enforces command allowlists, evidence hashing, audit logging, a
provenance ledger, validation, and a bounded self-correction loop. It is decision-support and
triage for an investigator — not a court-ready evidentiary system.

## 1. What It Does

EvilTrace registers a case, hashes evidence, creates an investigation plan, executes typed
forensic tools, normalizes artifacts into an evidence graph, proposes candidate findings,
validates each finding against provenance/manifest hashes/contradictions/corroboration,
rejects or downgrades unsupported or overconfident claims, self-corrects, and writes a
traceable report where every finding maps to a tool execution and the original evidence hash.

Final outputs per case:

- `artifacts/logs/<case>.agent.jsonl` — append-only event log (with `self_correction_triggered`)
- `artifacts/raw/provenance/<case>.provenance.jsonl` — per-tool provenance records
- `artifacts/reports/<case>.report.md` / `.findings.json` / `.validation.json` / `.run.json`
- `artifacts/graphs/<case>.graph.json` — evidence graph with the full provenance chain

## 2. Competition Compliance Map

| Required Component | Location | Status |
|---|---|---|
| Code Repository | This repo (MIT) | Complete |
| Demo Video | `docs/demo-video.md` | Recording-ready; **public URL must be added before submitting** |
| Architecture Diagram | `docs/architecture.md`, `docs/architecture.svg` (labeled trust boundary) | Complete |
| Written Project Description | `docs/project-story.md` | Complete |
| Dataset Documentation | `docs/dataset-documentation.md` | Complete |
| Accuracy Report | `docs/accuracy-report.md` | Complete |
| Try-It-Out Instructions | `docs/try-it-out.md` | Complete |
| Agent Execution Logs | `artifacts/logs/`, `artifacts/raw/provenance/` | Complete |

## 3. Why EvilTrace Scores Well

| Judging Criterion | EvilTrace Feature |
|---|---|
| Autonomous Execution Quality | Bounded planner → tool execution → validation → self-correction loop with `--max-iterations`, `alternate_tool`, and graceful degradation |
| IR Accuracy | Finding validation, manifest-hash provenance checks, contradiction + hallucination detection, rejected unsupported claims |
| Breadth and Depth | Validated network-first PCAP path; disk (Sleuth Kit), Windows, and memory typed wrappers that degrade to `needs_review` until local evidence is present |
| Constraint Implementation | Typed MCP tools (no shell-exec), command allowlist+denylist, read-only evidence, fail-closed hooks |
| Audit Trail Quality | JSONL logs, provenance ledger, audit IDs, raw output hashes, evidence-graph provenance chain |
| Usability and Documentation | One-command sample run, `submission-check`, `export-devpost`, complete docs |

## 4. Quick Start

Dependencies: Python 3.11+, `uv` or `pip`, and `jq` (the Claude Code guardrail hooks fail
closed without it). `tshark` is optional — without it EvilTrace uses a read-only built-in
PCAP/DNS parser and records the fallback in provenance.

```bash
uv sync
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
uv run eviltrace submission-check
```

Or with pip:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .[dev]
eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
```

The repository bundles a small public Wireshark `dns.cap` under `cases/sample/` plus generated
sample outputs. When you place additional PCAP or disk evidence under `cases/`, EvilTrace runs
the typed-tool path against it and records any missing SIFT binary as a limitation instead of
confirming unsupported findings.

## 5. Demo

```bash
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
jq 'select(.event_type=="self_correction_triggered")' artifacts/logs/sample.agent.jsonl
jq '.findings[0].artifacts' artifacts/reports/sample.findings.json
uv run eviltrace benchmark --findings artifacts/reports/sample.findings.json \
  --expected data/ground_truth/sample.expected.json --manifest artifacts/reports/sample.case.json
```

## 6. Two Execution Modes (one shared core)

1. **Deterministic reference orchestrator** (`eviltrace run`) — reproducible, rule-based, no LLM
   inference in the loop (token usage zero by construction), runs in seconds.
2. **Claude Code headless** — Claude drives the same MCP server (`.claude/mcp.json`,
   `prompts/`); per-turn token usage is captured into the same logs.

Both share the typed MCP tools, validators, evidence graph, and audit log. See
`docs/architecture.md`.

## 7. How Self-Correction Works

Every candidate finding is validated against provenance, manifest hashes, corroboration count,
graph entities, contradictions, and evidence integrity. Unsupported claims are rejected;
overconfident findings are downgraded to `inferred`; contradictions and evidence gaps trigger a
targeted re-plan or an alternate tool; tool failures degrade gracefully. The loop is hard-capped
by `--max-iterations`. Rejected findings never enter the final report.

## 8. Evidence Integrity and Guardrails

- Evidence under `cases/` is read-only (code guardrails + fail-closed Claude Code hooks).
- Writes are limited to `artifacts/` and `docs/`.
- Forensic execution uses allowlisted read-only binaries; the MCP server exposes no shell-exec.
- Destructive commands are denied by both code guardrails and hooks.
- Tool output is capped and stored under `artifacts/raw/tool-outputs/`.

See `docs/guardrails.md` and the guardrail test results in `docs/accuracy-report.md` section 7.

## 9. Dataset and Accuracy

See `docs/dataset-documentation.md` and `docs/accuracy-report.md`. The bundled sample has a
machine-comparable ground-truth set (`data/ground_truth/sample.expected.json`) yielding artifact
recall 1.0; large validation evidence is not vendored.

## 10. Repository Layout

```text
src/eviltrace/      EvilTrace Python package
docs/               Devpost and technical documentation
prompts/            Claude Code prompt pack
scripts/            Setup, benchmark, and validation scripts
data/               Manifests and machine-comparable ground truth
cases/              Local evidence root, read-only by policy
artifacts/          Reports, logs, graphs, provenance, raw tool outputs
tests/              Unit and integration tests
```

## 11. Development

```bash
uv run pytest
python3 -m compileall -q src
bash scripts/validate_submission.sh
```

## 12. Known Limitations

EvilTrace is a triage and decision-support agent requiring human validation, not a court-ready
evidentiary system. The validated depth is the network-first PCAP path; disk/Windows/memory
wrappers are implemented and degrade to `needs_review` until validated local evidence and SIFT
binaries are present. See `docs/limitations.md`.

## 13. License

MIT. See `LICENSE`.
