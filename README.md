# EvilTrace

Self-correcting, evidence-grounded DFIR agent for Protocol SIFT.

EvilTrace uses Claude Code for orchestration, but forensic evidence access is routed through typed MCP tools with read-only evidence guardrails, command allowlists, audit IDs, evidence hashing, validation, and a bounded self-correction loop.

## 1. What It Does

EvilTrace registers a case, hashes evidence, creates an investigation plan, executes typed forensic tools, normalizes artifacts into an evidence graph, proposes candidate findings, validates each finding, corrects unsupported or overconfident claims, and writes traceable reports.

Final outputs include:

- `artifacts/logs/<case>.agent.jsonl`
- `artifacts/reports/<case>.report.md`
- `artifacts/reports/<case>.findings.json`
- `artifacts/reports/<case>.validation.json`
- `artifacts/graphs/<case>.graph.json`

## 2. Competition Compliance Map

| Required Component | Location | Status |
|---|---|---|
| Code Repository | This repo | Complete |
| Demo Video | `docs/demo-video.md` | Recording-ready; public URL pending |
| Architecture Diagram | `docs/architecture.md` | Complete |
| Written Project Description | `docs/project-story.md` | Complete |
| Dataset Documentation | `docs/dataset-documentation.md` | Complete |
| Accuracy Report | `docs/accuracy-report.md` | Complete |
| Try-It-Out Instructions | `docs/try-it-out.md` | Complete |
| Agent Execution Logs | `artifacts/logs/` | Complete |

## 3. Why EvilTrace Scores Well

| Judging Criterion | EvilTrace Feature |
|---|---|
| Autonomous Execution Quality | Bounded planner → tool execution → validation → self-correction loop |
| IR Accuracy | Finding validation, hallucination checks, and rejected unsupported claims |
| Breadth and Depth | Deep network-first path with disk, Windows, and memory typed wrappers |
| Constraint Implementation | MCP typed tools, command allowlist, read-only evidence paths |
| Audit Trail Quality | JSONL logs, audit IDs, raw output paths, hashes, graph export |
| Usability and Documentation | One-command local run, submission check, complete docs |

## 4. Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
eviltrace submission-check
```

If `uv` is available:

```bash
uv sync
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
```

The repository includes a small public Wireshark `dns.cap` sample under `cases/sample/` plus generated sample outputs. When additional PCAP or disk evidence is placed under `cases/`, EvilTrace runs the typed tool path against that evidence and records any missing SIFT binary as a limitation instead of confirming unsupported findings.

## 5. Demo

```bash
uv run eviltrace run \
  --case-id sample \
  --case-root ./cases/sample \
  --profile network-first \
  --max-iterations 5
```

Then inspect:

```bash
jq 'select(.event_type=="self_correction_triggered")' artifacts/logs/sample.agent.jsonl
jq '.findings[0].artifacts' artifacts/reports/sample.findings.json
cat artifacts/reports/sample.report.md
```

## 6. Architecture

See `docs/architecture.md` and `docs/architecture.mmd`.

## 7. How Self-Correction Works

EvilTrace validates every candidate finding against provenance, corroboration, graph entities, contradictions, and evidence integrity. Unsupported claims are rejected. Overconfident findings are downgraded to `inferred`. Contradictions or evidence gaps trigger a targeted re-plan until the max-iteration cap is reached.

## 8. Evidence Integrity and Guardrails

- Evidence under `cases/` is treated as read-only.
- Writes are limited to `artifacts/` and `docs/`.
- Forensic command execution uses allowlisted binaries.
- Destructive commands are denied by both code guardrails and Claude Code hooks.
- Tool output is capped and stored under `artifacts/raw/tool-outputs/`.

## 9. Dataset and Accuracy

See `docs/dataset-documentation.md` and `docs/accuracy-report.md`. Large validation evidence is not vendored; the docs point to local placement and run commands.

## 10. Repository Layout

```text
src/eviltrace/      EvilTrace Python package
docs/               Devpost and technical documentation
prompts/            Claude Code prompt pack
scripts/            Setup, benchmark, and validation scripts
data/               Manifests and expected-answer templates
cases/              Local evidence root, read-only by policy
artifacts/          Reports, logs, graphs, raw tool outputs
tests/              Unit and integration tests
```

## 11. Development

```bash
python3 -m pytest
python3 -m compileall -q src
bash scripts/validate_submission.sh
```

## 12. Known Limitations

EvilTrace is a triage and research agent, not a court-ready evidentiary system. Disk and memory wrappers intentionally degrade to `needs_review` until validated local evidence and SIFT tools are present.

## 13. License

MIT.

