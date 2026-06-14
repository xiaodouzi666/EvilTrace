# Demo Script

## 0:00-0:20 Opening

Show README and terminal.

Narration: EvilTrace is a self-correcting DFIR agent for Protocol SIFT. Claude Code orchestrates the investigation, but evidence access goes through typed MCP tools with read-only guardrails and audit logging.

## 0:20-0:50 Architecture

```bash
cat docs/architecture.md
```

Highlight Claude Code, typed MCP, SIFT tools, evidence graph, validation, self-correction, and output pipeline.

## 0:50-1:30 Live Run

```bash
uv run eviltrace run \
  --case-id nitroba-demo \
  --case-root ./cases/nitroba \
  --profile network-first \
  --max-iterations 5
```

## 1:30-2:25 First-Pass Candidate

Show `finding_proposed` and `finding_validated` events in the JSONL log.

## 2:25-3:20 Self-Correction

```bash
jq 'select(.event_type=="self_correction_triggered")' artifacts/logs/nitroba-demo.agent.jsonl
```

Narration: EvilTrace catches unsupported or overconfident language, rejects or downgrades it, and performs targeted re-planning when evidence exists.

## 3:20-4:00 Provenance Drill-Down

```bash
jq '.findings[0].artifacts' artifacts/reports/nitroba-demo.findings.json
```

Show `audit_id`, `mcp_tool`, `source_path`, `source_sha256`, and `raw_output_path`.

## 4:00-4:40 Final Report and Required Docs

```bash
ls docs
bash scripts/validate_submission.sh
```

## 4:40-5:00 Closing

EvilTrace optimizes correctness over overclaiming. Unsupported claims are rejected or downgraded, and the trace is preserved for review.

