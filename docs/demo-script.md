# Demo Script (< 5 minutes, live terminal + audio narration)

Record a screencast of the actual terminal (not slides) against the bundled real capture
`cases/sample/dns.cap`. Every command below works as-is in the repository.

## 0:00-0:20 Opening

Show README and terminal.

Narration: EvilTrace is a self-correcting DFIR agent for Protocol SIFT. Reasoning is treated as
untrusted; all evidence access crosses a trust boundary into a typed MCP server with read-only
guardrails and audit logging. There is no shell-exec tool, so the agent cannot run destructive
commands.

## 0:20-0:50 Architecture and trust boundary

```bash
sed -n '1,40p' docs/architecture.md
```

Highlight the TRUST BOUNDARY edge between the untrusted reasoning zone and the trusted
read-only evidence zone, and the architectural-vs-prompt guardrail split.

## 0:50-1:40 Live run on real evidence

```bash
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 3
```

Narration: The agent registers the case, hashes `dns.cap`, plans a network-first
investigation, and parses the real PCAP (tshark if present, otherwise a read-only built-in
parser recorded in provenance).

## 1:40-2:30 First-pass candidates (iteration 1)

```bash
jq 'select(.iteration==1 and (.event_type=="finding_proposed" or .event_type=="finding_validated"))' artifacts/logs/sample.agent.jsonl
```

Narration: Iteration 1 runs only a protocol summary. From it the agent proposes two
over-confident candidates: an "exfiltration" claim, and a DNS-activity claim asserted as
`confirmed` from a single summary artifact.

## 2:30-3:30 Self-correction across iterations

```bash
jq 'select(.event_type=="self_correction_triggered") | {iteration, action: .output_summary.action, finding: .input.finding_id}' artifacts/logs/sample.agent.jsonl
jq 'select(.event_type=="plan_created") | {iteration, steps: [.output_summary.tool_steps[].tool]}' artifacts/logs/sample.agent.jsonl
```

Narration: The validator **rejects** the exfiltration claim (no stream/object/endpoint
evidence), and **downgrades** the single-source DNS claim from `confirmed` to `inferred`. That
downgrade triggers a **targeted re-plan**: iteration 2 extracts the actual DNS queries. With two
corroborating artifacts the same finding (`finding-0002`) is **upgraded back to `confirmed`** —
demonstrable improvement between the first and final iteration on the same evidence, with full
traces preserved. The rejected claim never enters the final report.

## 3:20-4:05 Provenance drill-down

```bash
jq '.findings[0].artifacts' artifacts/reports/sample.findings.json
head -n 3 artifacts/raw/provenance/sample.provenance.jsonl
```

Narration: Every final finding traces to an `audit_id`, an MCP tool, the source path and SHA256,
and a provenance record with the command, exit code, and output hashes.

## 4:05-4:40 Accuracy and required docs

```bash
uv run eviltrace benchmark --findings artifacts/reports/sample.findings.json --expected data/ground_truth/sample.expected.json --manifest artifacts/reports/sample.case.json
bash scripts/validate_submission.sh
```

Narration: Artifact recall against the ground-truth DNS set is 1.0, hallucination rate is 0,
evidence integrity passed, and all eight required submission components are present.

## 4:40-5:00 Closing

EvilTrace optimizes correctness over overclaiming: unsupported claims are rejected, the full
trace is preserved, and the report is decision-support for a human investigator.
