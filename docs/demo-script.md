# Demo Script — recorded live on the SANS SIFT Workstation (< 5 min)

This is the exact screencast script. It was recorded inside the real SANS SIFT Workstation
(Ubuntu 24.04, Python 3.12), where EvilTrace runs against SIFT's native tools (real `tshark`,
`vol`, `mmls`, `fls`, `jq`). Every command below is a **single line** — type it on one line (do
not let `--max-iterations 3` wrap onto a new line) so the terminal output matches this script.

## Setup (before recording)

If the SIFT Workstation is a headless VM, SSH into it and activate the environment:

```bash
ssh -p 2222 sansforensics@127.0.0.1      # SIFT default password: forensics
cd ~/eviltrace && source .venv/bin/activate
```

The prompt becomes `sansforensics@siftworkstation` — proof you are on the real SIFT box. Rehearse
the whole flow once with `bash ~/demo.sh`.

---

## 0:00–0:10 Opening

> EvilTrace is a self-correcting, evidence-grounded DFIR agent for Protocol SIFT, running live on
> the SANS SIFT Workstation.

## 0:10–0:30 STEP 1 — this is the real SIFT Workstation

```bash
hostname; grep PRETTY_NAME /etc/os-release; for b in tshark vol mmls fls jq; do printf "  %-8s " "$b"; command -v "$b"; done
```

Output: `siftworkstation`, `Ubuntu 24.04.4 LTS`, and real paths for tshark/vol/mmls/fls/jq.

> We're on the real SIFT Workstation. EvilTrace uses SIFT's native forensic tools through a typed
> MCP layer.

## 0:30–0:50 STEP 2 — architecture / trust boundary

```bash
grep -nE "Custom MCP Server|TRUST BOUNDARY|execute_shell" docs/architecture.md | head -3
```

Output includes: `TRUST BOUNDARY: typed tools only, no execute_shell`.

> The design choice that matters: there is no execute_shell tool. The agent physically cannot run
> destructive commands — evidence access crosses a typed MCP trust boundary.

## 0:50–1:20 STEP 3 — one command, live investigation (type on ONE line)

```bash
time eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 3
```

Output: JSON with `"final_findings": 1, "rejected_findings": 1, "iterations": 2,
"stop_reason": "validation_passed"`, then `real 0m0.5s`.

> One command registers the case, hashes the evidence, and runs a bounded self-correcting
> investigation against the PCAP — in about half a second. Threats strike in minutes; this
> responds in seconds.

## 1:20–2:20 STEP 4 — self-correction across iterations (the key beat)

```bash
jq -c 'select(.event_type|test("self_correction_triggered|finding_rejected|finding_inferred|finding_confirmed")) | {it:.iteration, event:.event_type, action:.output_summary.action}' artifacts/logs/sample.agent.jsonl
```

Output:

```
{"it":1,"event":"self_correction_triggered","action":"reject_finding"}
{"it":1,"event":"finding_rejected","action":null}
{"it":1,"event":"self_correction_triggered","action":"downgrade_to_inferred"}
{"it":1,"event":"finding_inferred","action":null}
{"it":2,"event":"finding_confirmed","action":null}
```

> Here's the self-correction. Iteration one: it rejects an over-confident exfiltration claim that
> has no supporting evidence, and downgrades a single-source DNS finding from confirmed to
> inferred. That downgrade triggers a targeted re-plan. Iteration two extracts the actual DNS
> queries, and the same finding is upgraded back to confirmed — demonstrable improvement between
> the first and final iteration, with the full trace preserved.

## 2:20–3:10 STEP 5 — provenance: finding → real tshark → evidence hash

```bash
jq '.findings[0].artifacts[] | {artifact_id, mcp_tool, audit_id, source_sha256}' artifacts/reports/sample.findings.json
```

```bash
jq -c '{mcp_tool, underlying_tool, command_redacted}' artifacts/raw/provenance/sample.provenance.jsonl
```

Output: the provenance records show `"underlying_tool":"tshark"` and the exact command, e.g.
`tshark -r .../dns.cap -Y dns.flags.response == 0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name`.

> Every finding traces to an audit ID, the source file's SHA-256, and a provenance record with the
> exact tshark command that produced it. A judge can follow any finding back to the real tool
> execution.

## 3:10–3:40 STEP 6 — accuracy vs known-answer ground truth

```bash
eviltrace benchmark --findings artifacts/reports/sample.findings.json --expected data/ground_truth/sample.expected.json --manifest artifacts/reports/sample.case.json
```

Output: `artifact_recall 1.0, hallucination_rate 0.0, finding_precision 1.0, evidence_integrity 1.0`.

> Against a known-answer DNS set, artifact recall is one-point-zero and the hallucination rate in
> final findings is zero.

## 3:40–4:05 STEP 7 — evidence is architecturally read-only

```bash
python - <<'EOF'
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.mcp_server.guardrails import GuardrailConfig, GuardrailError
g = GuardrailConfig(WorkspacePaths.from_workspace("."))
try:
    g.ensure_write_path("cases/sample/tampered.txt"); print("not blocked")
except GuardrailError as e:
    print("BLOCKED:", e)
EOF
```

Output: `BLOCKED: Evidence path is read-only: cases/sample/tampered.txt`.

> Evidence is architecturally read-only — any attempt to write into the case directory is
> rejected. Zero spoliation risk.

## 4:05–4:40 STEP 8 + closing — all required components

```bash
eviltrace submission-check
```

Output: a column of `PASS:` lines covering all eight required submission components.

> All required submission components are present, and everything you just saw is reproducible on
> the SIFT Workstation. EvilTrace optimizes correctness over overclaiming — that's the defender we
> need at machine speed.

---

## Recording tips

- Check the mic; speak slowly; pause on STEP 4 (the self-correction is the highest-weighted beat).
- Run STEP 3 → 8 strictly in order: STEP 3 regenerates the artifacts that STEP 4–8 read.
- Keep each command on one physical line so nothing wraps into a stray "command not found".
- To trim under 5 minutes, shorten STEP 2 and STEP 8 to ~10 seconds each.
