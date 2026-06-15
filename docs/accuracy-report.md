# EvilTrace Accuracy Report

## 1. System Version

- Project: EvilTrace
- Run date: generated during repository validation
- MCP server version: 0.1.0

## 2. Validation Methodology

EvilTrace evaluates findings against structured provenance, evidence-integrity hashes, contradiction checks, and machine-comparable known-answer datasets when supplied. The bundled Wireshark DNS sample (`cases/sample/dns.cap`) is used for seconds-scale validation with a machine-comparable ground-truth file (`data/ground_truth/sample.expected.json`); NIST and Nitroba manifests are included for larger local validation runs.

EvilTrace has two execution modes that share the same typed MCP tools, validators, and audit log: (1) the deterministic reference orchestrator (`eviltrace run`), used here for reproducible scoring, which performs rule-based planning/validation with no LLM inference in the loop; and (2) Claude Code headless driving the same MCP server. Token usage is therefore zero for the deterministic path and is captured per turn in the Claude Code mode.

## 3. Cases Tested

| Case | Evidence Type | Ground Truth Source | Used For |
|---|---|---|---|
| Wireshark DNS Sample | PCAP | data/ground_truth/sample.expected.json (independently enumerated DNS names) | Default demo + smoke validation |
| Nitroba University Harassment | PCAP | Published scenario materials | Network validation when evidence is supplied |
| NIST Data Leakage | Disk + removable media | NIST CFReDS answers | Accuracy validation when evidence is supplied |
| NIST Hacking Case | Disk | NIST CFReDS | Secondary validation when evidence is supplied |

## 4. Metrics Summary

| Metric | Current sample run |
|---|---:|
| Finding precision | 1.0 |
| Artifact recall (vs sample ground truth) | 1.0 |
| Hallucination rate in final findings | 0.0 |
| Self-correction success | 1.0 |
| Provenance completeness | 1.0 |
| Evidence integrity | 1.0 (passed) |
| Rejected unsupported findings | 1 |

Artifact recall is computed by intersecting the DNS query names EvilTrace recovered from the PCAP with the independently enumerated DNS names in the sample ground-truth file. Run it yourself:

```bash
uv run eviltrace benchmark \
  --findings artifacts/reports/sample.findings.json \
  --expected data/ground_truth/sample.expected.json \
  --manifest artifacts/reports/sample.case.json
```

## 5. False Positives, Missed Artifacts, and Unsupported Claims

### False positives / unsupported claims

The sample run intentionally creates one overconfident exfiltration candidate (`finding-0001`, as proposed: status `confirmed`, confidence 0.62 in the `finding_proposed` agent-log event; downgraded to confidence 0.1 on rejection) from limited network metadata. Validation rejects it because no stream, HTTP object, or endpoint evidence supports exfiltration (`overclaim:exfiltration_without_direct_support`). It is retained in `rejected_findings` and excluded from the final report. No unsupported claim survives into final findings (hallucination rate 0.0).

### Iteration-over-iteration self-correction

The sample also exercises a multi-iteration correction. In iteration 1 (protocol summary only), `finding-0002` is proposed as `confirmed` from a single artifact; the validator downgrades it to `inferred` (`single_source_overclaim`) and the loop re-plans a targeted DNS extraction. In iteration 2 the same finding is re-evaluated with two corroborating artifacts and upgraded back to `confirmed` — a demonstrable accuracy improvement between the first and final iteration on the same evidence, with the full trace preserved in `artifacts/logs/sample.agent.jsonl` (`stop_reason: validation_passed`, 2 of 3 iterations used).

### Missed artifacts

For the bundled sample, EvilTrace recovered every DNS name in the ground-truth set (artifact recall 1.0). Missed-artifact analysis for Nitroba and NIST is populated once those known-answer cases are run against locally supplied evidence; their `expected_indicators` lists ship empty until then so recall is honestly reported as not measured.

### Hallucinated claims

Findings whose `entities` reference an indicator/host/process absent from the evidence graph are flagged (`entity_not_in_graph:*`) and rejected. None occurred in the sample run.

## 6. Evidence Integrity

How does the architecture prevent original data from being modified? Evidence under `cases/` is never opened for writing: the typed MCP server exposes no write-to-evidence or shell tool, `ensure_write_path` rejects any write resolving under the evidence root, and the PCAP path uses byte-level read-only readers. Every evidence file in a case manifest is hashed (SHA256) at registration and re-verified after the run via `evidence_verify_integrity`. The bundled sample file `cases/sample/dns.cap` has SHA256 `041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`; the latest run reports `evidence_integrity` 1.0 (passed) with no changed or missing files.

Did you test for spoliation? Yes. We attempt to mutate evidence three ways and confirm each is blocked, then confirm the before/after evidence hashes are identical:

1. `GuardrailConfig.ensure_write_path('cases/sample/x')` raises `GuardrailError` (asserted in `tests/test_guardrails.py::test_blocks_writes_to_cases`).
2. A `Write`/`Bash` aimed at `cases/` is blocked by the `PreToolUse` Claude Code hooks (exit 2), which also fail closed when `jq` is unavailable.
3. The post-run `evidence_verify_integrity` reports `changed_files: []`, `missing_files: []`, status `passed` — the SHA256 above is unchanged across the run. No spoliation path was found.

## 7. Guardrail Testing

Architectural guardrails (enforced in code, not by prompt):

- Writing to `cases/` via `GuardrailConfig.ensure_write_path` raises `GuardrailError` (verified in `tests/test_guardrails.py`).
- Non-allowlisted or denied commands (`rm -rf`, redirects into `cases/`, pipe-to-shell) raise `GuardrailError` before any subprocess runs.
- The Claude Code `PreToolUse` hooks independently block writes under `cases/`/`evidence/` and destructive Bash, and fail closed if `jq` is unavailable.
- The typed MCP server exposes no `execute_shell` tool, so the agent physically cannot issue arbitrary commands; this is the primary (architectural) control.

Prompt guardrails (advisory) are secondary: if the model ignores them, the architectural layer still rejects the write/command and the validation engine still rejects the unsupported finding.

## 8. Failure Modes Observed

Documented as signal, not hidden:

- With `tshark` absent, `pcap_http_objects`/`pcap_follow_stream` cannot reconstruct HTTP objects or streams; they degrade to `needs_review` and the gap is recorded as a run limitation rather than being papered over with a confirmed finding.
- The deterministic reference orchestrator emits zero token usage (no LLM in the loop). This is correct, but means the token-usage execution-log requirement is only exercised in the Claude Code headless mode.
- Disk/Windows/memory wrappers are implemented but not validated against known-answer cases in this repository (no large evidence vendored), so their depth is unproven here.
- `windows_prefetch_summary` enumerates filenames only; it deliberately does NOT assert run counts or last-run timestamps, so a naive consumer could under-read execution evidence.

## 9. Limitations

- EvilTrace is a triage/decision-support and research agent, not a court-ready evidentiary system; its machine-authored report requires human validation (consistent with the SANS Protocol SIFT research-stage framing: not validated for forensic soundness or evidentiary reliability).
- The demonstrated depth is the network-first PCAP path. Disk timeline/search tools invoke Sleuth Kit (`fls`/`mactime`) when a disk image and the binaries are present and otherwise degrade to `needs_review`; Windows/memory wrappers degrade to `needs_review` until validated local evidence and SIFT binaries are present. These are implemented but not validated against known answers in this repo.
- Large validation evidence is not vendored in this repository.
