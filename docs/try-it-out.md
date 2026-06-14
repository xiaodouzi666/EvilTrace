# Try EvilTrace

EvilTrace ships with a small public Wireshark `dns.cap` capture under `cases/sample/`, so the
quick start below reproduces real findings in seconds with no large downloads.

## Dependencies

- Python 3.11+ and either `uv` (recommended) or `pip`.
- `jq` is required for the Claude Code guardrail hooks (they fail closed without it).
- `tshark` (Wireshark) is optional: if absent, EvilTrace uses a built-in read-only PCAP/DNS
  parser and records the fallback in provenance. Sleuth Kit (`mmls`, `fls`, `mactime`) is only
  needed for the disk tools.

## Option A: uv (recommended)

```bash
uv sync
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
uv run eviltrace submission-check
```

## Option B: pip

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
eviltrace submission-check
```

## Inspect the bundled sample outputs

```bash
cat artifacts/reports/sample.report.md
jq '.findings[0].artifacts' artifacts/reports/sample.findings.json
jq 'select(.event_type=="self_correction_triggered")' artifacts/logs/sample.agent.jsonl
jq . artifacts/reports/sample.run.json
head artifacts/raw/provenance/sample.provenance.jsonl
```

## Measure accuracy against machine-comparable ground truth

```bash
uv run eviltrace benchmark \
  --findings artifacts/reports/sample.findings.json \
  --expected data/ground_truth/sample.expected.json \
  --manifest artifacts/reports/sample.case.json
```

This computes a real `artifact_recall` (1.0) by intersecting recovered DNS names with the
independently enumerated ground-truth names in `data/ground_truth/sample.expected.json`.

## Option C: your own / larger cases (requires local evidence)

The Nitroba and NIST cases are **not vendored**. Place evidence locally and run, e.g.:

```bash
# Requires you to supply the PCAP under cases/nitroba/
uv run eviltrace run --case-id nitroba --case-root ./cases/nitroba --profile network-first --max-iterations 5

# Requires you to supply the disk image under cases/nist-data-leakage/
uv run eviltrace run --case-id nist-data-leakage --case-root ./cases/nist-data-leakage --profile disk-first
```

If a required SIFT binary or the evidence is missing, the corresponding tool degrades to
`needs_review` and the gap is recorded as a limitation instead of producing an unsupported
finding.

## Pre-generated sample run (no setup)

For judges who do not want to run anything, the committed sample outputs are:

- `artifacts/reports/sample.report.md`
- `artifacts/reports/sample.findings.json`
- `artifacts/reports/sample.validation.json`
- `artifacts/reports/sample.run.json`
- `artifacts/graphs/sample.graph.json`
- `artifacts/logs/sample.agent.jsonl`
- `artifacts/raw/provenance/sample.provenance.jsonl`
