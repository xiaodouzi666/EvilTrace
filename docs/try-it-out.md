# Try EvilTrace

## Option A: Local Python Environment

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
eviltrace run --case-id demo --case-root ./cases/demo --profile network-first --max-iterations 2
eviltrace submission-check
```

## Option B: uv

```bash
uv sync
uv run eviltrace run \
  --case-id demo \
  --case-root ./cases/demo \
  --profile network-first \
  --max-iterations 2
```

## Option C: SIFT Workstation With Local Evidence

Place PCAP evidence under `cases/nitroba/`, then run:

```bash
uv run eviltrace run \
  --case-id nitroba-demo \
  --case-root ./cases/nitroba \
  --profile network-first \
  --max-iterations 5
```

Inspect outputs:

```bash
cat artifacts/reports/nitroba-demo.report.md
jq . artifacts/reports/nitroba-demo.findings.json
less artifacts/logs/nitroba-demo.agent.jsonl
```

## Pre-Generated Sample Run

For judges who do not want to download large evidence files, inspect the generated sample outputs:

- `artifacts/reports/sample.report.md`
- `artifacts/reports/sample.findings.json`
- `artifacts/reports/sample.validation.json`
- `artifacts/graphs/sample.graph.json`
- `artifacts/logs/sample.agent.jsonl`

The sample run is explicitly marked as a no-local-evidence run when local evidence is absent.

