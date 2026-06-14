from __future__ import annotations

from pathlib import Path


def write_dataset_doc(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        """# Dataset Documentation

## Purpose

This document describes datasets used to evaluate EvilTrace, their source, evidence type, expected findings, and reproducibility notes.

## Dataset Table

| Case | Source | Evidence Type | Ground Truth | Used In Demo | Used In Accuracy |
|---|---|---|---|---|---|
| Wireshark DNS Sample | Wireshark SampleCaptures `dns.cap` | PCAP | Packet-level DNS activity | Yes | Smoke test and provenance demo |
| Nitroba University Harassment | Public classroom / scenario materials | PCAP | Published scenario answer material | Yes, when local PCAP is supplied | Network validation |
| NIST Data Leakage Case | NIST CFReDS | Windows disk + removable media | NIST answer PDF | No | Primary accuracy validation |
| NIST Hacking Case | NIST CFReDS | Disk image | NIST case materials | No | Secondary validation |

## Case 1: Wireshark DNS Sample

Source: https://wiki.wireshark.org/SampleCaptures

Evidence file: `cases/sample/dns.cap`

SHA256: `041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`

Why selected: compact public PCAP with DNS lookups. It lets judges run EvilTrace in seconds and inspect provenance, audit IDs, evidence hashing, and self-correction without downloading large forensic images.

Machine-comparable ground truth: `data/ground_truth/sample.expected.json` lists DNS query names independently enumerated from the public capture, so `eviltrace benchmark --expected` computes a real `artifact_recall` (1.0) against the bundled sample.

Reproduce:

```bash
uv run eviltrace run --case-id sample --case-root ./cases/sample --profile network-first --max-iterations 2
uv run eviltrace benchmark \\
  --findings artifacts/reports/sample.findings.json \\
  --expected data/ground_truth/sample.expected.json \\
  --manifest artifacts/reports/sample.case.json
```

## Case 2: Nitroba University Harassment

Compact PCAP-based case used to demonstrate network artifact extraction, session reconstruction, contradiction detection, and provenance. The repository contains the manifest shape and sample logs; large evidence files must be supplied locally under `cases/nitroba/`.

## Case 3: NIST Data Leakage Case

NIST CFReDS Data Leakage Case includes Windows disk and removable media artifacts and published questions/answers. Store evidence locally under `cases/nist-data-leakage/` and run:

```bash
uv run eviltrace run --case-id nist-data-leakage --case-root ./cases/nist-data-leakage --profile disk-first
```

## Practice Cases

Practice cases are used only for development and qualitative testing. They are not presented as primary validation results unless their ground truth is documented in `data/ground_truth/`.
""",
        encoding="utf-8",
    )
    return target
