# Limitations

EvilTrace is built for autonomous **triage and decision-support**, not as a replacement for an
investigator. Its machine-authored report requires human validation. It does not claim
court-ready forensic soundness — consistent with the SANS Protocol SIFT research-stage framing
(augment, never replace the practitioner; not validated for forensic soundness or evidentiary
reliability).

Known limitations:

- The demonstrated depth is the network-first PCAP path, validated on the bundled `dns.cap`
  sample with a machine-comparable ground-truth set. Disk timeline/search tools invoke Sleuth
  Kit (`fls`/`mactime`) when a disk image and the binaries are present, and otherwise degrade
  to `needs_review`; Windows/memory wrappers degrade to `needs_review` until validated local
  evidence and SIFT binaries are present. These are implemented but not validated against known
  answers in this repository.
- Large public forensic evidence (Nitroba, NIST) is not vendored; their ground-truth
  `expected_indicators` lists ship empty, so `artifact_recall` is honestly reported as not
  measured until local evidence is supplied.
- The reproducible `eviltrace run` is a deterministic reference orchestrator: it performs no LLM
  inference in the loop, so its `token_usage` is zero by construction. Token usage is captured
  when the same typed MCP tools are driven by Claude Code headless.
- `windows_prefetch_summary` enumerates prefetch filenames only; it does not parse run counts or
  last-run timestamps, and annotates this so downstream findings do not assert them.
- Encrypted, corrupted, or unsupported formats may be marked `needs_review`.
- Confidence scores are rule-based and intended for triage.
- Prompt guardrails are secondary; architectural guardrails (typed MCP, allowlist, read-only
  evidence) enforce evidence and command constraints.
