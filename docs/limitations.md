# Limitations

EvilTrace is built for autonomous triage and research workflows. It does not claim court-ready forensic soundness.

Known limitations:

- Large public forensic evidence is not stored in the repository.
- Disk and memory wrappers need local evidence plus SIFT tools to produce full artifact detail.
- Encrypted, corrupted, or unsupported formats may be marked `needs_review`.
- Confidence scores are rule-based and intended for triage.
- Prompt guardrails are secondary; architectural guardrails enforce evidence and command constraints.

