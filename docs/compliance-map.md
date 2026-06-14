# Competition Compliance Map

| Required Component | Location | Status |
|---|---|---|
| Code Repository | repository root (public GitHub, MIT license) | Complete |
| Demo Video | `docs/demo-video.md` | Recording-ready against `cases/sample`; public URL must be added before submitting |
| Architecture Diagram | `docs/architecture.md`, `docs/architecture.svg` (labeled trust boundary) | Complete |
| Written Project Description | `docs/project-story.md` | Complete |
| Dataset Documentation | `docs/dataset-documentation.md` | Complete |
| Accuracy Report | `docs/accuracy-report.md` | Complete |
| Try-It-Out Instructions | `docs/try-it-out.md` | Complete |
| Agent Execution Logs | `artifacts/logs/sample.agent.jsonl`, `artifacts/raw/provenance/sample.provenance.jsonl` | Complete |

The only outstanding item is the public demo-video URL, which cannot be produced from inside
the repository — record per `docs/demo-script.md`, upload publicly, and paste the URL into
`docs/demo-video.md`, `README.md`, and the Devpost form.

## Judging Criteria Mapping

| Criterion | Implementation |
|---|---|
| Autonomous Execution Quality | `src/eviltrace/agent/orchestrator.py`, planner, bounded self-correction loop with `--max-iterations`, `alternate_tool`/`targeted_replan`/`finalize_with_limitations` actions, terminal `run_failed`/`run_completed` events |
| IR Accuracy | `finding_validator` (manifest-hash verification, corroboration, overclaim), `contradiction_detector`, `hallucination_checker`, evidence integrity, machine-comparable benchmark |
| Breadth and Depth | validated network-first PCAP path; disk (Sleuth Kit), Windows, and memory typed wrappers with graceful degradation |
| Constraint Implementation | typed MCP server (no shell-exec), command allowlist+denylist, read-only evidence paths, fail-closed Claude Code hooks |
| Audit Trail Quality | JSONL event log, per-tool provenance ledger, audit IDs, raw output hashes, evidence graph provenance chain |
| Usability and Documentation | one-command sample run, `submission-check`, `export-devpost`, complete docs |
