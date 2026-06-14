# Competition Compliance Map

| Required Component | Location | Status |
|---|---|---|
| Code Repository | repository root | Complete |
| Demo Video | `docs/demo-video.md` | Recording-ready; public URL pending |
| Architecture Diagram | `docs/architecture.md`, `docs/architecture.svg` | Complete |
| Written Project Description | `docs/project-story.md` | Complete |
| Dataset Documentation | `docs/dataset-documentation.md` | Complete |
| Accuracy Report | `docs/accuracy-report.md` | Complete |
| Try-It-Out Instructions | `docs/try-it-out.md` | Complete |
| Agent Execution Logs | `artifacts/logs/` | Complete |

## Judging Criteria Mapping

| Criterion | Implementation |
|---|---|
| Autonomous Execution Quality | `src/eviltrace/agent/orchestrator.py`, planner, bounded self-correction |
| IR Accuracy | finding validator, hallucination checker, evidence integrity |
| Breadth and Depth | network-first implementation plus disk, Windows, memory typed wrappers |
| Constraint Implementation | guardrails, hooks, command runner, MCP typed tools |
| Audit Trail Quality | JSONL event logs, audit IDs, raw output hashes |
| Usability and Documentation | README, try-it-out, scripts, submission check |

