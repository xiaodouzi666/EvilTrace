from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from typing import Any, Callable

from eviltrace.evidence.normalization import artifact_from_tool_result
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.findings.model import Finding
from eviltrace.findings.provenance import reset_provenance_ids
from eviltrace.findings.registry import FindingRegistry
from eviltrace.graph.correlate import (
    add_case_manifest,
    add_finding as add_finding_to_graph,
    add_network_artifact,
    add_tool_execution,
    link_corroborations,
)
from eviltrace.graph.store import GraphStore
from eviltrace.logging.audit_logger import AuditLogger
from eviltrace.logging.run_logger import RunLogger
from eviltrace.logging.token_logger import TokenLogger
from eviltrace.mcp_server.command_runner import CommandRunner
from eviltrace.mcp_server.guardrails import GuardrailConfig
from eviltrace.mcp_server.tools.case_tools import case_register
from eviltrace.mcp_server.tools.common import ToolContext
from eviltrace.mcp_server.tools.disk_tools import disk_image_info, disk_search_files, disk_timeline
from eviltrace.mcp_server.tools.evidence_tools import evidence_verify_integrity
from eviltrace.mcp_server.tools.memory_tools import memory_volatility_plugin
from eviltrace.mcp_server.tools.network_tools import pcap_dns_queries, pcap_follow_stream, pcap_http_objects, pcap_summary
from eviltrace.mcp_server.tools.windows_tools import windows_evtx_query, windows_prefetch_summary, windows_run_keys, windows_usb_history
from eviltrace.reporting.report_generator import generate_markdown_report
from eviltrace.validators.benchmark import compute_metrics
from eviltrace.validators.finding_validator import FindingValidator

from .planner import InvestigationPlanner
from .self_correction import SelfCorrectionEngine
from .state import RunState


def _utc_run_id() -> str:
    return "run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


class EvilTraceOrchestrator:
    def __init__(
        self,
        *,
        workspace: str | Path = ".",
        evidence_root: str | Path = "cases",
        artifact_root: str | Path = "artifacts",
    ) -> None:
        self.paths = WorkspacePaths.from_workspace(workspace, evidence_root, artifact_root)
        self.paths.ensure()
        self.planner = InvestigationPlanner()
        self.validator = FindingValidator()
        self.correction = SelfCorrectionEngine()

    def run(
        self,
        *,
        case_id: str,
        case_root: str,
        profile: str = "network-first",
        max_iterations: int = 5,
        description: str = "",
        output: str | None = None,
    ) -> dict[str, Any]:
        run_id = _utc_run_id()
        reports_dir = self.paths.reports_dir if output is None else Path(output)
        reports_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.paths.logs_dir / f"{case_id}.agent.jsonl"
        if log_path.exists():
            log_path.unlink()
        logger = AuditLogger(log_path=log_path, run_id=run_id, case_id=case_id)
        provenance = RunLogger(self.paths, case_id)
        provenance.reset()
        reset_provenance_ids()
        guardrails = GuardrailConfig(self.paths)
        runner = CommandRunner(guardrails, logger, provenance)
        ctx = ToolContext(self.paths, logger, guardrails, runner, provenance=provenance)
        token_logger = TokenLogger()
        state = RunState(case_id=case_id, run_id=run_id, profile=profile, max_iterations=max_iterations)
        state.registry = FindingRegistry(case_id)

        try:
            return self._run_body(
                case_id=case_id,
                case_root=case_root,
                profile=profile,
                max_iterations=max_iterations,
                description=description,
                run_id=run_id,
                reports_dir=reports_dir,
                log_path=log_path,
                logger=logger,
                provenance=provenance,
                ctx=ctx,
                token_logger=token_logger,
                state=state,
            )
        except Exception as exc:  # emit a terminal failure event so the audit trail is never left open
            logger.log_event(
                "run_failed",
                iteration=state.iteration,
                input_data={"case_id": case_id},
                output_summary={"error_type": type(exc).__name__, "error": str(exc)},
                status="error",
            )
            raise

    def _run_body(
        self,
        *,
        case_id: str,
        case_root: str,
        profile: str,
        max_iterations: int,
        description: str,
        run_id: str,
        reports_dir: Path,
        log_path: Path,
        logger: AuditLogger,
        provenance: RunLogger,
        ctx: ToolContext,
        token_logger: TokenLogger,
        state: RunState,
    ) -> dict[str, Any]:
        logger.log_event("run_started", input_data={"case_id": case_id, "case_root": case_root, "profile": profile}, output_summary={"run_id": run_id})
        case_type = "network" if profile == "network-first" else "disk"
        registered = case_register(ctx, case_id=case_id, case_root=case_root, case_type=case_type, description=description)
        manifest_path = self.paths.workspace / registered["manifest_path"]
        state.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        ctx.manifest = state.manifest
        add_case_manifest(state.graph, state.manifest)
        case_tool_node = add_tool_execution(state.graph, registered["audit_id"], "case_register")
        state.graph.add_edge(f"case-{case_id}", case_tool_node, "PRODUCED_BY")

        if not state.manifest.get("evidence"):
            state.limitations.append("No local evidence files were found under the supplied case root.")

        for iteration in range(1, max_iterations + 1):
            state.iteration = iteration
            ctx.iteration = iteration
            plan = self.planner.create_plan(state)
            logger.log_event(
                "plan_created",
                iteration=iteration,
                input_data={"profile": profile, "targeted_replan": state.targeted_replan or {}},
                output_summary={"plan_id": plan.plan_id, "tool_steps": plan.tool_steps, "rationale": plan.rationale},
            )
            state.targeted_replan = None

            new_artifacts, failures = self._execute_plan(plan.tool_steps, ctx, state)
            state.artifacts.extend(new_artifacts)
            if new_artifacts:
                logger.log_event("artifact_normalized", iteration=iteration, output_summary={"new_artifacts": [a["artifact_id"] for a in new_artifacts]})
                for artifact in new_artifacts:
                    add_network_artifact(state.graph, artifact)
                link_corroborations(state.graph)
                logger.log_event("graph_updated", iteration=iteration, output_summary={"nodes": len(state.graph.nodes), "edges": len(state.graph.edges)})

            correction_triggered = self._handle_tool_failures(failures, ctx, state, logger, iteration, max_iterations)

            candidates = self._propose_findings(state, new_artifacts)
            for finding in candidates:
                logger.log_event(
                    "finding_proposed",
                    iteration=iteration,
                    input_data={"finding_id": finding.finding_id},
                    output_summary={"status": finding.status, "confidence": finding.confidence, "audit_ids": finding.audit_ids},
                )
                outcome = self.validator.validate(finding, state.graph, state.manifest)
                finding.validation = outcome.to_dict()
                state.validation_results.append(outcome.to_dict())
                logger.log_event(
                    "finding_validated",
                    iteration=iteration,
                    input_data={"finding_id": finding.finding_id},
                    output_summary=outcome.to_dict(),
                    status="success",
                )
                if outcome.contradicted_by:
                    logger.log_event(
                        "contradiction_detected",
                        iteration=iteration,
                        input_data={"finding_id": finding.finding_id},
                        output_summary={"contradicted_by": outcome.contradicted_by, "reason": outcome.reason},
                        status="success",
                    )
                decision = self.correction.decide(finding, outcome, max_iterations_reached=(iteration >= max_iterations))
                if decision.action != "accept_validation":
                    correction_triggered = True
                    logger.log_event(
                        "self_correction_triggered",
                        iteration=iteration,
                        input_data={"finding_id": finding.finding_id},
                        output_summary=decision.to_dict(),
                        status="success",
                    )
                    state.corrections.append(decision.to_dict())
                    finding.status = decision.new_status
                    finding.confidence = outcome.confidence
                    finding.reasoning_note = decision.reason
                    if decision.action == "downgrade_to_inferred":
                        finding.limitations = "The initial conclusion language was stronger than the available evidence; the finding was downgraded."
                        # The downgrade IS the remediation for overclaim/single-source markers, so move
                        # them out of unsupported_claims (preserved under remediated_claims) — otherwise a
                        # kept-but-downgraded finding would inflate hallucination_rate.
                        remediated = [c for c in (finding.validation.get("unsupported_claims") or []) if c.startswith("overclaim:") or c == "single_source_overclaim"]
                        if remediated:
                            finding.validation = {
                                **finding.validation,
                                "remediated_claims": remediated,
                                "unsupported_claims": [c for c in finding.validation.get("unsupported_claims", []) if c not in remediated],
                            }
                    elif decision.action == "reject_finding":
                        finding.limitations = "Rejected because validation found unsupported claims or missing provenance."
                    if decision.targeted_replan:
                        state.targeted_replan = decision.targeted_replan
                else:
                    finding.status = outcome.recommended_status
                    finding.confidence = outcome.confidence

                assert state.registry is not None
                state.registry.add(finding)
                add_finding_to_graph(state.graph, finding.to_dict())
                logger.log_event(self._finding_event_type(finding.status), iteration=iteration, input_data={"finding_id": finding.finding_id}, output_summary=finding.to_dict())

            if not state.targeted_replan:
                state.stop_reason = "no_further_correction_needed" if correction_triggered else "validation_passed"
                break
            if iteration >= max_iterations:
                state.stop_reason = "max_iterations_reached"
                logger.log_event(
                    "self_correction_triggered",
                    iteration=iteration,
                    input_data={"pending_replan": state.targeted_replan},
                    output_summary={"action": "finalize_with_limitations", "reason": "Iteration budget exhausted with a pending re-plan."},
                    status="success",
                )
                state.corrections.append({"action": "finalize_with_limitations", "reason": "max_iterations_reached"})
                break

        integrity = evidence_verify_integrity(ctx, manifest=state.manifest)
        expected = self._load_expected(case_id)
        final_dicts = [f.to_dict() for f in (state.registry.all_for_validation() if state.registry else [])]
        metrics = compute_metrics(final_dicts, expected, integrity)
        validation_summary = {
            "case_id": case_id,
            "run_id": run_id,
            "stop_reason": state.stop_reason,
            "iterations": state.iteration,
            "validation_results": state.validation_results,
            "corrections": state.corrections,
            "evidence_integrity": integrity,
            "metrics": metrics,
            "limitations": state.limitations,
            "token_usage": token_logger.summary(),
        }

        graph_path = self.paths.graphs_dir / f"{case_id}.graph.json"
        GraphStore(state.graph).export_json(graph_path)
        findings_path = reports_dir / f"{case_id}.findings.json"
        findings = state.registry.to_dict() if state.registry else {"case_id": case_id, "findings": [], "rejected_findings": []}
        findings_path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validation_path = reports_dir / f"{case_id}.validation.json"
        validation_path.write_text(json.dumps(validation_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report_path = reports_dir / f"{case_id}.report.md"
        generate_markdown_report(
            case_id=case_id,
            run_id=run_id,
            manifest=state.manifest or {},
            findings=findings,
            validation=validation_summary,
            graph_path=self.paths.relative_to_workspace(graph_path),
            log_path=self.paths.relative_to_workspace(log_path),
            output_path=report_path,
            limitations=state.limitations,
        )

        run_summary = {
            "case_id": case_id,
            "run_id": run_id,
            "profile": profile,
            "iterations": state.iteration,
            "max_iterations": max_iterations,
            "stop_reason": state.stop_reason,
            "final_findings": len(findings.get("findings", [])),
            "rejected_findings": len(findings.get("rejected_findings", [])),
            "self_correction_events": len(state.corrections),
            "evidence_integrity": integrity.get("integrity_status", integrity.get("status")),
            "metrics": metrics,
            "token_usage": token_logger.summary(),
            "limitations": state.limitations,
        }
        provenance.write_run_summary(run_summary)

        logger.log_event(
            "report_generated",
            output_summary={
                "report_path": self.paths.relative_to_workspace(report_path),
                "findings_path": self.paths.relative_to_workspace(findings_path),
                "graph_path": self.paths.relative_to_workspace(graph_path),
                "validation_path": self.paths.relative_to_workspace(validation_path),
                "provenance_path": self.paths.relative_to_workspace(provenance.provenance_path),
                "run_summary_path": self.paths.relative_to_workspace(provenance.run_summary_path),
            },
        )
        logger.log_event("run_completed", output_summary={"case_id": case_id, "run_id": run_id, "stop_reason": state.stop_reason}, status="success")

        return {
            "case_id": case_id,
            "run_id": run_id,
            "stop_reason": state.stop_reason,
            "iterations": state.iteration,
            "log_path": self.paths.relative_to_workspace(log_path),
            "report_path": self.paths.relative_to_workspace(report_path),
            "findings_path": self.paths.relative_to_workspace(findings_path),
            "graph_path": self.paths.relative_to_workspace(graph_path),
            "validation_path": self.paths.relative_to_workspace(validation_path),
            "provenance_path": self.paths.relative_to_workspace(provenance.provenance_path),
            "run_summary_path": self.paths.relative_to_workspace(provenance.run_summary_path),
            "final_findings": len(findings.get("findings", [])),
            "rejected_findings": len(findings.get("rejected_findings", [])),
        }

    @staticmethod
    def _finding_event_type(status: str) -> str:
        return {
            "rejected": "finding_rejected",
            "confirmed": "finding_confirmed",
            "inferred": "finding_inferred",
            "needs_review": "finding_needs_review",
        }.get(status, "finding_finalized")

    def _load_expected(self, case_id: str) -> dict[str, Any]:
        expected_path = self.paths.workspace / "data" / "ground_truth" / f"{case_id}.expected.json"
        if expected_path.exists():
            try:
                return json.loads(expected_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return {}
        return {}

    def _handle_tool_failures(
        self,
        failures: list[dict[str, Any]],
        ctx: ToolContext,
        state: RunState,
        logger: AuditLogger,
        iteration: int,
        max_iterations: int,
    ) -> bool:
        triggered = False
        pcaps = [row for row in (state.manifest or {}).get("evidence", []) if row.get("detected_type") == "pcap"]
        for failure in failures:
            tool = failure["tool"]
            decision = self.correction.decide_tool_failure(
                tool=tool,
                status=failure["status"],
                reason=failure["reason"],
                max_iterations_reached=(iteration >= max_iterations),
            )
            replan = decision.targeted_replan or {}
            binary = replan.get("binary")
            viable = (
                decision.action == "alternate_tool"
                and bool(replan.get("tool"))
                and not state.tried_alternate.get(tool)
                and (binary is None or shutil.which(binary) is not None)
                and iteration < max_iterations
            )
            if viable and replan.get("tool") == "pcap_follow_stream" and pcaps:
                state.tried_alternate[tool] = True
                triggered = True
                state.targeted_replan = {"tool": "pcap_follow_stream", "pcap_path": pcaps[0]["path"], "stream_id": 0}
                logger.log_event(
                    "self_correction_triggered",
                    iteration=iteration,
                    input_data={"failed_tool": tool},
                    output_summary=decision.to_dict(),
                    status="success",
                )
                state.corrections.append(decision.to_dict())
            else:
                state.limitations.append(f"{tool}: {failure['reason']}")
        return triggered

    def _execute_plan(self, steps: list[dict[str, Any]], ctx: ToolContext, state: RunState) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        tools: dict[str, Callable[..., dict[str, Any]]] = {
            "evidence_verify_integrity": evidence_verify_integrity,
            "pcap_summary": pcap_summary,
            "pcap_dns_queries": pcap_dns_queries,
            "pcap_http_objects": pcap_http_objects,
            "pcap_follow_stream": pcap_follow_stream,
            "disk_image_info": disk_image_info,
            "disk_timeline": disk_timeline,
            "disk_search_files": disk_search_files,
            "windows_evtx_query": windows_evtx_query,
            "windows_prefetch_summary": windows_prefetch_summary,
            "windows_usb_history": windows_usb_history,
            "windows_run_keys": windows_run_keys,
            "memory_volatility_plugin": memory_volatility_plugin,
        }
        artifacts: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for step in steps:
            name = step["tool"]
            func = tools[name]
            result = func(ctx, **step.get("input", {}))
            state.tool_results.append({"tool": name, "result": result})
            artifact = self._artifact_from_result(name, result, len(state.artifacts) + len(artifacts) + 1)
            if artifact:
                artifacts.append(artifact)
            elif result.get("status") in {"tool_missing", "tool_error", "needs_review", "timeout", "blocked"}:
                reason = result.get("reason") or result.get("fallback_reason") or result.get("status")
                failures.append({"tool": name, "status": result.get("status"), "reason": reason})
        return artifacts, failures

    def _artifact_from_result(self, tool_name: str, result: dict[str, Any], index: int) -> dict[str, Any] | None:
        if result.get("status") != "success":
            return None
        if not result.get("source_path") or not result.get("source_sha256") or not result.get("audit_id"):
            return None
        artifact_type_by_tool = {
            "pcap_summary": "pcap_summary",
            "pcap_dns_queries": "dns_query",
            "pcap_http_objects": "http_object",
            "pcap_follow_stream": "pcap_stream",
        }
        artifact_type = artifact_type_by_tool.get(tool_name)
        if not artifact_type:
            return None
        summary: dict[str, Any] = {}
        if tool_name == "pcap_summary":
            summary = {"protocols": result.get("protocols", []), "packet_count": result.get("packet_count"), "hosts": [], "network_indicators": []}
        elif tool_name == "pcap_dns_queries":
            queries = result.get("queries", [])
            summary = {"query_count": len(queries), "network_indicators": [q.get("query") for q in queries if q.get("query")]}
        elif tool_name == "pcap_http_objects":
            summary = {"object_count": len(result.get("objects", []))}
        elif tool_name == "pcap_follow_stream":
            summary = {"stream_id": result.get("stream_id"), "preview_available": bool(result.get("text_preview"))}
        return artifact_from_tool_result(
            artifact_id=f"artifact-{index:04d}",
            artifact_type=artifact_type,
            source_path=result["source_path"],
            source_sha256=result["source_sha256"],
            tool=result.get("underlying_tool", "tshark"),
            mcp_tool=tool_name,
            audit_id=result["audit_id"],
            raw_output_path=result.get("raw_output_path"),
            offset_or_record=f"tcp.stream eq {result.get('stream_id')}" if tool_name == "pcap_follow_stream" else None,
            summary=summary,
        )

    def _propose_findings(self, state: RunState, new_artifacts: list[dict[str, Any]]) -> list[Finding]:
        candidates: list[Finding] = []
        base_index = len(state.registry.all_for_validation()) if state.registry else 0
        if new_artifacts:
            weak_support = new_artifacts[:1]
            candidates.append(
                Finding(
                    finding_id=f"finding-{base_index + 1:04d}",
                    case_id=state.case_id,
                    title="Unsupported exfiltration overclaim",
                    category="network",
                    status="confirmed",
                    confidence=0.62,
                    summary="A first-pass candidate used exfiltration language from limited network metadata and must be rejected unless direct stream, object, or endpoint evidence exists.",
                    artifacts=weak_support,
                    entities={"hosts": [], "users": [], "processes": [], "files": [], "network_indicators": []},
                    reasoning_note="Initial candidate generated to demonstrate validation and self-correction.",
                    limitations="Exfiltration is not asserted without direct transferred-content or endpoint corroboration.",
                )
            )

            dns_artifacts = [artifact for artifact in new_artifacts if artifact.get("artifact_type") == "dns_query"]
            summary_artifacts = [artifact for artifact in new_artifacts if artifact.get("artifact_type") == "pcap_summary"]
            factual_support = (summary_artifacts[:1] + dns_artifacts[:1]) or new_artifacts[:1]
            if dns_artifacts:
                query_count = dns_artifacts[0].get("summary", {}).get("query_count", 0)
                candidates.append(
                    Finding(
                        finding_id=f"finding-{base_index + 2:04d}",
                        case_id=state.case_id,
                        title="DNS query activity observed in PCAP evidence",
                        category="network",
                        status="confirmed",
                        confidence=0.86,
                        summary=f"EvilTrace parsed DNS metadata from the PCAP and observed {query_count} DNS query artifact(s).",
                        artifacts=factual_support,
                        entities={"hosts": [], "users": [], "processes": [], "files": [], "network_indicators": dns_artifacts[0].get("summary", {}).get("network_indicators", [])[:10]},
                        reasoning_note="The finding is limited to observed DNS activity and does not assert compromise or exfiltration.",
                        limitations="DNS activity alone is network context, not proof of compromise.",
                    )
                )
            else:
                candidates.append(
                    Finding(
                        finding_id=f"finding-{base_index + 2:04d}",
                        case_id=state.case_id,
                        title="Network packets parsed from PCAP evidence",
                        category="network",
                        status="inferred",
                        confidence=0.55,
                        summary="EvilTrace parsed packet metadata from the supplied PCAP evidence.",
                        artifacts=factual_support,
                        entities={"hosts": [], "users": [], "processes": [], "files": [], "network_indicators": []},
                        reasoning_note="This finding stays at inferred unless corroborating protocol-specific artifacts are available.",
                        limitations="Packet metadata alone does not establish incident impact.",
                    )
                )
        elif state.iteration == 1:
            candidates.append(
                Finding(
                    finding_id="finding-0001",
                    case_id=state.case_id,
                    title="Unsupported incident claim",
                    category="case_intake",
                    status="candidate",
                    confidence=0.2,
                    summary="No local evidence artifact is available to support an incident finding.",
                    artifacts=[],
                    reasoning_note="The agent must reject this candidate because no evidence was provided.",
                    limitations="Supply case evidence under the case root to perform DFIR analysis.",
                )
            )
        return candidates
