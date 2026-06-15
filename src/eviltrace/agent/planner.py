from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .state import RunState


@dataclass
class InvestigationPlan:
    plan_id: str
    iteration: int
    profile: str
    tool_steps: list[dict[str, Any]] = field(default_factory=list)
    rationale: str = ""


class InvestigationPlanner:
    def create_plan(self, state: RunState) -> InvestigationPlan:
        plan_id = f"plan-{state.iteration:03d}"
        manifest = state.manifest or {"evidence": []}
        evidence = manifest.get("evidence", [])
        steps: list[dict[str, Any]] = []

        if state.targeted_replan:
            target = state.targeted_replan
            if target.get("tool") == "pcap_dns_queries" and target.get("pcap_path"):
                steps.append(
                    {"tool": "pcap_dns_queries", "input": {"pcap_path": target["pcap_path"], "domain_filter": None}}
                )
            elif target.get("tool") == "pcap_follow_stream" and target.get("pcap_path"):
                steps.append(
                    {
                        "tool": "pcap_follow_stream",
                        "input": {"pcap_path": target["pcap_path"], "stream_id": int(target.get("stream_id", 0)), "protocol": "tcp"},
                    }
                )
            return InvestigationPlan(plan_id, state.iteration, state.profile, steps, "Targeted re-plan to corroborate a downgraded finding.")

        pcaps = [row for row in evidence if row.get("detected_type") == "pcap"]
        disks = [row for row in evidence if row.get("detected_type") in {"ewf_disk_image", "raw_image"}]
        if state.profile == "network-first" and pcaps:
            pcap_path = pcaps[0]["path"]
            # First pass is intentionally summary-only: a single protocol-summary artifact is not
            # enough to confirm, so the validation engine downgrades the candidate and the loop
            # re-plans a targeted DNS extraction on the next iteration (see self_correction).
            steps.extend(
                [
                    {"tool": "pcap_summary", "input": {"pcap_path": pcap_path, "limit": 200}},
                    {"tool": "pcap_http_objects", "input": {"pcap_path": pcap_path, "export_dir": "artifacts/raw/http-objects"}},
                ]
            )
        elif disks:
            steps.append({"tool": "disk_image_info", "input": {"image_path": disks[0]["path"]}})
        else:
            steps.append({"tool": "evidence_verify_integrity", "input": {}})

        return InvestigationPlan(plan_id, state.iteration, state.profile, steps, "Profile-driven first pass over available evidence.")

