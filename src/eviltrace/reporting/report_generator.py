from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def generate_markdown_report(
    *,
    case_id: str,
    run_id: str,
    manifest: dict[str, Any],
    findings: dict[str, Any],
    validation: dict[str, Any],
    graph_path: str,
    log_path: str,
    output_path: str | Path,
    limitations: list[str],
) -> Path:
    final_findings = findings.get("findings", [])
    rejected = findings.get("rejected_findings", [])
    lines = [
        f"# EvilTrace Incident Report: {case_id}",
        "",
        "## Executive Summary",
        "",
        f"EvilTrace run `{run_id}` processed {manifest.get('evidence_count', 0)} evidence file(s). "
        f"The final report contains {len(final_findings)} confirmed/inferred/needs-review finding(s). "
        f"{len(rejected)} unsupported candidate finding(s) were rejected or excluded from final findings.",
        "",
        "## Final Findings",
        "",
    ]
    if final_findings:
        for finding in final_findings:
            lines.extend(
                [
                    f"### {finding['finding_id']}: {finding['title']}",
                    "",
                    f"- Status: `{finding['status']}`",
                    f"- Confidence: `{finding['confidence']}`",
                    f"- Audit IDs: `{', '.join(finding.get('audit_ids', [])) or 'none'}`",
                    f"- Summary: {finding['summary']}",
                    f"- Limitations: {finding.get('limitations') or 'None stated.'}",
                    "",
                    "| Artifact | Type | MCP Tool | Source |",
                    "|---|---|---|---|",
                ]
            )
            for artifact in finding.get("artifacts", []):
                lines.append(
                    f"| {artifact.get('artifact_id')} | {artifact.get('artifact_type')} | "
                    f"{artifact.get('mcp_tool')} | {artifact.get('source_path')} |"
                )
            lines.append("")
    else:
        lines.extend(["No incident finding was confirmed from the provided evidence.", ""])

    lines.extend(
        [
            "## Self-Correction Trace",
            "",
            "Rejected and downgraded candidates are retained in structured outputs but excluded from final findings.",
            "",
            "| Finding | Final disposition | Reason |",
            "|---|---|---|",
        ]
    )
    for finding in rejected:
        validation_reason = finding.get("validation", {}).get("reason", "Rejected by validation.")
        lines.append(f"| {finding.get('finding_id')} | rejected | {validation_reason} |")
    if not rejected:
        lines.append("| none | none | No rejected findings in this run. |")

    lines.extend(["", "## Validation Summary", "", "```json", json.dumps(validation, indent=2, sort_keys=True), "```", ""])
    lines.extend(["## Evidence Integrity", "", f"- Status: `{validation.get('evidence_integrity', {}).get('integrity_status', validation.get('evidence_integrity', {}).get('status', 'unknown'))}`", ""])
    lines.extend(["## Audit Trail", "", f"- Agent log: `{log_path}`", f"- Evidence graph: `{graph_path}`", ""])
    lines.extend(["## Limitations", ""])
    if limitations:
        lines.extend([f"- {item}" for item in limitations])
    else:
        lines.append("- No additional limitations were recorded.")
    lines.append("")

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8")
    return target

