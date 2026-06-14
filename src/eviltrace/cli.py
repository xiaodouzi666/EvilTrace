from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from eviltrace.agent.orchestrator import EvilTraceOrchestrator
from eviltrace.evidence.manifest import build_case_manifest, write_manifest
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.findings.provenance import provenance_complete
from eviltrace.graph.store import GraphStore
from eviltrace.reporting.accuracy_report import write_accuracy_report
from eviltrace.reporting.dataset_doc import write_dataset_doc
from eviltrace.reporting.devpost_export import write_devpost_submission, write_project_story
from eviltrace.reporting.report_generator import generate_markdown_report
from eviltrace.validators.benchmark import compute_metrics

app = typer.Typer(help="Self-correcting, evidence-grounded DFIR agent.", no_args_is_help=True)

REQUIRED_FILES = [
    ("LICENSE", "MIT or Apache license"),
    ("README.md", "README"),
    ("docs/architecture.md", "Architecture diagram doc"),
    ("docs/project-story.md", "Written project description"),
    ("docs/dataset-documentation.md", "Dataset documentation"),
    ("docs/accuracy-report.md", "Accuracy report"),
    ("docs/try-it-out.md", "Try-it-out instructions"),
    ("docs/demo-video.md", "Demo video link"),
]


def _print_json(value: Any) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


def _load_json(path: str) -> Any:
    file_path = Path(path)
    if not file_path.is_file():
        raise typer.BadParameter(f"File not found: {path}")
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON in {path}: {exc}") from exc


@app.command("init-case")
def init_case(
    case_id: str = typer.Option(..., "--case-id"),
    case_root: str = typer.Option(..., "--case-root"),
    case_type: str = typer.Option("unknown", "--case-type"),
    description: str = typer.Option("", "--description"),
    output: str | None = typer.Option(None, "--output"),
) -> None:
    paths = WorkspacePaths.from_workspace(".")
    paths.ensure()
    manifest = build_case_manifest(case_id, case_root, paths, case_type=case_type, description=description)
    output_path = Path(output or paths.reports_dir / f"{case_id}.case.json")
    write_manifest(manifest, output_path)
    _print_json({"manifest_path": str(output_path), "evidence_count": manifest["evidence_count"]})


@app.command("run")
def run_command(
    case_id: str = typer.Option(..., "--case-id"),
    case_root: str = typer.Option(..., "--case-root"),
    profile: str = typer.Option("network-first", "--profile"),
    max_iterations: int = typer.Option(5, "--max-iterations", min=1),
    description: str = typer.Option("", "--description"),
    output: str | None = typer.Option(None, "--output", help="Directory for findings/report/validation/run outputs."),
) -> None:
    result = EvilTraceOrchestrator().run(
        case_id=case_id,
        case_root=case_root,
        profile=profile,
        max_iterations=max_iterations,
        description=description,
        output=output,
    )
    _print_json(result)


def _validate_findings_data(data: dict[str, Any]) -> list[str]:
    """Data-level enforcement of the finding rules (sections 9/14 of the plan)."""
    errors: list[str] = []
    for finding in data.get("findings", []):
        fid = finding.get("finding_id", "?")
        status = finding.get("status")
        if status == "rejected":
            errors.append(f"{fid}: Rule 8 violation — rejected finding present in final findings")
        if status in {"confirmed", "inferred"}:
            if not finding.get("artifacts"):
                errors.append(f"{fid}: Rule 1 violation — confirmed/inferred finding has no artifacts")
            if not finding.get("audit_ids"):
                errors.append(f"{fid}: Rule 2 violation — confirmed/inferred finding has no audit_ids")
            for artifact in finding.get("artifacts", []):
                if not provenance_complete(artifact):
                    errors.append(f"{fid}: Rule 3/4 violation — artifact {artifact.get('artifact_id', '?')} has incomplete provenance")
            if not (finding.get("limitations") or "").strip():
                errors.append(f"{fid}: Rule 9 violation — finding does not state limitations")
    for finding in data.get("rejected_findings", []):
        if finding.get("status") != "rejected":
            errors.append(f"{finding.get('finding_id', '?')}: rejected_findings entry is not marked rejected")
    return errors


@app.command("validate")
def validate_command(findings: str = typer.Option(..., "--findings")) -> None:
    data = _load_json(findings)
    errors = _validate_findings_data(data)
    _print_json({"status": "failed" if errors else "passed", "errors": errors})
    if errors:
        raise typer.Exit(1)


@app.command("benchmark")
def benchmark_command(
    findings: str = typer.Option(..., "--findings"),
    expected: str | None = typer.Option(None, "--expected"),
    manifest: str | None = typer.Option(None, "--manifest", help="Case manifest to compute evidence_integrity."),
    output: str | None = typer.Option(None, "--output"),
) -> None:
    findings_data = _load_json(findings)
    expected_data = _load_json(expected) if expected else {}
    integrity = None
    if manifest:
        from eviltrace.validators.evidence_integrity import verify_manifest_integrity

        integrity = verify_manifest_integrity(_load_json(manifest), ".")
    metrics = compute_metrics(
        findings_data.get("findings", []) + findings_data.get("rejected_findings", []),
        expected_data,
        integrity,
    )
    output_path = Path(output or "artifacts/benchmarks/benchmark.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _print_json(metrics)


@app.command("report")
def report_command(
    case_id: str | None = typer.Option(None, "--case-id", help="Regenerate the per-case report.md from existing artifacts."),
    findings: str | None = typer.Option(None, "--findings"),
) -> None:
    if case_id:
        paths = WorkspacePaths.from_workspace(".")
        findings_path = Path(findings) if findings else paths.reports_dir / f"{case_id}.findings.json"
        findings_data = _load_json(str(findings_path))
        validation_path = paths.reports_dir / f"{case_id}.validation.json"
        validation = _load_json(str(validation_path)) if validation_path.is_file() else {}
        manifest_path = paths.reports_dir / f"{case_id}.case.json"
        manifest = _load_json(str(manifest_path)) if manifest_path.is_file() else {}
        graph_path = paths.graphs_dir / f"{case_id}.graph.json"
        log_path = paths.logs_dir / f"{case_id}.agent.jsonl"
        report_path = paths.reports_dir / f"{case_id}.report.md"
        generate_markdown_report(
            case_id=case_id,
            run_id=validation.get("run_id", "regenerated"),
            manifest=manifest,
            findings=findings_data,
            validation=validation,
            graph_path=paths.relative_to_workspace(graph_path),
            log_path=paths.relative_to_workspace(log_path),
            output_path=report_path,
            limitations=validation.get("limitations", []) or [],
        )
        _print_json({"status": "regenerated", "report": str(report_path)})
        return
    write_accuracy_report("docs/accuracy-report.md")
    write_dataset_doc("docs/dataset-documentation.md")
    write_project_story("docs/project-story.md")
    _print_json({"status": "generated", "files": ["docs/accuracy-report.md", "docs/dataset-documentation.md", "docs/project-story.md"]})


@app.command("export-devpost")
def export_devpost_command(
    output: str = typer.Option("docs/devpost-submission.md", "--output"),
) -> None:
    story = write_project_story("docs/project-story.md")
    submission = write_devpost_submission(output)
    _print_json({"status": "generated", "files": [str(story), str(submission)]})


def _dir_nonempty(path: str) -> bool:
    p = Path(path)
    return p.is_dir() and any(item.is_file() for item in p.rglob("*"))


def submission_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for path, label in REQUIRED_FILES:
        checks.append({"label": label, "path": path, "passed": Path(path).is_file()})
    checks.append({"label": "Agent execution logs", "path": "artifacts/logs", "passed": _dir_nonempty("artifacts/logs")})
    checks.append({"label": "Sample reports", "path": "artifacts/reports", "passed": _dir_nonempty("artifacts/reports")})
    license_ok = False
    if Path("LICENSE").exists():
        text = Path("LICENSE").read_text(encoding="utf-8", errors="replace")
        license_ok = "MIT License" in text or "Apache License" in text
    checks.append({"label": "LICENSE text", "path": "LICENSE", "passed": license_ok})
    readme_ok = False
    if Path("README.md").exists():
        readme_ok = "Competition Compliance Map" in Path("README.md").read_text(encoding="utf-8", errors="replace")
    checks.append({"label": "README compliance map", "path": "README.md", "passed": readme_ok})
    return checks


@app.command("submission-check")
def submission_check_command() -> None:
    checks = submission_checks()
    for check in checks:
        typer.echo(f"{'PASS' if check['passed'] else 'FAIL'}: {check['label']} -> {check['path']}")
    if not all(check["passed"] for check in checks):
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
