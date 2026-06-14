from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import typer

from eviltrace.agent.orchestrator import EvilTraceOrchestrator
from eviltrace.evidence.manifest import build_case_manifest, write_manifest
from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.reporting.accuracy_report import write_accuracy_report
from eviltrace.reporting.dataset_doc import write_dataset_doc
from eviltrace.reporting.devpost_export import write_project_story
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
) -> None:
    result = EvilTraceOrchestrator().run(
        case_id=case_id,
        case_root=case_root,
        profile=profile,
        max_iterations=max_iterations,
        description=description,
    )
    _print_json(result)


@app.command("validate")
def validate_command(findings: str = typer.Option(..., "--findings")) -> None:
    data = json.loads(Path(findings).read_text(encoding="utf-8"))
    errors: list[str] = []
    for finding in data.get("findings", []):
        if finding.get("status") == "rejected":
            errors.append(f"{finding.get('finding_id')}: rejected finding present in final findings")
        if finding.get("status") in {"confirmed", "inferred"} and not finding.get("audit_ids"):
            errors.append(f"{finding.get('finding_id')}: missing audit_ids")
    _print_json({"status": "failed" if errors else "passed", "errors": errors})
    if errors:
        raise typer.Exit(1)


@app.command("benchmark")
def benchmark_command(
    findings: str = typer.Option(..., "--findings"),
    expected: str | None = typer.Option(None, "--expected"),
    output: str | None = typer.Option(None, "--output"),
) -> None:
    findings_data = json.loads(Path(findings).read_text(encoding="utf-8"))
    expected_data = json.loads(Path(expected).read_text(encoding="utf-8")) if expected else {}
    metrics = compute_metrics(findings_data.get("findings", []) + findings_data.get("rejected_findings", []), expected_data)
    output_path = Path(output or "artifacts/benchmarks/benchmark.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _print_json(metrics)


@app.command("report")
def report_command() -> None:
    write_accuracy_report("docs/accuracy-report.md")
    write_dataset_doc("docs/dataset-documentation.md")
    write_project_story("docs/project-story.md")
    _print_json({"status": "generated", "files": ["docs/accuracy-report.md", "docs/dataset-documentation.md", "docs/project-story.md"]})


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
