from pathlib import Path

from eviltrace.agent.orchestrator import EvilTraceOrchestrator


def test_demo_case_without_local_evidence_rejects_unsupported_claim(tmp_path: Path) -> None:
    (tmp_path / "cases" / "demo").mkdir(parents=True)
    result = EvilTraceOrchestrator(workspace=tmp_path).run(case_id="demo", case_root="cases/demo", max_iterations=2)
    assert result["rejected_findings"] == 1
    assert (tmp_path / result["log_path"]).exists()
    assert (tmp_path / result["report_path"]).exists()

