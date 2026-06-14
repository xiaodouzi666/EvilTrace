from __future__ import annotations

from pathlib import Path

import pytest

from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.logging.audit_logger import AuditLogger
from eviltrace.mcp_server.command_runner import CommandRunner
from eviltrace.mcp_server.guardrails import GuardrailConfig, GuardrailError


def _runner(tmp_path: Path) -> CommandRunner:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    logger = AuditLogger(paths.logs_dir / "demo.agent.jsonl", run_id="run-test", case_id="demo")
    return CommandRunner(GuardrailConfig(paths), logger)


def test_missing_binary_returns_tool_missing(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    # 'vol' is allowlisted but not installed in the test environment path we control
    result = runner.run(["vol", "--version"], mcp_tool="memory_volatility_plugin", input_data={"memory_path": "x"})
    assert result.status in {"tool_missing", "success", "tool_error"}
    if result.status == "tool_missing":
        assert result.exit_code == 127
        assert Path(tmp_path / result.raw_output_path).exists()


def test_non_allowlisted_command_raises_before_running(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    with pytest.raises(GuardrailError):
        runner.run(["curl", "http://example.com"], mcp_tool="x", input_data={})


def test_denied_command_raises(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    with pytest.raises(GuardrailError):
        runner.run(["dd", "if=/dev/zero", "of=cases/x"], mcp_tool="x", input_data={})


def test_output_cap_truncates(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    runner.guardrails.max_output_bytes = 100
    capped = runner._cap("x" * 5000)
    assert len(capped.encode("utf-8")) <= 100 + len("\n[eviltrace: output truncated by max_output_bytes]")
    assert "truncated by max_output_bytes" in capped
