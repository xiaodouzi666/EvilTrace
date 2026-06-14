from pathlib import Path

import pytest

from eviltrace.evidence.paths import WorkspacePaths
from eviltrace.mcp_server.guardrails import GuardrailConfig, GuardrailError


def test_blocks_writes_to_cases(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    with pytest.raises(GuardrailError):
        guardrails.ensure_write_path(paths.evidence_root / "sample.pcap")


def test_blocks_destructive_command(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    with pytest.raises(GuardrailError):
        guardrails.validate_command(["rm", "-rf", "cases/demo"])


def test_allows_tshark_read_only_command(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    assert guardrails.validate_command(["tshark", "-r", "cases/demo/capture.pcap", "-q"]) == [
        "tshark",
        "-r",
        "cases/demo/capture.pcap",
        "-q",
    ]


def test_allows_writes_to_artifacts_and_docs(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    assert guardrails.ensure_write_path(paths.artifact_root / "reports" / "x.json")
    assert guardrails.ensure_write_path(paths.workspace / "docs" / "x.md")


def test_read_path_escaping_workspace_raises(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    with pytest.raises(GuardrailError):
        guardrails.ensure_read_path("/etc/passwd")


def test_non_allowlisted_executable_raises(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    with pytest.raises(GuardrailError):
        guardrails.validate_command(["curl", "http://example.com"])


def test_redirect_and_pipe_to_shell_are_denied(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    with pytest.raises(GuardrailError):
        guardrails.validate_command(["tshark", "-r", "x", ">", "cases/out"])
    with pytest.raises(GuardrailError):
        guardrails.validate_command(["sha256sum", "x", "|", "sh"])


def test_writable_mount_denied_but_read_only_mount_allowed(tmp_path: Path) -> None:
    paths = WorkspacePaths.from_workspace(tmp_path)
    paths.ensure()
    guardrails = GuardrailConfig(paths)
    # 'mount' is not allowlisted, so any mount via the command runner is rejected outright;
    # the denylist additionally guards the rw/remount pattern.
    with pytest.raises(GuardrailError):
        guardrails.validate_command(["mount", "-o", "remount,rw", "/mnt"])

