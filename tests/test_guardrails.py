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

