from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PCAP = REPO_ROOT / "cases" / "sample" / "dns.cap"


@pytest.fixture
def workspace_with_pcap(tmp_path: Path) -> Path:
    """A clean tmp workspace containing cases/sample/dns.cap copied from the repo sample."""
    case_dir = tmp_path / "cases" / "sample"
    case_dir.mkdir(parents=True)
    shutil.copy(SAMPLE_PCAP, case_dir / "dns.cap")
    return tmp_path


@pytest.fixture
def empty_workspace(tmp_path: Path) -> Path:
    (tmp_path / "cases" / "demo").mkdir(parents=True)
    return tmp_path
