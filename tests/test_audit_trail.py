import json
from pathlib import Path

from eviltrace.logging.audit_logger import AuditLogger


def test_audit_logger_writes_jsonl(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "demo.agent.jsonl", run_id="run-test", case_id="demo")
    event = logger.log_event("tool_call", input_data={"x": 1}, output_summary={"ok": True}, audit_id="audit-000001", mcp_tool="pcap_summary")
    rows = [json.loads(line) for line in (tmp_path / "demo.agent.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["event_id"] == event["event_id"]
    assert rows[0]["audit_id"] == "audit-000001"
    assert rows[0]["token_usage"]["total_tokens"] == 0

