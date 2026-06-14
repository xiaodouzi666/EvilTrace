from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from eviltrace.evidence.hashing import sha256_text
from eviltrace.findings.provenance import build_provenance_record
from eviltrace.logging.audit_logger import AuditLogger, utc_now
from eviltrace.logging.run_logger import RunLogger

from .guardrails import GuardrailConfig, GuardrailError


_SOURCE_PATH_KEYS = ("pcap_path", "image_path", "evtx_path", "memory_path", "system_hive", "software_hive", "path")


@dataclass
class CommandResult:
    audit_id: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    raw_output_path: str
    duration_ms: int
    status: str


class CommandRunner:
    def __init__(self, guardrails: GuardrailConfig, logger: AuditLogger, provenance: RunLogger | None = None):
        self.guardrails = guardrails
        self.logger = logger
        self.provenance = provenance

    def run(
        self,
        argv: list[str],
        *,
        mcp_tool: str,
        input_data: dict[str, Any],
        iteration: int = 0,
        raw_suffix: str = "txt",
    ) -> CommandResult:
        audit_id = self.logger.next_audit_id()
        started = time.monotonic()
        command = self.guardrails.validate_command(argv)
        executable = Path(command[0]).name
        raw_path = self.guardrails.paths.tool_outputs_dir / f"{audit_id}.{raw_suffix}"
        raw_path.parent.mkdir(parents=True, exist_ok=True)

        self.logger.log_event(
            "tool_call",
            iteration=iteration,
            input_data=input_data,
            output_summary={"command_redacted": " ".join(command)},
            audit_id=audit_id,
            status="started",
            mcp_tool=mcp_tool,
        )

        if shutil.which(executable) is None:
            message = f"Required forensic tool is not installed or not on PATH: {executable}"
            raw_path.write_text(message + "\n", encoding="utf-8")
            duration_ms = int((time.monotonic() - started) * 1000)
            result = CommandResult(
                audit_id=audit_id,
                command=command,
                exit_code=127,
                stdout="",
                stderr=message,
                stdout_sha256=sha256_text(""),
                stderr_sha256=sha256_text(message),
                raw_output_path=self.guardrails.paths.relative_to_workspace(raw_path),
                duration_ms=duration_ms,
                status="tool_missing",
            )
            self._log_result(result, iteration, mcp_tool, input_data)
            return result

        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.guardrails.timeout_seconds,
                errors="replace",
            )
            status = "success" if completed.returncode == 0 else "tool_error"
            stdout = self._cap(completed.stdout)
            stderr = self._cap(completed.stderr)
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = self._cap(exc.stdout or "")
            stderr = self._cap((exc.stderr or "") + f"\nTimeout after {self.guardrails.timeout_seconds}s")
            status = "timeout"
            exit_code = 124
        except GuardrailError:
            raise
        except Exception as exc:  # pragma: no cover - defensive path
            stdout = ""
            stderr = repr(exc)
            status = "tool_error"
            exit_code = 1

        duration_ms = int((time.monotonic() - started) * 1000)
        raw_path.write_text(
            "\n".join(
                [
                    "$ " + " ".join(command),
                    "",
                    "[stdout]",
                    stdout,
                    "",
                    "[stderr]",
                    stderr,
                ]
            ),
            encoding="utf-8",
        )
        result = CommandResult(
            audit_id=audit_id,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=sha256_text(stdout),
            stderr_sha256=sha256_text(stderr),
            raw_output_path=self.guardrails.paths.relative_to_workspace(raw_path),
            duration_ms=duration_ms,
            status=status,
        )
        self._log_result(result, iteration, mcp_tool, input_data)
        return result

    def _cap(self, value: str) -> str:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= self.guardrails.max_output_bytes:
            return value
        capped = encoded[: self.guardrails.max_output_bytes].decode("utf-8", errors="replace")
        return capped + "\n[eviltrace: output truncated by max_output_bytes]"

    def _log_result(
        self,
        result: CommandResult,
        iteration: int,
        mcp_tool: str,
        input_data: dict[str, Any],
    ) -> None:
        self.logger.log_event(
            "tool_result",
            iteration=iteration,
            input_data=input_data,
            output_summary={
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "stdout_sha256": result.stdout_sha256,
                "stderr_sha256": result.stderr_sha256,
                "raw_output_path": result.raw_output_path,
            },
            audit_id=result.audit_id,
            status=result.status,
            mcp_tool=mcp_tool,
        )
        if self.provenance is not None:
            source_path = next((str(input_data[key]) for key in _SOURCE_PATH_KEYS if input_data.get(key)), "")
            self.provenance.write_provenance(
                build_provenance_record(
                    audit_id=result.audit_id,
                    case_id=self.logger.case_id,
                    mcp_tool=mcp_tool,
                    tool_layer="subprocess",
                    timestamp_utc=utc_now(),
                    stdout_sha256=result.stdout_sha256,
                    stderr_sha256=result.stderr_sha256,
                    exit_code=result.exit_code,
                    duration_ms=result.duration_ms,
                    source_path=source_path,
                    underlying_tool=Path(result.command[0]).name if result.command else "",
                    command_redacted=" ".join(result.command),
                    raw_output_path=result.raw_output_path,
                )
            )

