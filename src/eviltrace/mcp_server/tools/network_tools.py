from __future__ import annotations

from collections import Counter
from pathlib import Path
import shutil
import socket
import struct
import re
from typing import Any

from eviltrace.evidence.hashing import sha256_file

from .common import ToolContext, structured_tool_event, workspace_path


def _missing_path(ctx: ToolContext, tool: str, path: str, input_data: dict[str, Any]) -> dict[str, Any]:
    return structured_tool_event(
        ctx,
        mcp_tool=tool,
        input_data=input_data,
        output={"path": path, "reason": "Evidence path does not exist"},
        status="needs_review",
    )


def _ip(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _read_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end_offset = offset
    seen = 0
    while offset < len(payload) and seen < 128:
        seen += 1
        length = payload[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(payload):
            break
        label = payload[offset : offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length
        if not jumped:
            end_offset = offset
    return ".".join(labels), end_offset


def _parse_dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    flags = struct.unpack("!H", payload[2:4])[0]
    qdcount = struct.unpack("!H", payload[4:6])[0]
    is_response = bool(flags & 0x8000)
    if is_response or qdcount < 1:
        return None
    name, _ = _read_dns_name(payload, 12)
    return name or None


def _parse_pcap_builtin(path: Path, limit: int = 100000) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 24:
        return {"packet_count": 0, "protocols": [], "top_talkers": [], "dns_queries": []}
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
        divisor = 1_000_000 if magic == b"\xd4\xc3\xb2\xa1" else 1_000_000_000
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
        divisor = 1_000_000 if magic == b"\xa1\xb2\xc3\xd4" else 1_000_000_000
    else:
        return {"packet_count": 0, "protocols": ["unsupported_pcap_format"], "top_talkers": [], "dns_queries": []}

    offset = 24
    packet_count = 0
    protocols: set[str] = set()
    talkers: Counter[tuple[str, str]] = Counter()
    dns_queries: list[dict[str, Any]] = []
    while offset + 16 <= len(data) and packet_count < limit:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        packet_count += 1
        if len(frame) < 14:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        cursor = 14
        if eth_type == 0x8100 and len(frame) >= 18:
            eth_type = struct.unpack("!H", frame[16:18])[0]
            cursor = 18
        if eth_type == 0x0806:
            protocols.add("ARP")
            continue
        if eth_type != 0x0800 or len(frame) < cursor + 20:
            continue
        protocols.add("IP")
        version_ihl = frame[cursor]
        ihl = (version_ihl & 0x0F) * 4
        if len(frame) < cursor + ihl or ihl < 20:
            continue
        proto = frame[cursor + 9]
        src = _ip(frame[cursor + 12 : cursor + 16])
        dst = _ip(frame[cursor + 16 : cursor + 20])
        talkers[(src, dst)] += 1
        payload_offset = cursor + ihl
        if proto == 6:
            protocols.add("TCP")
            if len(frame) >= payload_offset + 4:
                src_port, dst_port = struct.unpack("!HH", frame[payload_offset : payload_offset + 4])
                if src_port == 80 or dst_port == 80:
                    protocols.add("HTTP")
        elif proto == 17:
            protocols.add("UDP")
            if len(frame) >= payload_offset + 8:
                src_port, dst_port, udp_len, _checksum = struct.unpack("!HHHH", frame[payload_offset : payload_offset + 8])
                payload = frame[payload_offset + 8 : payload_offset + max(8, udp_len)]
                if src_port == 53 or dst_port == 53:
                    protocols.add("DNS")
                    query = _parse_dns_query(payload)
                    if query:
                        dns_queries.append(
                            {
                                "timestamp_epoch": f"{ts_sec + ts_frac / divisor:.6f}",
                                "client": src,
                                "query": query,
                                "response": None,
                            }
                        )
        elif proto == 1:
            protocols.add("ICMP")
    return {
        "packet_count": packet_count,
        "protocols": sorted(protocols),
        "top_talkers": [
            {"src": src, "dst": dst, "count": count}
            for (src, dst), count in talkers.most_common(10)
        ],
        "dns_queries": dns_queries,
    }


def _builtin_event(ctx: ToolContext, *, mcp_tool: str, input_data: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    return structured_tool_event(ctx, mcp_tool=mcp_tool, input_data=input_data, output=output, status="success")


def pcap_summary(ctx: ToolContext, *, pcap_path: str, limit: int = 200) -> dict[str, Any]:
    resolved = workspace_path(ctx.paths, pcap_path)
    input_data = {"pcap_path": pcap_path, "limit": limit}
    if not resolved.exists():
        return _missing_path(ctx, "pcap_summary", pcap_path, input_data)
    if shutil.which("tshark") is None:
        parsed = _parse_pcap_builtin(resolved, limit=limit)
        output = {
            "packet_count": parsed["packet_count"],
            "protocols": parsed["protocols"],
            "top_talkers": parsed["top_talkers"],
            "source_path": ctx.paths.relative_to_workspace(resolved),
            "source_sha256": sha256_file(resolved),
            "underlying_tool": "python.pcap_builtin",
            "fallback_reason": "tshark is not installed; used read-only built-in PCAP parser for summary and DNS metadata.",
        }
        return _builtin_event(ctx, mcp_tool="pcap_summary", input_data=input_data, output=output)
    result = ctx.runner.run(
        ["tshark", "-r", str(resolved), "-q", "-z", "io,phs", "-z", "conv,ip"],
        mcp_tool="pcap_summary",
        input_data=input_data,
        iteration=ctx.iteration,
    )
    protocols = sorted(set(re.findall(r"\b(DNS|HTTP|SMTP|TLS|TCP|UDP|ICMP|ARP|FTP|SMB)\b", result.stdout, re.I)))
    packet_count = None
    match = re.search(r"(\d+)\s+packets?", result.stdout, re.I)
    if match:
        packet_count = int(match.group(1))
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "packet_count": packet_count,
        "protocols": [p.upper() for p in protocols],
        "top_talkers": [],
        "source_path": ctx.paths.relative_to_workspace(resolved),
        "source_sha256": sha256_file(resolved),
        "underlying_tool": "tshark",
        "raw_output_path": result.raw_output_path,
    }


def pcap_dns_queries(ctx: ToolContext, *, pcap_path: str, domain_filter: str | None = None) -> dict[str, Any]:
    resolved = workspace_path(ctx.paths, pcap_path)
    input_data = {"pcap_path": pcap_path, "domain_filter": domain_filter}
    if not resolved.exists():
        return _missing_path(ctx, "pcap_dns_queries", pcap_path, input_data)
    if shutil.which("tshark") is None:
        parsed = _parse_pcap_builtin(resolved)
        queries = parsed["dns_queries"]
        if domain_filter:
            queries = [row for row in queries if domain_filter in row.get("query", "")]
        output = {
            "queries": queries,
            "source_path": ctx.paths.relative_to_workspace(resolved),
            "source_sha256": sha256_file(resolved),
            "underlying_tool": "python.pcap_builtin",
            "fallback_reason": "tshark is not installed; used read-only built-in DNS parser.",
        }
        return _builtin_event(ctx, mcp_tool="pcap_dns_queries", input_data=input_data, output=output)
    display_filter = "dns.flags.response == 0"
    if domain_filter:
        display_filter += f" and dns.qry.name contains \"{domain_filter}\""
    result = ctx.runner.run(
        [
            "tshark",
            "-r",
            str(resolved),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "dns.qry.name",
        ],
        mcp_tool="pcap_dns_queries",
        input_data=input_data,
        iteration=ctx.iteration,
        raw_suffix="tsv",
    )
    queries = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2]:
            queries.append({"timestamp_epoch": parts[0], "client": parts[1], "query": parts[2], "response": None})
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "queries": queries,
        "source_path": ctx.paths.relative_to_workspace(resolved),
        "source_sha256": sha256_file(resolved),
        "underlying_tool": "tshark",
        "raw_output_path": result.raw_output_path,
    }


def pcap_http_objects(ctx: ToolContext, *, pcap_path: str, export_dir: str = "artifacts/raw/http-objects") -> dict[str, Any]:
    resolved = workspace_path(ctx.paths, pcap_path)
    input_data = {"pcap_path": pcap_path, "export_dir": export_dir}
    if not resolved.exists():
        return _missing_path(ctx, "pcap_http_objects", pcap_path, input_data)
    if shutil.which("tshark") is None:
        return structured_tool_event(
            ctx,
            mcp_tool="pcap_http_objects",
            input_data=input_data,
            output={"objects": [], "source_path": ctx.paths.relative_to_workspace(resolved), "source_sha256": sha256_file(resolved), "reason": "HTTP object export requires tshark."},
            status="needs_review",
        )
    destination = ctx.guardrails.ensure_write_path(export_dir)
    destination.mkdir(parents=True, exist_ok=True)
    result = ctx.runner.run(
        ["tshark", "-r", str(resolved), "--export-objects", f"http,{destination}"],
        mcp_tool="pcap_http_objects",
        input_data=input_data,
        iteration=ctx.iteration,
    )
    objects = []
    for index, path in enumerate(sorted(p for p in destination.rglob("*") if p.is_file()), start=1):
        objects.append(
            {
                "object_id": f"http-object-{index:04d}",
                "filename": path.name,
                "sha256": sha256_file(path),
                "path": ctx.paths.relative_to_workspace(path),
            }
        )
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "objects": objects,
        "source_path": ctx.paths.relative_to_workspace(resolved),
        "source_sha256": sha256_file(resolved),
        "underlying_tool": "tshark",
        "raw_output_path": result.raw_output_path,
    }


def pcap_follow_stream(ctx: ToolContext, *, pcap_path: str, stream_id: int, protocol: str = "tcp") -> dict[str, Any]:
    if protocol not in {"tcp", "udp"}:
        return structured_tool_event(
            ctx,
            mcp_tool="pcap_follow_stream",
            input_data={"pcap_path": pcap_path, "stream_id": stream_id, "protocol": protocol},
            output={"reason": "Only tcp and udp streams are supported"},
            status="needs_review",
        )
    resolved = workspace_path(ctx.paths, pcap_path)
    input_data = {"pcap_path": pcap_path, "stream_id": stream_id, "protocol": protocol}
    if not resolved.exists():
        return _missing_path(ctx, "pcap_follow_stream", pcap_path, input_data)
    if shutil.which("tshark") is None:
        return structured_tool_event(
            ctx,
            mcp_tool="pcap_follow_stream",
            input_data=input_data,
            output={"stream_id": stream_id, "protocol": protocol, "text_preview": "", "source_path": ctx.paths.relative_to_workspace(resolved), "source_sha256": sha256_file(resolved), "reason": "Stream reconstruction requires tshark."},
            status="needs_review",
        )
    result = ctx.runner.run(
        ["tshark", "-r", str(resolved), "-q", "-z", f"follow,{protocol},ascii,{stream_id}"],
        mcp_tool="pcap_follow_stream",
        input_data=input_data,
        iteration=ctx.iteration,
    )
    return {
        "audit_id": result.audit_id,
        "status": result.status,
        "stream_id": stream_id,
        "protocol": protocol,
        "text_preview": result.stdout[:2000],
        "source_path": ctx.paths.relative_to_workspace(resolved),
        "source_sha256": sha256_file(resolved),
        "underlying_tool": "tshark",
        "raw_output_path": result.raw_output_path,
    }
