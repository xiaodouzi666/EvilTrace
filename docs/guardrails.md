# EvilTrace Guardrails

## Read-Only Evidence

Evidence under `cases/` is never written by EvilTrace. Code-level guardrails reject write paths under the evidence root, and Claude Code hooks block edit/write/bash operations targeting `cases/` or `evidence/`.

## Command Allowlist

Only approved forensic binaries are allowed through the command runner:

- `tshark`
- `capinfos`
- `file`
- `mmls`
- `fsstat`
- `fls`
- `icat`
- `mactime`
- `evtx_dump`
- `reglookup`
- `volatility3`

Denied patterns block destructive operations such as `rm`, `mv`, `chmod`, `chown`, `dd`, writable remounts, and shell pipe execution.

## Audit Logging

Every tool call records:

- timestamp
- `audit_id`
- MCP tool name
- command template or structured input
- output hash
- raw output path
- status

## Graceful Degradation

If a SIFT binary is missing, the tool returns `tool_missing`, the limitation is logged, and no unsupported finding is confirmed.

