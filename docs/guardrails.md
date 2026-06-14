# EvilTrace Guardrails

Guardrails are layered. The **architectural** layer (the typed MCP server + command runner) is
the primary, always-enforced control; the Claude Code **hooks** are defense-in-depth for raw
Bash; the **prompt** rules are advisory.

## Read-Only Evidence (architectural)

Evidence under `cases/` is never written by EvilTrace. `GuardrailConfig.ensure_write_path`
resolves and rejects any write whose path is under the evidence root, and restricts writes to
`artifacts/` and `docs/`. Evidence is read with byte-level readers or read-only allowlisted
binaries and is never opened for writing.

## Command Allowlist + Denylist (architectural)

Only approved read-only forensic binaries pass `GuardrailConfig.validate_command`:

`tshark`, `capinfos`, `file`, `mmls`, `fsstat`, `fls`, `icat`, `mactime`, `tsk_recover`,
`evtx_dump`, `reglookup`, `sha256sum`, `vol`, `volatility3`.

Denied patterns block destructive or evidence-mutating operations (`rm`, `shred`, `truncate`,
`dd`, `mkfs`, `chmod`, `chown`, writable/`remount` mounts, redirects/`tee`/`cp`/`mv`/`install`
into the evidence roots, `find -delete`, and pipe-to-shell). Read-only `mount ... -o ro` is
allowed. The MCP server exposes no `execute_shell` tool, so the agent cannot bypass the
allowlist with an arbitrary command.

## Claude Code Hooks (defense-in-depth)

`.claude/hooks/` runs on every Claude tool call:

- `protect-evidence.sh` (PreToolUse Edit|Write) blocks writes whose resolved path is under the
  `cases/`/`evidence/` roots — anchored to the project roots, so paths like
  `artifacts/showcases/` or `src/eviltrace/evidence/` are not false-positives.
- `block-dangerous-commands.sh` (PreToolUse Bash) applies the denylist above.
- `audit-bash.sh` (PreToolUse Bash) appends an injection-safe JSONL record of each command.
- `post-run-validate.sh` (PostToolUse) records the tool/target and flags any write that landed
  under an evidence root.

The security hooks **fail closed**: if `jq` is unavailable they deny the operation rather than
silently allowing it.

## Audit Logging + Provenance (architectural)

Every tool call records, in `artifacts/logs/<case>.agent.jsonl`: timestamp, `audit_id`, MCP
tool name, structured input, output hash, raw output path, exit code, duration, and status. In
addition, a `provenance.schema.json` record per execution is written to
`artifacts/raw/provenance/<case>.provenance.jsonl` (command, exit code, durations, stdout/stderr
SHA256). Audit and event counters resume from the existing log, so the stdio MCP server never
collides on `audit_id`/`event_id` or overwrites raw outputs.

## Graceful Degradation

If a SIFT binary is missing, the tool returns `tool_missing`/`needs_review` with a
`fallback_reason`, the gap is logged as a limitation, and no unsupported finding is confirmed.
The PCAP path additionally falls back to a read-only built-in parser when `tshark` is absent.
