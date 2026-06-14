# Demo Video

Status: recording-ready against the bundled real capture `cases/sample/dns.cap`. The public
upload URL must be added below (and on the Devpost submission form) before submitting — a
missing/private video is a common cause of elimination.

Recommended title: `EvilTrace — FIND EVIL Demo`.

Constraints (from the FIND EVIL rules): under 5 minutes, a screencast of **live terminal
execution** with **audio narration** (not slides, not a marketing video), showing the agent
working against real evidence including **at least one self-correction sequence**.

Follow `docs/demo-script.md`. Required moments to show:

- live terminal execution of `uv run eviltrace run --case-id sample --case-root ./cases/sample ...`
- real case data (`cases/sample/dns.cap`, a public Wireshark capture)
- a self-correction event in `artifacts/logs/sample.agent.jsonl`
  (`jq 'select(.event_type=="self_correction_triggered")'`)
- provenance from a final finding to its artifact, `audit_id`, and provenance record
- the architecture trust boundary and the compliance map

After recording and uploading to YouTube or Vimeo (public), replace the placeholder below and
update the status cells in `README.md` and `docs/compliance-map.md` to "Complete":

```text
PUBLIC_DEMO_VIDEO_URL: <paste YouTube/Vimeo URL here>
```
