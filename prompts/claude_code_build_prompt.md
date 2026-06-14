Build EvilTrace as a self-correcting, evidence-grounded DFIR agent for Protocol SIFT.

Hard requirements:

- evidence under cases/ is read-only
- all evidence access goes through typed MCP tools
- every tool call emits an audit_id
- every finding includes artifacts and audit_ids
- unsupported claims are rejected or downgraded
- self-correction is visible in JSONL logs
- final outputs include report, findings JSON, validation JSON, evidence graph, and logs

