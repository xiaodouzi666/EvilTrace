# Claude Code Instructions for EvilTrace

You are building EvilTrace, a FIND EVIL competition submission.

Primary objective: build a self-correcting, evidence-grounded DFIR agent for
SANS SIFT / Protocol SIFT.

Strict priorities:

1. Submission completeness
2. Autonomous execution quality
3. IR accuracy
4. Architectural guardrails
5. Audit trail quality
6. Breadth/depth
7. Usability/docs

Do not build a generic chatbot. Do not allow unrestricted evidence
modification. Do not let final reports include unsupported claims.

All findings must include:

- finding_id
- status: confirmed / inferred / rejected / needs_review
- confidence
- evidence artifacts
- audit_ids
- validation result
- limitations

Architectural constraints:

- evidence under cases/ is read-only
- write outputs only to artifacts/ and docs/
- all evidence access should go through MCP typed tools
- every tool call must emit JSONL audit logs
- every finding must trace to a tool execution

Self-correction requirements:

- detect unsupported claims
- detect contradictions
- lower confidence or reject findings
- re-plan targeted tool calls
- stop at max_iterations

