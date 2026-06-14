# EvilTrace Architecture

EvilTrace is built around a strict separation between autonomous reasoning and forensic evidence access.

```mermaid
flowchart LR
    User[Judge / Analyst] --> CLI[EvilTrace CLI]
    CLI --> Claude[Claude Code Orchestrator]
    Claude --> Planner[Investigation Planner]
    Claude --> Loop[Self-Correction Loop]
    Planner --> MCPClient[MCP Client]
    MCPClient --> MCP[EvilTrace Typed MCP Server]

    subgraph Guardrails[Architectural Guardrails]
        MCP --> Allowlist[Tool Allowlist]
        MCP --> ReadOnly[Read-only Evidence Access]
        MCP --> Timeout[Timeout + Output Limits]
        MCP --> Audit[Mandatory Audit Logging]
    end

    MCP --> SIFT[SIFT / DFIR Tools]
    SIFT --> Disk[Disk Artifacts]
    SIFT --> Memory[Memory Artifacts]
    SIFT --> Network[Network Artifacts]
    SIFT --> Logs[Event Logs]
    Disk --> Normalize[Artifact Normalizer]
    Memory --> Normalize
    Network --> Normalize
    Logs --> Normalize
    Normalize --> Graph[Evidence Graph]
    Graph --> Findings[Finding Registry]
    Findings --> Validator[Validation Engine]
    Validator --> Loop
    Loop -->|Contradiction found| Planner
    Loop -->|Validated| Report[Report Generator]
    Report --> MD[Markdown Report]
    Report --> JSON[findings.json]
    Report --> LogsOut[agent.jsonl]
    Report --> Accuracy[Accuracy Report]
    PromptGuard[Prompt Guardrails] -.-> Claude
```

## Architectural Guardrails

- Typed MCP functions expose case, evidence, PCAP, disk, Windows, memory, graph, finding, and validation operations.
- Evidence paths are read-only by policy.
- Writes are restricted to `artifacts/` and `docs/`.
- Command execution is allowlisted and denied-pattern checked.
- Tool calls have timeout and output-size limits.
- Every tool call emits JSONL audit events and raw output hashes.

## Prompt Guardrails

- The investigator prompt forbids guessing and overclaiming.
- Findings must be marked `confirmed`, `inferred`, `rejected`, or `needs_review`.
- Unsupported claims must be rejected or downgraded.
- Final reports must cite artifacts and audit IDs.

## Output Pipeline

The orchestrator writes all durable outputs under `artifacts/`. Any final finding can be traced from `findings.json` to an artifact, then to an `audit_id`, then to a tool execution event and raw output path in the JSONL log.

