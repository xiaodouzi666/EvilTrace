# EvilTrace Incident Report: sample

## Executive Summary

EvilTrace run `run-20260614-223730` processed 1 evidence file(s). The final report contains 1 confirmed/inferred/needs-review finding(s). 1 unsupported candidate finding(s) were rejected or excluded from final findings.

## Final Findings

### finding-0002: DNS query activity observed in PCAP evidence

- Status: `confirmed`
- Confidence: `0.86`
- Audit IDs: `audit-000002, audit-000003`
- Summary: EvilTrace parsed DNS metadata from the PCAP and observed 19 DNS query artifact(s).
- Limitations: DNS activity alone is network context, not proof of compromise.

| Artifact | Type | MCP Tool | Source |
|---|---|---|---|
| artifact-0001 | pcap_summary | pcap_summary | cases/sample/dns.cap |
| artifact-0002 | dns_query | pcap_dns_queries | cases/sample/dns.cap |

## Self-Correction Trace

Rejected and downgraded candidates are retained in structured outputs but excluded from final findings.

| Finding | Final disposition | Reason |
|---|---|---|
| finding-0001 | rejected | Exfiltration language requires stream, object, or endpoint evidence; none is present. |

## Validation Summary

```json
{
  "case_id": "sample",
  "corrections": [
    {
      "action": "reject_finding",
      "finding_id": "finding-0001",
      "needs_replan": false,
      "new_status": "rejected",
      "next_action": "Reject unsupported claim.",
      "previous_status": "confirmed",
      "reason": "Exfiltration language requires stream, object, or endpoint evidence; none is present.",
      "targeted_replan": null
    }
  ],
  "evidence_integrity": {
    "audit_id": "audit-000005",
    "case_id": "sample",
    "changed_files": [],
    "checked_count": 1,
    "integrity_status": "passed",
    "missing_files": [],
    "raw_output_path": "artifacts/raw/tool-outputs/audit-000005.json",
    "status": "success"
  },
  "metrics": {
    "artifact_recall": "not_measured_without_known_answer_case",
    "finding_precision": 1.0,
    "hallucination_rate": 0.0,
    "provenance_completeness": 1.0,
    "rejected_findings": 1,
    "self_correction_success": 1.0,
    "unsupported_rejected_claims": 1
  },
  "run_id": "run-20260614-223730",
  "validation_results": [
    {
      "confidence": 0.1,
      "contradicted_by": [],
      "corroborated_by": [
        "artifact-0001"
      ],
      "finding_id": "finding-0001",
      "hallucination_check": "passed",
      "reason": "Exfiltration language requires stream, object, or endpoint evidence; none is present.",
      "recommended_status": "rejected",
      "status": "confirmed",
      "unsupported_claims": [
        "overclaim:exfiltration_without_direct_support"
      ]
    },
    {
      "confidence": 0.86,
      "contradicted_by": [],
      "corroborated_by": [
        "artifact-0001",
        "artifact-0002"
      ],
      "finding_id": "finding-0002",
      "hallucination_check": "passed",
      "reason": "Finding has required provenance and no contradictions.",
      "recommended_status": "confirmed",
      "status": "confirmed",
      "unsupported_claims": []
    }
  ]
}
```

## Evidence Integrity

- Status: `passed`

## Audit Trail

- Agent log: `artifacts/logs/sample.agent.jsonl`
- Evidence graph: `artifacts/graphs/sample.graph.json`

## Limitations

- pcap_http_objects: HTTP object export requires tshark.
