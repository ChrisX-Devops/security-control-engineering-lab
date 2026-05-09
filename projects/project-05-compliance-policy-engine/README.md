# Project 05 — Compliance Policy Engine

## What This Is

A unified Python orchestrator that runs all Rego policies
against input state files and produces structured violations.

This is the engine layer of the security control system.
It sits between the data extraction layer (cloud APIs, logs)
and the reporting layer (dashboards, executive reports).

## Control System Parallel

This engine functions as a Distributed Control System (DCS)
for compliance:

| DCS Component | This Engine |
|---------------|-------------|
| Multiple control loops | Multiple Rego policies |
| Per-loop setpoints | Per-policy specifications |
| Per-loop measurements | Per-policy input files |
| Unified operator view | Unified findings JSON |
| Alarm prioritization | Severity classification |

## What It Does

1. Discovers all Rego policies in the policies directory
2. Routes each policy to its appropriate input file
3. Executes OPA evaluations against current state
4. Collects violations into structured findings
5. Computes compliance score across all policies
6. Saves timestamped results for downstream processing

## Project Structure

project-05-compliance-policy-engine/
├── policies/
│ ├── iam/ (4 Rego policies)
│ ├── s3/ (2 Rego policies)
│ └── network/ (1 Rego policy)
├── sample-inputs/
│ ├── iam-state.json
│ ├── s3-state.json
│ └── network-state.json
├── scripts/
│ └── policy_engine.py
├── output/
│ └── policy-violations-{timestamp}.json
├── tests/
└── README.md


## How to Run

```bash
python3 scripts/policy_engine.py


Output is saved to output/ with timestamp.


Output Structure

{
  "scan_metadata": {
    "scan_id": "20260507-143022",
    "started_at": "2026-05-07T14:30:22+00:00",
    "completed_at": "2026-05-07T14:30:24+00:00",
    "duration_seconds": 1.85,
    "engine_version": "1.0.0"
  },
  "scan_summary": {
    "policies_executed": 10,
    "policies_with_violations": 6,
    "policies_passing": 4,
    "total_findings": 14,
    "compliance_score": 40.0
  },
  "findings_by_severity": {
    "CRITICAL": 8,
    "HIGH": 4,
    "MEDIUM": 0,
    "LOW": 0
  },
  "findings": [
    {
      "policy_name": "MFA Required",
      "policy_package": "data.iam.mfa.deny",
      "domain": "iam",
      "severity": "CRITICAL",
      "soc2_mapping": "CC6.1",
      "iec62443_mapping": "FR1",
      "violation_message": "User 'bob' is active but does not have MFA enabled",
      "detected_at": "2026-05-07T14:30:22+00:00"
    }
  ]
}

Framework Mappings
Each policy maps to both SOC2 and IEC 62443 conceptually.
The IEC 62443 mapping demonstrates framework awareness without
claiming OT assessment capability. See:

frameworks/honest-positioning.md
frameworks/soc2-iec62443-crosswalk.md
What This Enables
Day 20 builds on this foundation by:

Adding standing alarm detection (ISA 18.2 inspired)
Connecting to live AWS data
Producing prioritized stakeholder reports
Generating remediation runbooks
