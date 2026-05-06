# Project 04 — Unified Compliance Dashboard

## Objective

Combine findings from all security control systems into
one unified compliance view with scoring and remediation planning.

## What This Does

Aggregates findings from:
- Project 02: SQL behavioral security controls
- Project 03: AWS cloud security validator

Produces:
- Overall compliance score (0-100 with letter grade)
- Score breakdown by category
- Unified findings report (Markdown)
- Prioritized remediation plan
- Machine-readable JSON dashboard

## Technology Stack

- Python 3
- PostgreSQL
- AWS CLI
- JSON report aggregation

## Scoring Model

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -20 points |
| HIGH | -10 points |
| MEDIUM | -5 points |
| LOW | -2 points |

Baseline score is 100.

## Reports Generated

| File | Purpose |
|------|---------|
| unified-dashboard-[date].json | Machine-readable dashboard |
| unified-dashboard-[date].md | Executive compliance report |
| remediation-plan-[date].md | Prioritized remediation actions |

## Sources Integrated

| Source | Findings Collected |
|--------|-------------------|
| Project 02 SQL Controls | Brute force, MFA, access reviews, terminated users |
| Project 03 AWS Validator | IAM and S3 cloud security findings |

## How to Run

```bash
python3 run_dashboard.py
