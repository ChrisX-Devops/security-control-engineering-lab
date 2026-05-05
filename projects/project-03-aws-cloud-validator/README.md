# Project 03 — AWS Cloud Security Validator

## Objective

Automatically extract AWS cloud state, validate it against
security baselines, and generate audit-ready findings reports.

## What This Does

Connects to a real AWS account and validates:
- IAM user configurations (MFA, access keys, policies)
- S3 bucket security settings (public access, encryption, logging)

Produces:
- JSON findings report (machine-readable)
- Markdown findings report (auditor-ready)

## Technology Stack

- Python 3
- AWS CLI
- subprocess for AWS API calls

## Controls Implemented

| Control ID | Resource | Check | Severity |
|------------|----------|-------|----------|
| AWS-IAM-001 | IAM User | MFA enabled | CRITICAL |
| AWS-IAM-002 | IAM User | Access key age < 90 days | HIGH |
| AWS-IAM-003 | IAM User | No AdministratorAccess | HIGH |
| AWS-IAM-004 | IAM User | No inline policies | MEDIUM |
| AWS-IAM-005 | IAM User | Member of at least one group | LOW |
| AWS-S3-001 | S3 Bucket | Public access blocked | CRITICAL |
| AWS-S3-002 | S3 Bucket | Versioning enabled | MEDIUM |
| AWS-S3-003 | S3 Bucket | Encryption enabled | HIGH |
| AWS-S3-004 | S3 Bucket | Access logging enabled | MEDIUM |

## Real Findings Detected

Running against a real AWS account detected:

| Finding | Resource | Severity |
|---------|----------|----------|
| MFA Not Enabled | audit-test-user | CRITICAL |
| User Not In Any Group | audit-test-user | LOW |

## How to Run

```bash
python3 run_validator.py
