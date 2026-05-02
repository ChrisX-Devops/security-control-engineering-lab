# Cloud IAM Access Control Review Report

## Executive Summary
A cloud IAM access control review was conducted to assess whether IAM user permissions aligned with least-privilege principles.

The review identified an over-permissioned IAM user (`audit-test-user`) with unrestricted administrative access via the AWS managed policy `AdministratorAccess`.

The issue was documented, mapped to control requirements, remediated through scoped access redesign, validated through functional testing, and converted into repeatable policy-driven control logic.

This report captures the full control lifecycle from detection through enforcement validation.

---

## Scope
Review focused on AWS IAM user access controls, attached permissions, privilege scope, and least-privilege enforcement.

Included:
- IAM user review
- attached policy review
- privilege scope analysis
- MFA review
- control remediation
- policy validation
- evidence automation

---

## Finding Summary
A test IAM user (`audit-test-user`) was assigned the AWS managed policy `AdministratorAccess`, granting unrestricted access across the AWS account.

### Risk
This violated least privilege and introduced excessive blast radius in the event of misuse or credential compromise.

### Severity
High

---

## Control Failure
The IAM user was over-permissioned and lacked:
- scoped access
- least-privilege enforcement
- MFA enforcement
- privilege governance

This created unnecessary administrative exposure.

---

## Remediation Summary
The excessive privilege condition was remediated by:

- removing `AdministratorAccess`
- creating scoped replacement policy (`IAMAuditReadOnly`)
- attaching scoped least-privilege access
- enabling MFA for privileged access assurance

This reduced privilege scope and improved authentication control strength.

---

## Validation Summary
Post-remediation validation confirmed:

### Allowed
- IAM user review
- IAM policy inspection
- read-only IAM visibility

### Blocked
- IAM user creation
- IAM user deletion
- IAM policy modification
- privilege escalation attempts

Validation confirmed least privilege was successfully enforced.

---

## Automation Summary
Manual IAM review was converted into repeatable control automation using:

- AWS CLI
- Bash
- evidence generation scripts

This enabled repeatable IAM access review and evidence capture.

---

## Policy-as-Code Summary
IAM least-privilege logic was codified using:

- OPA
- Rego

The control was encoded to deny any IAM identity with `AdministratorAccess` attached and return machine-evaluable policy decisions.

This converted least-privilege review into policy-as-code.

---

## Live Control Evaluation
Live AWS IAM user data was exported from AWS and evaluated against Rego control logic.

This confirmed the control could be evaluated against actual cloud state, not only simulated test data.

---

## Control Outcome
The IAM access control was:

- reviewed
- documented
- remediated
- validated
- automated
- codified
- evaluated live

This control is now materially stronger, testable, and repeatable.

---

## Final Security Assertion
Least privilege is now enforced for the reviewed IAM access path, and the control is supported by evidence, validation, and policy-driven logic.
