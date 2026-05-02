# Finding 01 — Over-Permissioned IAM User

## Summary
An IAM user (`audit-test-user`) was assigned the AWS managed policy `AdministratorAccess`, granting unrestricted access across the AWS account.

## Risk
This violates the principle of least privilege and creates unnecessary blast radius in the event of credential compromise.

## Why It Matters
Over-permissioned identities increase the likelihood of:
- privilege abuse
- accidental destructive actions
- full-account compromise if credentials are exposed

## Severity
High

## Recommendation
Replace `AdministratorAccess` with scoped, role-based access aligned to operational need.
Enforce least privilege and require MFA for privileged identities.

---

## Remediation Status
Remediated

## Remediation Summary
Excessive administrative access was removed and replaced with a scoped read-only IAM policy. MFA was enabled for the IAM user to strengthen authentication controls.