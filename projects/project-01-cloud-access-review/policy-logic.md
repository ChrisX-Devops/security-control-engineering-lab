# IAM Least Privilege Policy Logic

## Objective
Codify least-privilege IAM review as machine-evaluable policy logic.

## Policy Rule
Deny if any IAM user has `AdministratorAccess` attached.

## Enforcement Logic
- Evaluate IAM users
- Inspect attached policies
- Flag `AdministratorAccess` as control failure
- Return deny decision

## Result
This policy converts IAM least-privilege review into policy-as-code using OPA and Rego.

## Security Value
Least privilege is now testable as machine-enforced control logic.