# Live IAM Policy Evaluation

## Objective
Evaluate real AWS IAM users against least-privilege policy logic using OPA.

## Data Source
Live IAM user and attached policy data exported from AWS CLI.

## Evaluation Logic
Real AWS IAM state was normalized into policy input and evaluated against the `iam_least_privilege.rego` control.

## Result
OPA successfully evaluated live IAM identities and returned policy decisions based on actual cloud access state.

## Security Value
This converts IAM least-privilege review from simulated testing into live cloud control validation.