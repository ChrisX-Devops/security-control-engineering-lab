# IAM Access Review Automation

## Objective
Automate IAM access review to identify over-permissioned IAM users and produce repeatable evidence.

## Automation Logic
The script:
- enumerates IAM users
- retrieves attached user policies
- flags `AdministratorAccess` as an over-permissioned condition
- writes review output to an evidence file

## Output
A timestamped evidence artifact is generated for each run.

## Security Value
This converts manual IAM access review into a repeatable control check that can be re-run on demand.