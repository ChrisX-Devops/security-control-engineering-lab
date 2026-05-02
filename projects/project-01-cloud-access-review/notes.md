# IAM Access Review Notes

## Objective
Review IAM identities and identify excessive permissions that violate least privilege.

## Scope
AWS IAM users and attached policies.

## Observation
A test IAM user (`audit-test-user`) was assigned `AdministratorAccess`, granting unrestricted access to all AWS services.

## Initial Assessment
This represents excessive privilege and weak access governance.

## Next Action
Validate remediation path using scoped permissions and MFA enforcement.