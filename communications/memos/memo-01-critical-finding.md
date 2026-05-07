# Security Finding — Action Required

**To:** [CTO Name]
**From:** Onuawuchi Christian, Security Operations
**Date:** [Date]
**Severity:** CRITICAL
**Estimated Time to Resolve:** 2 hours

---

## What Happened

Our compliance monitoring system detected that a terminated employee
account (`charlie`) has 5 failed login attempts after their
termination date of 2026-04-15.

This means one of two things:
1. The account was never disabled in our identity system
2. Someone is actively attempting to use the credentials

Either case is a critical security incident.

## Business Impact

- **SOC2 audit risk:** This is an immediate audit failure under
  CC6.2 (credential lifecycle management)
- **Breach risk:** If credentials are reused, attacker has the same
  access charlie had (Finance department, analyst level)
- **Regulatory exposure:** NDPA Article 32 requires terminated
  employee access to be revoked within 24 hours

## What I Need From You

**Today (next 2 hours):**
- Approve me to disable the account
- Approve credential rotation for any shared resources

**This week:**
- Review the offboarding process to find why this was missed
- Authorize me to add automated termination detection to our pipeline

## What I Have Already Done

- Captured evidence of all 5 login attempts
- Identified the source IP (Berlin, Germany)
- Documented the finding with full audit trail
- Generated the remediation report

Evidence file: `evidence/control-08-terminated-logins-2026-05-04.txt`

Reply **"approved"** and I will execute the remediation in the next hour.
