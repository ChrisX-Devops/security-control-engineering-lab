# Remediation Plan

**Generated:** 2026-05-05 12:10:13
**Current Score:** 0/100

Findings are ordered by priority. Fix CRITICAL items first.

## 1. [CRITICAL] Terminated Employee Login Activity

| Field | Value |
|-------|-------|
| Resource | `user/charlie` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.2, CC6.3 |
| Timeline | Within 24 hours |
| Score Impact | +20 pts when fixed |

**Finding:** Terminated employee 'Charlie Weber' has 5 login events after termination date 2026-04-15

## 2. [CRITICAL] Active User Without MFA

| Field | Value |
|-------|-------|
| Resource | `user/eve` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.1 |
| Timeline | Within 24 hours |
| Score Impact | +20 pts when fixed |

**Finding:** User 'Eve Martinez' (engineer) is active but has no MFA device enrolled

## 3. [CRITICAL] Access Review Overdue

| Field | Value |
|-------|-------|
| Resource | `user/admin` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.2, CC6.3 |
| Timeline | Within 24 hours |
| Score Impact | +20 pts when fixed |

**Finding:** User 'System Administrator' access review is overdue. Days since last review: Never reviewed

## 4. [CRITICAL] MFA Not Enabled

| Field | Value |
|-------|-------|
| Resource | `iam/user/audit-test-user` |
| Source | project-03-aws-validator |
| Framework | SOC2 CC6.1 | ISO A.9.4.2 |
| Timeline | Within 24 hours |
| Score Impact | +20 pts when fixed |

**Finding:** User 'audit-test-user' does not have MFA enabled. If this account's password is compromised, an attacker has unrestricted access.

## 5. [HIGH] Brute Force Login Detected

| Field | Value |
|-------|-------|
| Resource | `user/alice from 45.33.22.11` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.1, CC7.2 |
| Timeline | Within 7 days |
| Score Impact | +10 pts when fixed |

**Finding:** User 'alice' had 7 failed login attempts from 45.33.22.11 (Moscow, Russia)

## 6. [HIGH] Brute Force Login Detected

| Field | Value |
|-------|-------|
| Resource | `user/charlie from 172.16.0.20` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.1, CC7.2 |
| Timeline | Within 7 days |
| Score Impact | +10 pts when fixed |

**Finding:** User 'charlie' had 5 failed login attempts from 172.16.0.20 (Berlin, Germany)

## 7. [HIGH] Access Review Overdue

| Field | Value |
|-------|-------|
| Resource | `user/alice` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.2, CC6.3 |
| Timeline | Within 7 days |
| Score Impact | +10 pts when fixed |

**Finding:** User 'Alice Chen' access review is overdue. Days since last review: 155

## 8. [HIGH] Access Review Overdue

| Field | Value |
|-------|-------|
| Resource | `user/eve` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.2, CC6.3 |
| Timeline | Within 7 days |
| Score Impact | +10 pts when fixed |

**Finding:** User 'Eve Martinez' access review is overdue. Days since last review: 93

## 9. [MEDIUM] Repeated After-Hours Login Activity

| Field | Value |
|-------|-------|
| Resource | `user/diana` |
| Source | project-02-sql-controls |
| Framework | SOC2 CC6.1 |
| Timeline | Within 30 days |
| Score Impact | +5 pts when fixed |

**Finding:** User 'diana' has 3 successful logins between 11pm and 6am

## 10. [LOW] User Not In Any Group

| Field | Value |
|-------|-------|
| Resource | `iam/user/audit-test-user` |
| Source | project-03-aws-validator |
| Framework | SOC2 CC6.3 | ISO A.9.2.1 |
| Timeline | Within 90 days |
| Score Impact | +2 pts when fixed |

**Finding:** User 'audit-test-user' is not a member of any IAM group. Best practice is to assign permissions via groups, not directly to users.

---
## Score Projection

Current score: **0/100**
Score after all remediations: **100/100**

*PaySecure Unified Compliance Dashboard — Confidential*