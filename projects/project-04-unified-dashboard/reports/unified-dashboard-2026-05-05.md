# PaySecure Unified Compliance Dashboard

**Report Date:** 2026-05-05
**Generated:** 2026-05-05 12:10:13

## Overall Compliance Score

# 🚨 0/100 — Grade F — CRITICAL

| Metric | Value |
|--------|-------|
| Total Findings | 10 |
| CRITICAL Findings | 4 (-80 pts) |
| HIGH Findings | 4 (-40 pts) |
| MEDIUM Findings | 1 (-5 pts) |
| LOW Findings | 1 (-2 pts) |

## Score by Category

| Category | Score | Findings |
|----------|-------|----------|
| 🚨 Access Control | 15/100 | 7 |
| 🚨 Identity | 58/100 | 3 |

## Findings by Source

### Project 02 Sql Controls
**8 finding(s)**

| Severity | Title | Resource |
|----------|-------|----------|
| CRITICAL | Terminated Employee Login Activity | `user/charlie` |
| CRITICAL | Active User Without MFA | `user/eve` |
| CRITICAL | Access Review Overdue | `user/admin` |
| HIGH | Brute Force Login Detected | `user/alice from 45.33.22.11` |
| HIGH | Brute Force Login Detected | `user/charlie from 172.16.0.20` |
| HIGH | Access Review Overdue | `user/alice` |
| HIGH | Access Review Overdue | `user/eve` |
| MEDIUM | Repeated After-Hours Login Activity | `user/diana` |

### Project 03 Aws Validator
**2 finding(s)**

| Severity | Title | Resource |
|----------|-------|----------|
| CRITICAL | MFA Not Enabled | `iam/user/audit-test-user` |
| LOW | User Not In Any Group | `iam/user/audit-test-user` |

## 🚨 Critical Findings — Act Immediately

### 1. Terminated Employee Login Activity
- **Source:** project-02-sql-controls
- **Resource:** `user/charlie`
- **Description:** Terminated employee 'Charlie Weber' has 5 login events after termination date 2026-04-15
- **Framework:** SOC2 CC6.2, CC6.3

### 2. Active User Without MFA
- **Source:** project-02-sql-controls
- **Resource:** `user/eve`
- **Description:** User 'Eve Martinez' (engineer) is active but has no MFA device enrolled
- **Framework:** SOC2 CC6.1

### 3. Access Review Overdue
- **Source:** project-02-sql-controls
- **Resource:** `user/admin`
- **Description:** User 'System Administrator' access review is overdue. Days since last review: Never reviewed
- **Framework:** SOC2 CC6.2, CC6.3

### 4. MFA Not Enabled
- **Source:** project-03-aws-validator
- **Resource:** `iam/user/audit-test-user`
- **Description:** User 'audit-test-user' does not have MFA enabled. If this account's password is compromised, an attacker has unrestricted access.
- **Framework:** SOC2 CC6.1 | ISO A.9.4.2

---
*PaySecure Unified Compliance Dashboard — Confidential*