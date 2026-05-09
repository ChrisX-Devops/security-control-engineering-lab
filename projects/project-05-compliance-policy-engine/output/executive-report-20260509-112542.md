# Compliance Assessment Report

**Scan ID:** 20260509-112542
**Generated:** 2026-05-09T11:25:42.331766+00:00
**Compliance Score:** 0.0/100 — URGENT

---

## Executive Summary

This assessment evaluated 10 security control policies against your environment. 0 controls passed without findings. 10 controls produced violations requiring action.

**Total findings: 19** (12 CRITICAL, 7 HIGH, 0 MEDIUM, 0 LOW)

## Critical Findings — Immediate Action Required

The following 12 findings represent risks that should be addressed immediately. Each maps to specific SOC2 control criteria.

### 1. MFA Required

**Finding:** User 'admin-prod' is active but does not have MFA enabled

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.1
- **IEC 62443 Mapping:** FR1 (conceptual)
- **Domain:** IAM

**Recommended action:** Enable MFA device for affected user
**Estimated time:** 5-10 minutes per user

### 2. MFA Required

**Finding:** User 'bob' is active but does not have MFA enabled

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.1
- **IEC 62443 Mapping:** FR1 (conceptual)
- **Domain:** IAM

**Recommended action:** Enable MFA device for affected user
**Estimated time:** 5-10 minutes per user

### 3. MFA Required for Admin Users

**Finding:** CRITICAL: Admin user 'admin-prod' has no MFA enabled

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.1
- **IEC 62443 Mapping:** FR1 (conceptual)
- **Domain:** IAM

**Recommended action:** URGENT: Enable MFA on admin account immediately
**Estimated time:** 15 minutes plus activity audit

### 4. Access Key Rotation Critical

**Finding:** CRITICAL: User 'admin-prod' has access key 247 days old (max allowed: 90)

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.7
- **IEC 62443 Mapping:** FR1 (conceptual)
- **Domain:** IAM

**Recommended action:** URGENT: Rotate access key over 180 days old
**Estimated time:** 1-2 hours including audit

### 5. Sensitive S3 Encryption Critical

**Finding:** CRITICAL: Sensitive bucket 'customer-data-prod' is unencrypted

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.7
- **IEC 62443 Mapping:** FR4 (conceptual)
- **Domain:** S3

**Recommended action:** URGENT: Encrypt sensitive bucket immediately
**Estimated time:** 5 minutes for setting plus re-encryption time

### 6. S3 Public Access Blocked

**Finding:** Bucket 'customer-data-prod' allows public ACLs

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** S3

**Recommended action:** Enable all public access block settings
**Estimated time:** 10 minutes per bucket

### 7. S3 Public Access Blocked

**Finding:** Bucket 'customer-data-prod' allows public bucket policies

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** S3

**Recommended action:** Enable all public access block settings
**Estimated time:** 10 minutes per bucket

### 8. S3 Public Access Blocked

**Finding:** Bucket 'customer-data-prod' does not have all public access block settings enabled

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** S3

**Recommended action:** Enable all public access block settings
**Estimated time:** 10 minutes per bucket

### 9. S3 Public Access Blocked

**Finding:** Bucket 'dev-test-bucket' allows public ACLs

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** S3

**Recommended action:** Enable all public access block settings
**Estimated time:** 10 minutes per bucket

### 10. S3 Public Access Blocked

**Finding:** Bucket 'dev-test-bucket' does not have all public access block settings enabled

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** S3

**Recommended action:** Enable all public access block settings
**Estimated time:** 10 minutes per bucket

### 11. Network Sensitive Ports

**Finding:** CRITICAL: Security group 'database-tier' exposes port 5432 to internet (0.0.0.0/0)

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** NETWORK

**Recommended action:** Restrict sensitive port from public internet
**Estimated time:** 15-30 minutes per security group

### 12. Network Sensitive Ports

**Finding:** CRITICAL: Security group 'ssh-management' exposes port 22 to internet (0.0.0.0/0)

- **Severity:** CRITICAL
- **SOC2 Control:** CC6.6
- **IEC 62443 Mapping:** FR5 (conceptual)
- **Domain:** NETWORK

**Recommended action:** Restrict sensitive port from public internet
**Estimated time:** 15-30 minutes per security group

## High Severity Findings

The following 7 findings require attention within the next 7 days.

| Finding | SOC2 | Policy |
|---------|------|--------|
| User 'admin-prod' has AdministratorAccess attached - violates least privilege... | CC6.3 | Least Privilege Enforcement |
| User 'admin-prod' has access key older than 90 days (current age: 247 days)... | CC6.7 | Access Key Rotation |
| User 'service-old-key' has access key older than 90 days (current age: 142 days)... | CC6.7 | Access Key Rotation |
| Password minimum length is 8 (required: 14)... | CC6.1 | Password Policy Strength |
| Password policy does not require symbols... | CC6.1 | Password Policy Strength |
| Bucket 'customer-data-prod' does not have server-side encryption enabled... | CC6.7 | S3 Encryption Required |
| Bucket 'dev-test-bucket' does not have server-side encryption enabled... | CC6.7 | S3 Encryption Required |

---

## Next Steps

1. Review CRITICAL findings with engineering leadership
2. Assign owners and timelines for each finding
3. Run remediation runbook (see remediation-runbook-*.md)
4. Re-scan after remediation to verify fixes

*This report was generated automatically by the Compliance Policy Engine. Findings map to SOC2 Trust Service Criteria and IEC 62443 Foundational Requirements (conceptual mapping only).*