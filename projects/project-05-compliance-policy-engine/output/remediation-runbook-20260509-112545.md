# Remediation Runbook

**Scan ID:** 20260509-112545
**Total findings:** 19

This runbook provides step-by-step remediation for every finding in the scan, ordered by severity.

---

## CRITICAL Severity Findings (12)

### CRITICAL-1: MFA Required

**Violation:** User 'admin-prod' is active but does not have MFA enabled

**Framework mapping:**
- SOC2: CC6.1
- IEC 62443: FR1 (conceptual)

**Action:** Enable MFA device for affected user

**Estimated time:** 5-10 minutes per user

**Change window required:** No

**Steps:**
1. Sign in to AWS IAM console as administrator
2. Navigate to Users, select affected username
3. Open Security Credentials tab
4. Choose 'Assign MFA device'
5. Use virtual MFA app (Authy, Google Authenticator) or hardware key
6. Verify by signing out and signing back in with MFA

---

### CRITICAL-2: MFA Required

**Violation:** User 'bob' is active but does not have MFA enabled

**Framework mapping:**
- SOC2: CC6.1
- IEC 62443: FR1 (conceptual)

**Action:** Enable MFA device for affected user

**Estimated time:** 5-10 minutes per user

**Change window required:** No

**Steps:**
1. Sign in to AWS IAM console as administrator
2. Navigate to Users, select affected username
3. Open Security Credentials tab
4. Choose 'Assign MFA device'
5. Use virtual MFA app (Authy, Google Authenticator) or hardware key
6. Verify by signing out and signing back in with MFA

---

### CRITICAL-3: MFA Required for Admin Users

**Violation:** CRITICAL: Admin user 'admin-prod' has no MFA enabled

**Framework mapping:**
- SOC2: CC6.1
- IEC 62443: FR1 (conceptual)

**Action:** URGENT: Enable MFA on admin account immediately

**Estimated time:** 15 minutes plus activity audit

**Change window required:** No

**Steps:**
1. Stop all admin work until MFA is enabled
2. Enable MFA via AWS console as documented in iam.mfa.deny
3. Audit recent admin activity for unauthorized actions
4. Document the gap and remediation time for audit trail

---

### CRITICAL-4: Access Key Rotation Critical

**Violation:** CRITICAL: User 'admin-prod' has access key 247 days old (max allowed: 90)

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR1 (conceptual)

**Action:** URGENT: Rotate access key over 180 days old

**Estimated time:** 1-2 hours including audit

**Change window required:** Yes

**Steps:**
1. Treat as potential credential exposure
2. Audit CloudTrail for unusual activity from this key
3. Rotate as documented in iam.key_rotation.deny
4. Document compromise assessment in security log

---

### CRITICAL-5: Sensitive S3 Encryption Critical

**Violation:** CRITICAL: Sensitive bucket 'customer-data-prod' is unencrypted

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR4 (conceptual)

**Action:** URGENT: Encrypt sensitive bucket immediately

**Estimated time:** 5 minutes for setting plus re-encryption time

**Change window required:** No

**Steps:**
1. Apply encryption as documented in s3.encryption.deny
2. If bucket has existing unencrypted objects, plan re-encryption
3. Document classification and remediation for compliance log

---

### CRITICAL-6: S3 Public Access Blocked

**Violation:** Bucket 'customer-data-prod' allows public ACLs

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Enable all public access block settings

**Estimated time:** 10 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console, select affected bucket
2. Open Permissions tab
3. Find 'Block public access (bucket settings)'
4. Click Edit
5. Check all four block settings
6. Save and confirm changes
7. Test that legitimate access still works

---

### CRITICAL-7: S3 Public Access Blocked

**Violation:** Bucket 'customer-data-prod' allows public bucket policies

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Enable all public access block settings

**Estimated time:** 10 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console, select affected bucket
2. Open Permissions tab
3. Find 'Block public access (bucket settings)'
4. Click Edit
5. Check all four block settings
6. Save and confirm changes
7. Test that legitimate access still works

---

### CRITICAL-8: S3 Public Access Blocked

**Violation:** Bucket 'customer-data-prod' does not have all public access block settings enabled

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Enable all public access block settings

**Estimated time:** 10 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console, select affected bucket
2. Open Permissions tab
3. Find 'Block public access (bucket settings)'
4. Click Edit
5. Check all four block settings
6. Save and confirm changes
7. Test that legitimate access still works

---

### CRITICAL-9: S3 Public Access Blocked

**Violation:** Bucket 'dev-test-bucket' allows public ACLs

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Enable all public access block settings

**Estimated time:** 10 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console, select affected bucket
2. Open Permissions tab
3. Find 'Block public access (bucket settings)'
4. Click Edit
5. Check all four block settings
6. Save and confirm changes
7. Test that legitimate access still works

---

### CRITICAL-10: S3 Public Access Blocked

**Violation:** Bucket 'dev-test-bucket' does not have all public access block settings enabled

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Enable all public access block settings

**Estimated time:** 10 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console, select affected bucket
2. Open Permissions tab
3. Find 'Block public access (bucket settings)'
4. Click Edit
5. Check all four block settings
6. Save and confirm changes
7. Test that legitimate access still works

---

### CRITICAL-11: Network Sensitive Ports

**Violation:** CRITICAL: Security group 'database-tier' exposes port 5432 to internet (0.0.0.0/0)

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Restrict sensitive port from public internet

**Estimated time:** 15-30 minutes per security group

**Change window required:** Yes

**Steps:**
1. Identify the security group with the exposure
2. Determine who legitimately needs access
3. Replace 0.0.0.0/0 with specific CIDR ranges (VPN, office IPs)
4. Or remove the rule if access is no longer needed
5. Test legitimate access still works after restriction

---

### CRITICAL-12: Network Sensitive Ports

**Violation:** CRITICAL: Security group 'ssh-management' exposes port 22 to internet (0.0.0.0/0)

**Framework mapping:**
- SOC2: CC6.6
- IEC 62443: FR5 (conceptual)

**Action:** Restrict sensitive port from public internet

**Estimated time:** 15-30 minutes per security group

**Change window required:** Yes

**Steps:**
1. Identify the security group with the exposure
2. Determine who legitimately needs access
3. Replace 0.0.0.0/0 with specific CIDR ranges (VPN, office IPs)
4. Or remove the rule if access is no longer needed
5. Test legitimate access still works after restriction

---

## HIGH Severity Findings (7)

### HIGH-1: Least Privilege Enforcement

**Violation:** User 'admin-prod' has AdministratorAccess attached - violates least privilege

**Framework mapping:**
- SOC2: CC6.3
- IEC 62443: FR2 (conceptual)

**Action:** Replace AdministratorAccess with scoped policies

**Estimated time:** 30-60 minutes per user

**Change window required:** No

**Steps:**
1. Identify what permissions the user actually needs
2. Create or attach a scoped policy granting only those permissions
3. Detach AdministratorAccess from the user
4. Verify the user can still perform required tasks

---

### HIGH-2: Access Key Rotation

**Violation:** User 'admin-prod' has access key older than 90 days (current age: 247 days)

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR1 (conceptual)

**Action:** Rotate access key older than 90 days

**Estimated time:** 30-90 minutes depending on key usage scope

**Change window required:** Yes

**Steps:**
1. Create new access key for the user
2. Update applications and scripts to use new key
3. Verify all systems are using the new key
4. Disable the old access key (do not delete yet)
5. Wait 24-48 hours for any missed integrations to surface
6. Delete the old access key permanently

---

### HIGH-3: Access Key Rotation

**Violation:** User 'service-old-key' has access key older than 90 days (current age: 142 days)

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR1 (conceptual)

**Action:** Rotate access key older than 90 days

**Estimated time:** 30-90 minutes depending on key usage scope

**Change window required:** Yes

**Steps:**
1. Create new access key for the user
2. Update applications and scripts to use new key
3. Verify all systems are using the new key
4. Disable the old access key (do not delete yet)
5. Wait 24-48 hours for any missed integrations to surface
6. Delete the old access key permanently

---

### HIGH-4: Password Policy Strength

**Violation:** Password minimum length is 8 (required: 14)

**Framework mapping:**
- SOC2: CC6.1
- IEC 62443: FR1 (conceptual)

**Action:** Strengthen account password policy

**Estimated time:** 15 minutes

**Change window required:** No

**Steps:**
1. Sign in to AWS IAM console as administrator
2. Navigate to Account settings
3. Update password policy with: minimum 14 characters
4. Enable: require symbols, numbers, uppercase, lowercase
5. Save policy
6. Communicate policy change to all users

---

### HIGH-5: Password Policy Strength

**Violation:** Password policy does not require symbols

**Framework mapping:**
- SOC2: CC6.1
- IEC 62443: FR1 (conceptual)

**Action:** Strengthen account password policy

**Estimated time:** 15 minutes

**Change window required:** No

**Steps:**
1. Sign in to AWS IAM console as administrator
2. Navigate to Account settings
3. Update password policy with: minimum 14 characters
4. Enable: require symbols, numbers, uppercase, lowercase
5. Save policy
6. Communicate policy change to all users

---

### HIGH-6: S3 Encryption Required

**Violation:** Bucket 'customer-data-prod' does not have server-side encryption enabled

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR4 (conceptual)

**Action:** Enable default encryption on S3 bucket

**Estimated time:** 5 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console and select affected bucket
2. Open Properties tab
3. Find 'Default encryption' section
4. Click Edit, choose SSE-S3 or SSE-KMS
5. Save changes

---

### HIGH-7: S3 Encryption Required

**Violation:** Bucket 'dev-test-bucket' does not have server-side encryption enabled

**Framework mapping:**
- SOC2: CC6.7
- IEC 62443: FR4 (conceptual)

**Action:** Enable default encryption on S3 bucket

**Estimated time:** 5 minutes per bucket

**Change window required:** No

**Steps:**
1. Open S3 console and select affected bucket
2. Open Properties tab
3. Find 'Default encryption' section
4. Click Edit, choose SSE-S3 or SSE-KMS
5. Save changes

---
