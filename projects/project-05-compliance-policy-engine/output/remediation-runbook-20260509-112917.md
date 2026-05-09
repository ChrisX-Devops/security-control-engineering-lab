# Remediation Runbook

**Scan ID:** 20260509-112917
**Total findings:** 5

This runbook provides step-by-step remediation for every finding in the scan, ordered by severity.

---

## HIGH Severity Findings (5)

### HIGH-1: Password Policy Strength

**Violation:** No account password policy is configured

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

### HIGH-2: Password Policy Strength

**Violation:** Password policy does not require lowercase characters

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

### HIGH-3: Password Policy Strength

**Violation:** Password policy does not require numbers

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

### HIGH-4: Password Policy Strength

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

### HIGH-5: Password Policy Strength

**Violation:** Password policy does not require uppercase characters

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
