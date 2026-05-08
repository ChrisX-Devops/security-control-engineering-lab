# OPA Output Translation Guide

## Why This Document Exists

OPA Rego policy outputs are dense, structured, and often
intimidating to non-technical audiences. A policy violation
that takes 5 seconds for an engineer to understand can take
30 minutes to explain to a founder if you do not have a
translation playbook ready.

This guide maps every OPA policy in Project 01 to the
three-language framework: Technical, Business, and IT/OT
Boundary Aware.

---

## The Three-Language Framework

For every OPA finding, prepare three versions:

| Audience | Version | Purpose |
|----------|---------|---------|
| Engineers | Technical | Action specification |
| Founders / CTOs | Business | Risk and ROI clarity |
| Industrial / Hybrid clients | IT/OT Boundary Aware | Control system parallel |

---

## Translation Table for Project 01 Policies

### Policy 1: MFA Required (iam.mfa)

**Raw OPA Output:**

User 'admin' is active but does not have MFA enabled

**Technical Language (for engineers):**
"IAM user 'admin' fails the iam.mfa.deny rule. The
input.users array contains a user with status='active'
and mfa_enabled=false, violating the MFA enforcement
specification. SOC2 CC6.1 logical access control failure."

**Business Language (for founders):**
"Your admin user has no second login factor. If their
password is stolen, an attacker takes full control of
your AWS account in seconds. They can delete everything,
steal customer data, or run up a $50,000 cloud bill
in hours. Fixing this takes 15 minutes."

**IT/OT Boundary Language (for industrial clients):**
"Your administrative authentication control has a
setpoint deviation. The required state is multi-factor
verification. The actual state is single-factor only.
This is an open pathway into your environment. The
control needs to return to specification before your
audit assessment."

---

### Policy 2: Critical MFA Missing for Admin (iam.mfa.deny_critical)

**Raw OPA Output:**
CRITICAL: Admin user 'root' has no MFA enabled


**Technical Language:**
"Privileged user without MFA. Triggers deny_critical
rule because role_level='admin' AND mfa_enabled=false.
Maps to SOC2 CC6.1 with elevated severity due to
privilege scope."

**Business Language:**
"Your most powerful account has the weakest login
protection. This is the single highest-risk finding
in your environment. Every successful attack on this
account is catastrophic, not minor. Fix this today."

**IT/OT Boundary Language:**
"Your highest-authority controller has no redundant
authentication path. In an industrial system this would
be equivalent to a master controller without password
protection on the engineering workstation. Fix this
before any audit walkthrough."

---

### Policy 3: Access Key Rotation (iam.key_rotation)

**Raw OPA Output:**

User 'old-service-account' has access key older than 90 days
(current age: 120 days)


**Technical Language:**
"Access key violates 90-day rotation specification.
Key age 120 days exceeds max_key_age_days threshold.
SOC2 CC6.1 and CC6.7 violation. ISO 27001 A.9.2.6
non-conformance."

**Business Language:**
"You have a programmatic credential that has been
unchanged for 4 months. If anyone has accidentally
leaked it during that time — in a code commit, a
log file, a screenshot — that attacker still has
access. Rotating it takes 30 minutes and invalidates
any leaked copies."

**IT/OT Boundary Language:**
"This authentication credential exceeds its calibration
interval. In instrumentation, an instrument out of
calibration produces unreliable readings. An access
key beyond rotation period produces unreliable trust
assertions. The credential must be reissued to restore
calibration."

---

### Policy 4: Critical Old Keys (iam.key_rotation.deny_critical)

**Raw OPA Output:**

CRITICAL: User 'admin' has access key 200 days old
(max allowed: 90)


**Technical Language:**
"Access key over 180 days. Triggers deny_critical
rule. Key has been valid for over 6 months without
rotation, exceeding both organizational policy and
common compromise dwell time estimates."

**Business Language:**
"This credential is older than most security incidents
take to detect. If it was ever leaked, the attacker
has had unlimited time to use it. Rotate immediately
and audit any account activity from this credential
in the past 6 months."

**IT/OT Boundary Language:**
"This credential is significantly out of specification.
The longer it remains valid past its rotation interval,
the greater the deviation between intended security
posture and actual security posture. This is the
equivalent of an instrument that has not been
calibrated for two service intervals."

---

### Policy 5: Password Policy Requirements (iam.password_policy)

**Raw OPA Output (multiple possible):**
No account password policy is configured
Password minimum length is 8 (required: 14)
Password policy does not require symbols
Password policy does not require numbers


**Technical Language:**
"Account password policy fails baseline specification.
Multiple deny rules triggered: missing length requirement,
missing complexity requirements. SOC2 CC6.1 and ISO 27001
A.9.4.3 violations."

**Business Language:**
"Your password rules are weak enough that an attacker
can crack passwords with off-the-shelf tools in hours.
Strengthening these rules takes 5 minutes and requires
no user action — it just enforces the rules going forward."

**IT/OT Boundary Language:**
"Your authentication setpoint specification is below
acceptable baseline. The control loop will accept
deviations that should be rejected. Tighten the
specification before next audit cycle."

---

### Policy 6: S3 Encryption (s3.encryption)

**Raw OPA Output:**
Bucket 'customer-uploads' does not have server-side
encryption enabled


**Technical Language:**
"S3 bucket fails encryption specification. Default
encryption is not enabled. Data at rest is stored
unencrypted. SOC2 CC6.1 and ISO 27001 A.10.1.1
violations."

**Business Language:**
"Your customer data is stored without encryption.
If anyone gains access to AWS — even read-only access —
they can download everything. Encryption takes one
click to enable and protects existing and future data."

**IT/OT Boundary Language:**
"This data store has no confidentiality control applied.
The required state is encryption at rest. The actual
state is plaintext storage. The control needs to be
applied to bring the system into compliance with
data protection specifications."

---

### Policy 7: Critical Sensitive Bucket Unencrypted (s3.encryption.deny_critical)

**Raw OPA Output:**
Bucket 'customer-uploads' does not have server-side
encryption enabled


**Technical Language:**
"S3 bucket fails encryption specification. Default
encryption is not enabled. Data at rest is stored
unencrypted. SOC2 CC6.1 and ISO 27001 A.10.1.1
violations."

**Business Language:**
"Your customer data is stored without encryption.
If anyone gains access to AWS — even read-only access —
they can download everything. Encryption takes one
click to enable and protects existing and future data."

**IT/OT Boundary Language:**
"This data store has no confidentiality control applied.
The required state is encryption at rest. The actual
state is plaintext storage. The control needs to be
applied to bring the system into compliance with
data protection specifications."

---

### Policy 7: Critical Sensitive Bucket Unencrypted (s3.encryption.deny_critical)

**Raw OPA Output:**
CRITICAL: Sensitive bucket 'customer-pii' is unencrypted


**Technical Language:**
"Bucket tagged classification='sensitive' fails
encryption check. Triggers deny_critical rule due
to sensitivity tag. Multi-framework violation."

**Business Language:**
"Your most sensitive data — the data your customers
trust you with — is sitting unprotected. This is
the kind of finding that triggers regulatory fines
and breach notification requirements. Fix immediately."

**IT/OT Boundary Language:**
"The asset with highest data classification has no
applied confidentiality control. This is the equivalent
of storing safety-critical data on an unsecured network
share. Maximum priority remediation."

---

### Policy 8: S3 Public Access (s3.public_access)

**Raw OPA Output (multiple possible):**

Bucket 'shared-files' does not have all public access
block settings enabled
Bucket 'shared-files' allows public ACLs
Bucket 'shared-files' allows public bucket policies


**Technical Language:**
"S3 bucket fails public access prevention checks.
Multiple deny rules triggered. Bucket may be accessible
to the public internet. SOC2 CC6.1 and CC6.6 violations."

**Business Language:**
"Your data storage is set up to potentially allow
public internet access. Anyone in the world might be
able to reach this. Closing this off takes 30 seconds
and requires no application changes."

**IT/OT Boundary Language:**
"This network boundary control has multiple deviations.
The required state is no external access. The actual
state allows multiple paths for external access. This
is a network segmentation failure that needs immediate
correction."

---

### Policy 9: Network Sensitive Ports Exposed (network.exposure)

**Raw OPA Output:**

CRITICAL: Security group 'web-tier' exposes port 22
to internet (0.0.0.0/0)


**Technical Language:**
"Security group ingress rule allows port 22 from
0.0.0.0/0. SSH service exposed to entire internet.
SOC2 CC6.1 and CC6.6 violations. ISO 27001 A.13.1.1
non-conformance."

**Business Language:**
"Your servers can be logged into from anywhere on the
internet. This means automated attack tools are
trying passwords against your servers right now,
24 hours a day. Restricting this to only your office
or VPN takes 5 minutes."

**IT/OT Boundary Language:**
"Your network boundary has an open access path on
a sensitive control port. This is exactly the kind
of network segmentation failure that creates IT/OT
boundary risk in industrial environments. The same
class of failure that allowed Triton, Stuxnet, and
Industroyer attacks. Restrict access immediately."

---

## Universal Translation Pattern

When you encounter any OPA finding, structure your
translation in this order:

WHAT WAS DETECTED (one sentence)
WHY IT MATTERS TO THE BUSINESS (two sentences)
WHAT THE AUDITOR WILL SAY (one sentence)
WHAT IT COSTS TO FIX (specific time)
WHAT IT COSTS NOT TO FIX (specific dollar estimate)


This is the same structure as the framework in
translation-reference.md, applied specifically to OPA
policy outputs.

---

## Practice Method

For each policy in this guide:

1. Read the technical version aloud (10 seconds)
2. Read the business version aloud (30 seconds)
3. Read the IT/OT boundary version aloud (30 seconds)
4. Without looking, explain the finding to an imaginary
   founder in 60 seconds
5. Record yourself
6. Listen for jargon you slipped in
7. Refine until you sound natural

Goal: Fluent translation under interview conditions.

---

## When to Use IT/OT Boundary Language

Only when:
- The client has industrial operations or OT context
- The conversation has surfaced control systems vocabulary
- You are speaking to someone who genuinely understands
  the parallel

Never force this language. It must fit the conversation
or it sounds like overreach. Your honest positioning
document is your guardrail here.
