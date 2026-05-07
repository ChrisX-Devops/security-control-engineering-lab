# Stakeholder Translation Reference Card

For any technical finding, translate through these 4 layers:

---

## The Translation Framework

| Layer | Question | Audience |
|-------|----------|----------|
| 1. Technical | What is the issue? | Engineers |
| 2. Business | Why does it matter? | CTO / Founders |
| 3. Audit | What is the regulatory consequence? | Compliance / Legal |
| 4. Cost | What does inaction cost? | CFO / Board |

---

## Worked Examples

### Finding: Admin user has no MFA

| Layer | Translation |
|-------|-------------|
| Technical | IAM user 'admin' has no MFA device attached |
| Business | If credentials are stolen, attacker has full cloud access |
| Audit | SOC2 CC6.1 immediate failure, may halt audit |
| Cost | Failed audit = lost enterprise deals, est. $500k+ |

### Finding: S3 bucket public

| Layer | Translation |
|-------|-------------|
| Technical | Bucket 'customer-data' has public ACL enabled |
| Business | Customer data is exposed to the entire internet |
| Audit | SOC2 + GDPR + NDPA violation simultaneously |
| Cost | Average data breach = $4.5M. Regulatory fines = up to 4% revenue |

### Finding: 90+ day old access keys

| Layer | Translation |
|-------|-------------|
| Technical | 3 IAM access keys exceed rotation policy |
| Business | If a key was leaked years ago, attacker still has access |
| Audit | SOC2 CC6.7 finding, auditor will require remediation |
| Cost | 1 day to fix now vs 2 weeks during audit pressure |

---

## The Magic Formula

When in doubt, structure every finding communication as:

> "We detected [TECHNICAL ISSUE].
> This means [BUSINESS RISK in one sentence].
> Auditors will [AUDIT CONSEQUENCE].
> Fixing it costs [TIME AND EFFORT].
> Not fixing it costs [DOLLAR ESTIMATE]."

---

## Words to Avoid

| Engineer Word | Stakeholder Word |
|---------------|------------------|
| Misconfiguration | Security gap |
| CVE | Vulnerability that attackers exploit |
| Exfiltration | Data theft |
| Privilege escalation | Unauthorized access expansion |
| Persistence | Attacker maintaining access |
| Hardening | Reducing attack surface |
| Posture | Current security state |
| Surface | What attackers can see |

The right side is what executives understand and act on.
The left side gets nods of fake comprehension.
