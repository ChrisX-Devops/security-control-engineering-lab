# Remediation Prioritization Framework

When a client asks "what should we fix first?" — use this model.

---

## The 4-Factor Scoring Model

Every finding is scored on 4 dimensions, each rated 1-10:

### 1. EXPLOITABILITY (1-10)

How easy is it for an attacker to exploit?

- **10** — Actively exploited in the wild, no skill required
   (example: public S3 bucket)
- **7** — Exploit code exists, moderate skill required
   (example: weak password policy)
- **4** — Theoretical vulnerability, significant skill required
   (example: misconfigured IAM trust relationship)
- **1** — Nearly impossible to exploit
   (example: low-privilege role with overpermissive policy)

### 2. BUSINESS EXPOSURE (1-10)

What is the blast radius if exploited?

- **10** — Customer data, production systems, revenue impact
- **7** — Internal systems, limited customer data
- **4** — Development environments, no customer data
- **1** — Isolated test systems

### 3. AUDIT IMPACT (1-10)

What happens if an auditor sees this?

- **10** — Guaranteed audit failure, regulatory fine risk
- **7** — Likely audit finding, requires written explanation
- **4** — Minor finding, easily remediated during audit
- **1** — Informational only, not typically audited

### 4. IMPLEMENTATION EFFORT (1-10, INVERTED)

How easy is it to fix? Higher score = easier fix.

- **10** — Less than 1 hour to fix, no downtime
- **7** — 1 to 4 hours, minimal coordination
- **4** — 1 to 2 days, requires change window
- **1** — More than 1 week, architectural changes

---

## Calculating Priority Score
Priority Score =
(Exploitability + Business Exposure + Audit Impact)
× Implementation Effort


**Why multiply by effort:**
A high-impact finding that takes 5 minutes to fix should be
done before a slightly higher-impact finding that takes a week.
Quick wins compound. Slow remediations consume budget.

---

## Priority Ranking

| Score | Rank | Timeline |
|-------|------|----------|
| 200+ | CRITICAL | Within 24 hours |
| 100-199 | HIGH | Within 7 days |
| 50-99 | MEDIUM | Within 30 days |
| Below 50 | LOW | Schedule when convenient |

---

## Worked Example

**Finding:** Admin user has no MFA enabled

| Factor | Score | Reasoning |
|--------|-------|-----------|
| Exploitability | 9 | Common attack vector, no skill needed |
| Business Exposure | 10 | Admin = full account access |
| Audit Impact | 10 | SOC2 immediate failure |
| Implementation Effort | 10 | Takes 5 minutes to enable |
| **Priority Score** | **(9+10+10) × 10 = 290** | |
| **Rank** | **CRITICAL** | Fix today |

---

**Finding:** S3 bucket without versioning enabled

| Factor | Score | Reasoning |
|--------|-------|-----------|
| Exploitability | 2 | Not directly exploitable |
| Business Exposure | 4 | Recovery issue, not breach |
| Audit Impact | 4 | Minor finding |
| Implementation Effort | 9 | One-click in console |
| **Priority Score** | **(2+4+4) × 9 = 90** | |
| **Rank** | **MEDIUM** | Fix this month |

---

## Why This Framework Wins Trust

When clients see this model, they immediately understand:
- You are not panicking about every finding
- You have a defensible reason for prioritization order
- You consider business reality, not just technical severity
- You respect their team's time and budget

This is how mature security engineers communicate.
