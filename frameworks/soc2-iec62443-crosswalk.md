# SOC2 to IEC 62443 Conceptual Crosswalk

## Purpose

This document maps SOC2 Trust Service Criteria to IEC 62443
Foundational Requirements at a conceptual level.

It demonstrates that I understand both frameworks and how
they relate, which is useful for clients with hybrid
IT/OT environments.

This document does NOT claim I perform IEC 62443
assessments. It claims I understand the framework
mapping conceptually.

---

## The Two Frameworks

### SOC2 (System and Organization Controls 2)
- Audit framework for service organizations
- Trust Service Criteria: Security, Availability, Processing
  Integrity, Confidentiality, Privacy
- Used primarily for SaaS and cloud companies
- The framework I work with daily

### IEC 62443
- Industrial cybersecurity standard
- Foundational Requirements (FR) define security capabilities
- Used primarily for industrial control systems
- The framework I am building knowledge of

---

## Conceptual Crosswalk

| IEC 62443 FR | Description | SOC2 Equivalent | What I Build For This |
|--------------|-------------|-----------------|----------------------|
| FR 1 | Identification and Authentication | CC6.1 | MFA enforcement policies (Project 01), MFA validation (Project 03) |
| FR 2 | Use Control | CC6.3 | Least privilege policies, role-based access checks |
| FR 3 | System Integrity | CC7.1 | CloudTrail validation, change detection |
| FR 4 | Data Confidentiality | CC6.7 | S3 encryption policies, data classification |
| FR 5 | Restricted Data Flow | CC6.6 | Network segmentation checks, public access detection |
| FR 6 | Timely Response to Events | CC7.2 | Behavioral detection (Project 02), alerting pipelines |
| FR 7 | Resource Availability | A1.1 | Backup validation, redundancy checks |

---

## What This Crosswalk Means in Practice

### For IT-Only Clients

The crosswalk is informational. SOC2 is the working framework.

### For Hybrid IT/OT Clients

The crosswalk shows that the security work I do on the IT
side aligns with the same conceptual requirements that govern
their OT environment.

This makes coordination easier between the IT security team
(my domain) and the OT security team (separate domain) because
both teams can reference the same conceptual structure.

### For Manufacturing or Industrial Clients

This crosswalk signals that I understand the industrial
context even if I am not performing OT assessments directly.

It positions me to handle the IT side of their compliance
needs while respecting the boundary to OT specialists.

---

## What This Crosswalk Does NOT Mean

This crosswalk does NOT mean:

- I can perform IEC 62443 conformance assessments
- My SOC2 work satisfies IEC 62443 requirements
- IT controls I implement work the same way in OT
- The architectural assumptions are interchangeable

The frameworks address different threat models:
- SOC2 addresses information security in service environments
- IEC 62443 addresses cybersecurity in industrial environments
  where physical processes can be affected

A misconfigured S3 bucket leaks data.
A misconfigured PLC can cause physical damage.

The frameworks reflect this difference. The crosswalk shows
conceptual alignment, not interchangeability.

---

## My Honest Positioning When This Crosswalk Comes Up

### If a client asks about IEC 62443

"I understand how SOC2 controls map to IEC 62443
Foundational Requirements at a conceptual level.
I can show you a crosswalk that demonstrates this.

For formal IEC 62443 conformance assessments, that
requires OT engineering expertise I am building but
do not have hands-on yet. I am pursuing ISA CCST
certification to formalize this knowledge.

For your IT environment and the IT/OT boundary,
I can deliver. For inside your OT environment,
I would partner with an OT specialist."

### If a client asks: "Why does this crosswalk matter?"

"It matters if you have both IT and OT environments
that need to coordinate. It shows that the security
work on each side is conceptually aligned even though
the implementation differs.

It also matters if your auditors are asking about
how your security program addresses both frameworks.
Most companies treat them separately. The crosswalk
shows the coherence between them."

---

## How This Document Will Evolve

When I gain hands-on OT experience or complete formal
IEC 62443 training, I will:

1. Update this document to reflect new capabilities
2. Move IEC 62443 from "conceptual understanding" to
   "operational capability" only for the specific
   FRs where I have proven experience
3. Continue maintaining the boundary between IT and
   OT work clearly

Until then, this document represents what I understand
conceptually, not what I deliver operationally.
