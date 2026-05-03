# Project 02 — SQL Security Control Validator

## Objective

Build a SQL-based security control system that detects unauthorized
access patterns in authentication logs and exports audit-ready
evidence for each control finding.

## Context

Project 01 used Rego (OPA) to validate what permissions exist.
This project uses SQL to validate what actions were taken.

| Layer | Tool | What It Detects |
|-------|------|-----------------|
| Preventive | Rego + OPA | Misconfigured permissions that exist right now |
| Detective | SQL + PostgreSQL | Suspicious behavior that already happened |

Both layers are required for a complete compliance control system.

## Technology Stack

- PostgreSQL 16
- SQL (GROUP BY, HAVING, LIKE, aggregation, filtering)

## Controls Implemented

| Control ID | Name | Type | Framework | Severity |
|------------|------|------|-----------|----------|
| CTL-01 | Failed Login Spike Detection | Detective | SOC2 CC6.1, CC7.2 / ISO A.9.4.2 | HIGH |
| CTL-02 | Admin Account Activity Review | Detective | SOC2 CC6.2, CC6.3 / ISO A.9.2.3 | CRITICAL |

## Project Structure
# Project 02 — SQL Security Control Validator

## Objective

Build a SQL-based security control system that detects unauthorized
access patterns in authentication logs, scores users by risk level,
and exports audit-ready evidence for each control finding.

## Context

Project 01 used Rego (OPA) to validate what permissions exist.
This project uses SQL to validate what actions were taken.

| Layer | Tool | What It Detects |
|-------|------|-----------------|
| Preventive | Rego + OPA | Misconfigured permissions that exist right now |
| Detective | SQL + PostgreSQL | Suspicious behavior that already happened |

Both layers are required for a complete compliance control system.

## Technology Stack

- PostgreSQL 16
- SQL (GROUP BY, HAVING, LIKE, self-JOIN, CTEs, CASE WHEN,
  EXTRACT, COALESCE, conditional aggregation)

## Controls Implemented

| Control ID | Name | Type | Framework | Severity |
|------------|------|------|-----------|----------|
| CTL-01 | Failed Login Spike Detection | Detective | SOC2 CC6.1, CC7.2 / ISO A.9.4.2 | HIGH |
| CTL-02 | Admin Account Activity Review | Detective | SOC2 CC6.2, CC6.3 / ISO A.9.2.3 | CRITICAL |
| CTL-03 | Impossible Travel Detection | Detective | SOC2 CC7.2, CC6.6 / ISO A.12.4.1 | CRITICAL |
| CTL-04 | After-Hours Login Detection | Detective | SOC2 CC6.1 / ISO A.9.4.2 | MEDIUM |
| CTL-05 | Zero Success Accounts | Detective | SOC2 CC6.1 / ISO A.9.2.5 | HIGH |
| CTL-06 | Simultaneous Multi-Location | Detective | SOC2 CC6.6 / ISO A.9.4.2 | CRITICAL |
| CTL-07 | User Risk Score Dashboard | Analytical | SOC2 CC7.1, CC7.2 / ISO A.12.4.1 | N/A |

## Key SQL Concepts Used

| Concept | Used In | Purpose |
|---------|---------|---------|
| GROUP BY + HAVING | CTL-01, 02, 05 | Aggregate and filter grouped results |
| Self-JOIN | CTL-03, 06 | Compare rows within the same table |
| EXTRACT(HOUR) | CTL-04, 07 | Pull time components from timestamps |
| INTERVAL arithmetic | CTL-03, 06 | Define time windows for comparison |
| CASE WHEN in SUM | CTL-05, 07 | Conditional counting within aggregates |
| CTEs (WITH ... AS) | CTL-07 | Modular sub-queries for complex logic |
| COALESCE | CTL-07 | Replace NULL with 0 in scoring |
| LEFT JOIN | CTL-07 | Include all users even with no risk signals |

## Project Structure
