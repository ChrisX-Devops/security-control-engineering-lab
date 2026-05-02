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
