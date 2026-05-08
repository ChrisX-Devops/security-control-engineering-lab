# Instrumentation Context

## Why This Document Exists

Every system in this portfolio mirrors a component of an
industrial control system. This is not a metaphor stretched
to sound impressive. The logic is genuinely identical.

This document maps each system I have built to its
control system equivalent. It exists to prove I understand
the conceptual parallel and to guide my own thinking as
I expand the portfolio.

---

## The Universal Control Loop

Every control system follows this pattern:

SENSOR → CONTROLLER → SETPOINT COMPARISON → ALARM/ACTION → REPEAT


Every security validation system follows the same pattern:

EXTRACTOR → VALIDATOR → POLICY COMPARISON → FINDING/REPORT → REPEAT


The vocabulary differs. The logic is identical.

---

## Mapping My Systems to Control Components

### Project 01 — IAM Policy Control (Rego)

| Control System Component | My Implementation |
|--------------------------|-------------------|
| Sensor | AWS CLI extracting IAM state |
| Transmitter | Bash scripts normalizing JSON |
| Controller | OPA policy engine |
| Setpoint | Rego policy rules (e.g., "all users must have MFA") |
| Deviation Detection | Policy evaluation against live state |
| Alarm | Deny rule output with violation message |
| Final Element | Stakeholder report with remediation guidance |

This system runs the complete control loop for IAM access controls.
Each Rego policy is a setpoint. Each evaluation is a measurement.
Each deny rule is an alarm.

### Project 02 — SQL Security Control Validator

| Control System Component | My Implementation |
|--------------------------|-------------------|
| Sensor | PostgreSQL ingestion of authentication logs |
| Historian | login_attempts and users tables |
| Controller | SQL queries running detection logic |
| Setpoint | Behavioral baselines (e.g., "no logins from 2 countries within 1 hour") |
| Deviation Detection | Query results identifying violations |
| Alarm | Finding records with severity classification |
| Trend Analysis | Risk scoring aggregation across users |

The 12 SQL controls function as a process historian and analytics
engine combined. The risk scoring system in CTL-07 is equivalent
to a process performance index.

### Project 03 — AWS Cloud Security Validator

| Control System Component | My Implementation |
|--------------------------|-------------------|
| Sensor | boto3 calls extracting AWS resource state |
| Transmitter | JSON state files with timestamps |
| Controller | Python validators applying security baselines |
| Setpoint | Security baseline (e.g., "MFA required for all users") |
| Deviation Detection | Validation logic identifying gaps |
| Alarm | Findings with CRITICAL/HIGH/MEDIUM/LOW severity |
| Audit Trail | Dated state files and findings reports |

This system runs against real AWS infrastructure. Each scan is
equivalent to a polling cycle in a SCADA system reading values
from field instruments.

### Project 04 — Unified Compliance Dashboard

| Control System Component | My Implementation |
|--------------------------|-------------------|
| DCS (Distributed Control System) | Dashboard orchestrator |
| Multiple Control Loops | Project 02 + Project 03 feeding findings |
| HMI (Human-Machine Interface) | Markdown executive report |
| Alarm Prioritization | Severity-weighted scoring engine |
| Operator Action List | Remediation plan with timelines |

This is the security equivalent of a plant control room.
Multiple sources feed in. One unified view comes out.
Operators (executives) see prioritized actions, not raw alarms.

### Project 05 — GitHub Actions CI/CD

| Control System Component | My Implementation |
|--------------------------|-------------------|
| Continuous Monitoring | Workflows triggered on every push |
| Scan Cycle | Cron-scheduled or event-driven runs |
| Quality Gate | Compliance gate failing builds on critical findings |
| Test Calibration | Unit tests proving policies behave correctly |

CI/CD on every commit is equivalent to a process historian
recording every measurement at fixed intervals. The pipeline
is the control loop. Every code change is measured against
the policy specification.

---

## ISA 18.2 Alarm Management Applied to Security

ISA 18.2 is the industrial standard for alarm management.
Its core principle: not every measurement should produce
an alarm, and not every alarm should be the same priority.

### The Alarm Flood Problem

In industrial plants, when too many alarms fire at once,
operators ignore everything and miss the critical ones.
This has caused fatal accidents.

In security, when every finding is treated as urgent,
clients fix nothing. The same psychological pattern applies.

### How I Apply ISA 18.2 to Security Findings

| ISA 18.2 Concept | My Application |
|------------------|----------------|
| Alarm rationalization | Every finding has defined severity and required action |
| Priority bands (1-4) | CRITICAL / HIGH / MEDIUM / LOW |
| Standing alarms | Findings present in 3+ consecutive scans |
| Alarm response time | Defined remediation timeline per severity |
| Alarm message clarity | Findings state what is wrong AND what to do |

### Priority Mapping

| Security Priority | ISA 18.2 Equivalent | Response Time |
|-------------------|---------------------|---------------|
| CRITICAL | Priority 1 — Emergency | This week |
| HIGH | Priority 2 — High | This month |
| MEDIUM | Priority 3 — Medium | This quarter |
| LOW | Priority 4 — Low | When convenient |

This framework is implemented in:
- Project 02's user risk scoring (CTL-07)
- Project 03's severity classification
- Project 04's deduction-based compliance scoring

---

## Why This Conceptual Foundation Matters

### Commercially

Most security engineers think in security vocabulary only.
They cannot communicate with industrial clients who think
in control systems vocabulary.

I can translate between domains. This is rare and valuable.

### Technically

Control systems thinking forces good design:
- Every measurement must have a defined setpoint
- Every alarm must be actionable
- Every system must close the loop with action, not just notification

These principles produce better security systems even when
the audience does not speak instrumentation.

### Honestly

I am not claiming OT expertise. I am claiming I understand
the conceptual structure of control systems and can apply
that thinking to cloud security problems.

This is provable. Every project in this portfolio demonstrates
the application. The CCST certification path will formalize
the underlying knowledge.

---

## CCST Study Plan Reference

I am pursuing ISA Certified Control Systems Technician (CCST)
to formalize this conceptual understanding.

Study covers:
- Measurement fundamentals (transmitters, signals, accuracy)
- Control loop concepts (PID, setpoints, process variables)
- Safety systems (SIS, SIL, separation principles)
- OT networks (Purdue Model, SCADA, industrial protocols)

Target: Schedule exam by Day 84 of roadmap.
Goal: Vocabulary and concepts, not technical depth in instrumentation.

---

## What This Document Is NOT

This document does NOT claim:
- I can secure SCADA systems
- I can configure PLCs
- I can assess live OT environments
- I have field experience with industrial controls

This document DOES claim:
- I understand control loop logic at a conceptual level
- I apply control systems design principles to security
- I can translate between IT security and OT vocabulary
- I am pursuing formal credentials to deepen this understanding

The boundary between these claims is the boundary of my
honesty. I do not cross it.
