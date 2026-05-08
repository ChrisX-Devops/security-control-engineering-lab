
---

## Control Loop Framing

This project implements a complete security control loop.
Every component maps to an industrial control system equivalent:

| Component | Industrial Equivalent | This Project |
|-----------|----------------------|--------------|
| Sensor | Process transmitter | AWS CLI extracting IAM state |
| Setpoint | Required process value | Rego policy specification |
| Controller | PID controller | OPA policy engine |
| Deviation Detection | Comparator | Policy evaluation logic |
| Alarm | Process alarm | Deny rule output |
| Final Element | Control valve | Remediation runbook |
| Historian | Process historian | Evidence files with timestamps |

Each Rego policy is a setpoint. Each evaluation is a measurement.
Each violation is an alarm. The system runs continuously through
GitHub Actions CI/CD, just as a control system runs continuously
to keep a process within specification.

For the conceptual foundation, see:
- `frameworks/instrumentation-context.md`
- `frameworks/honest-positioning.md`

For business translation of policy outputs, see:
- `communications/frameworks/opa-translation-guide.md`
