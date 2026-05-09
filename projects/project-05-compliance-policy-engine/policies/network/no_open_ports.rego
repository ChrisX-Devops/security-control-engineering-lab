# =============================================================
# POLICY: No Sensitive Ports Open to Internet
# Framework: SOC2 CC6.1, CC6.6 | ISO 27001 A.13.1.1
# Severity:  CRITICAL
# =============================================================

package network.exposure

import rego.v1

sensitive_ports := {22, 3389, 3306, 5432, 27017, 6379, 9200}

deny contains msg if {
    sg := input.security_groups[_]
    rule := sg.inbound_rules[_]
    rule.cidr == "0.0.0.0/0"
    sensitive_ports[rule.port]
    msg := sprintf(
        "CRITICAL: Security group '%s' exposes port %d to internet (0.0.0.0/0)",
        [sg.name, rule.port]
    )
}

deny_warning contains msg if {
    sg := input.security_groups[_]
    rule := sg.inbound_rules[_]
    rule.cidr == "0.0.0.0/0"
    not sensitive_ports[rule.port]
    msg := sprintf(
        "Security group '%s' exposes port %d to internet",
        [sg.name, rule.port]
    )
}
