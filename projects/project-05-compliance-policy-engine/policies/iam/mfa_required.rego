# =============================================================
# POLICY: MFA Required for All Active Users
# Framework: SOC2 CC6.1 | ISO 27001 A.9.4.2
# Severity:  CRITICAL
# =============================================================

package iam.mfa

import rego.v1

deny contains msg if {
    user := input.users[_]
    user.status == "active"
    user.mfa_enabled == false
    msg := sprintf(
        "User '%s' is active but does not have MFA enabled",
        [user.username]
    )
}

deny_critical contains msg if {
    user := input.users[_]
    user.status == "active"
    user.mfa_enabled == false
    user.role_level == "admin"
    msg := sprintf(
        "CRITICAL: Admin user '%s' has no MFA enabled",
        [user.username]
    )
}
