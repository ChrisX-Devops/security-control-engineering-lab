# =============================================================
# POLICY: Least Privilege - No AdministratorAccess
# Framework: SOC2 CC6.3 | ISO 27001 A.9.2.3
# Severity:  HIGH
# =============================================================

package iam.access

import rego.v1

deny contains msg if {
    user := input.users[_]
    "AdministratorAccess" in user.attached_policies
    msg := sprintf(
        "User '%s' has AdministratorAccess attached - violates least privilege",
        [user.username]
    )
}
