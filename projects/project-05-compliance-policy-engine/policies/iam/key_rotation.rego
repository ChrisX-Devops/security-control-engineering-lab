# =============================================================
# POLICY: Access Key Rotation
# Framework: SOC2 CC6.1, CC6.7 | ISO 27001 A.9.2.6
# Severity:  HIGH
# =============================================================

package iam.key_rotation

import rego.v1

max_key_age_days := 90

deny contains msg if {
    user := input.users[_]
    key  := user.access_keys[_]
    key.status == "Active"
    key.age_days > max_key_age_days
    msg := sprintf(
        "User '%s' has access key older than %d days (current age: %d days)",
        [user.username, max_key_age_days, key.age_days]
    )
}

deny_critical contains msg if {
    user := input.users[_]
    key  := user.access_keys[_]
    key.status == "Active"
    key.age_days > 180
    msg := sprintf(
        "CRITICAL: User '%s' has access key %d days old (max allowed: %d)",
        [user.username, key.age_days, max_key_age_days]
    )
}
