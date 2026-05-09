# =============================================================
# POLICY: Account Password Policy Requirements
# Framework: SOC2 CC6.1, CC6.6 | ISO 27001 A.9.4.3
# Severity:  HIGH
# =============================================================

package iam.password_policy

import rego.v1

min_password_length := 14

deny contains msg if {
    not input.password_policy.policy_exists
    msg := "No account password policy is configured"
}

deny contains msg if {
    input.password_policy.MinimumPasswordLength < min_password_length
    msg := sprintf(
        "Password minimum length is %d (required: %d)",
        [input.password_policy.MinimumPasswordLength, min_password_length]
    )
}

deny contains msg if {
    not input.password_policy.RequireSymbols
    msg := "Password policy does not require symbols"
}

deny contains msg if {
    not input.password_policy.RequireNumbers
    msg := "Password policy does not require numbers"
}

deny contains msg if {
    not input.password_policy.RequireUppercaseCharacters
    msg := "Password policy does not require uppercase characters"
}

deny contains msg if {
    not input.password_policy.RequireLowercaseCharacters
    msg := "Password policy does not require lowercase characters"
}
