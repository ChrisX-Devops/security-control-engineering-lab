package iam.mfa_test

import rego.v1

import data.iam.mfa

test_user_with_mfa_passes if {
    count(mfa.deny) == 0 with input as {
        "users": [
            {
                "username": "alice",
                "status": "active",
                "mfa_enabled": true,
                "role_level": "engineer"
            }
        ]
    }
}

test_user_without_mfa_denied if {
    count(mfa.deny) > 0 with input as {
        "users": [
            {
                "username": "bob",
                "status": "active",
                "mfa_enabled": false,
                "role_level": "engineer"
            }
        ]
    }
}

test_admin_without_mfa_critical if {
    count(mfa.deny_critical) > 0 with input as {
        "users": [
            {
                "username": "root",
                "status": "active",
                "mfa_enabled": false,
                "role_level": "admin"
            }
        ]
    }
}

test_inactive_user_not_flagged if {
    count(mfa.deny) == 0 with input as {
        "users": [
            {
                "username": "former-employee",
                "status": "inactive",
                "mfa_enabled": false,
                "role_level": "engineer"
            }
        ]
    }
}
