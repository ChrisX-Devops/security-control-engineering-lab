package iam.key_rotation_test

import rego.v1

import data.iam.key_rotation

test_recent_key_passes if {
    count(key_rotation.deny) == 0 with input as {
        "users": [
            {
                "username": "alice",
                "access_keys": [
                    {"id": "AKIA111", "status": "Active", "age_days": 30}
                ]
            }
        ]
    }
}

test_old_key_denied if {
    count(key_rotation.deny) > 0 with input as {
        "users": [
            {
                "username": "bob",
                "access_keys": [
                    {"id": "AKIA222", "status": "Active", "age_days": 120}
                ]
            }
        ]
    }
}

test_very_old_key_critical if {
    count(key_rotation.deny_critical) > 0 with input as {
        "users": [
            {
                "username": "admin",
                "access_keys": [
                    {"id": "AKIA333", "status": "Active", "age_days": 200}
                ]
            }
        ]
    }
}

test_inactive_old_key_passes if {
    count(key_rotation.deny) == 0 with input as {
        "users": [
            {
                "username": "service",
                "access_keys": [
                    {"id": "AKIA444", "status": "Inactive", "age_days": 365}
                ]
            }
        ]
    }
}
