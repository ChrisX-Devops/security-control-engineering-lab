package network.exposure_test

import rego.v1

import data.network.exposure

test_internal_only_passes if {
    count(exposure.deny) == 0 with input as {
        "security_groups": [
            {
                "name": "internal-app",
                "inbound_rules": [
                    {"port": 22, "cidr": "10.0.0.0/8"}
                ]
            }
        ]
    }
}

test_public_ssh_critical if {
    count(exposure.deny) > 0 with input as {
        "security_groups": [
            {
                "name": "exposed-ssh",
                "inbound_rules": [
                    {"port": 22, "cidr": "0.0.0.0/0"}
                ]
            }
        ]
    }
}

test_public_database_critical if {
    count(exposure.deny) > 0 with input as {
        "security_groups": [
            {
                "name": "exposed-postgres",
                "inbound_rules": [
                    {"port": 5432, "cidr": "0.0.0.0/0"}
                ]
            }
        ]
    }
}

test_public_https_warning_only if {
    count(exposure.deny) == 0 with input as {
        "security_groups": [
            {
                "name": "web-server",
                "inbound_rules": [
                    {"port": 443, "cidr": "0.0.0.0/0"}
                ]
            }
        ]
    }
}
