package s3.encryption_test

import rego.v1

import data.s3.encryption

test_encrypted_bucket_passes if {
    count(encryption.deny) == 0 with input as {
        "buckets": [
            {
                "name": "secure-bucket",
                "encryption_enabled": true,
                "tags": {"classification": "internal"}
            }
        ]
    }
}

test_unencrypted_bucket_denied if {
    count(encryption.deny) > 0 with input as {
        "buckets": [
            {
                "name": "insecure-bucket",
                "encryption_enabled": false,
                "tags": {"classification": "internal"}
            }
        ]
    }
}

test_unencrypted_sensitive_bucket_critical if {
    count(encryption.deny_critical) > 0 with input as {
        "buckets": [
            {
                "name": "sensitive-data",
                "encryption_enabled": false,
                "tags": {"classification": "sensitive"}
            }
        ]
    }
}
