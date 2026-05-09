# =============================================================
# POLICY: S3 Bucket Encryption Required
# Framework: SOC2 CC6.1 | ISO 27001 A.10.1.1
# Severity:  HIGH
# =============================================================

package s3.encryption

import rego.v1

deny contains msg if {
    bucket := input.buckets[_]
    bucket.encryption_enabled == false
    msg := sprintf(
        "Bucket '%s' does not have server-side encryption enabled",
        [bucket.name]
    )
}

deny_critical contains msg if {
    bucket := input.buckets[_]
    bucket.encryption_enabled == false
    bucket.tags.classification == "sensitive"
    msg := sprintf(
        "CRITICAL: Sensitive bucket '%s' is unencrypted",
        [bucket.name]
    )
}
