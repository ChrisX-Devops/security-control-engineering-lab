# =============================================================
# POLICY: S3 Public Access Must Be Blocked
# Framework: SOC2 CC6.1, CC6.6 | ISO 27001 A.13.1.3
# Severity:  CRITICAL
# =============================================================

package s3.public_access

import rego.v1

deny contains msg if {
    bucket := input.buckets[_]
    bucket.public_access_blocked == false
    msg := sprintf(
        "Bucket '%s' does not have all public access block settings enabled",
        [bucket.name]
    )
}

deny contains msg if {
    bucket := input.buckets[_]
    bucket.public_access_block.BlockPublicAcls == false
    msg := sprintf(
        "Bucket '%s' allows public ACLs",
        [bucket.name]
    )
}

deny contains msg if {
    bucket := input.buckets[_]
    bucket.public_access_block.BlockPublicPolicy == false
    msg := sprintf(
        "Bucket '%s' allows public bucket policies",
        [bucket.name]
    )
}
