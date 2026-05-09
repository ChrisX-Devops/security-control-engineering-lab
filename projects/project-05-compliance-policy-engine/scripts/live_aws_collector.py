"""
Live AWS State Collector
========================
Extracts real AWS state and writes it to the input files
that the policy engine evaluates.

This is the SENSOR layer of the control system.
It reads the actual state of the environment and feeds
it to the controller (policy engine) for comparison
against setpoints (Rego policies).
"""

import boto3
import json
import os
from pathlib import Path
from datetime import datetime, timezone


class LiveAWSCollector:
    """
    Extracts AWS state and formats it for the policy engine.
    """

    def __init__(self, inputs_dir):
        """
        Args:
            inputs_dir: Path to engine inputs directory
        """
        self.inputs_dir = Path(inputs_dir)
        self.session = boto3.Session()

    def collect_iam_state(self):
        """
        Extract IAM users and password policy.

        Returns:
            Dict matching the iam-state.json schema
        """
        print("  Collecting IAM users...")

        iam = self.session.client("iam")
        users_data = []

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Get MFA status
                    mfa_devices = iam.list_mfa_devices(
                        UserName=username
                    )["MFADevices"]
                    mfa_enabled = len(mfa_devices) > 0

                    # Get attached policies
                    attached = iam.list_attached_user_policies(
                        UserName=username
                    )["AttachedPolicies"]
                    attached_policies = [p["PolicyName"] for p in attached]

                    # Get access keys
                    access_keys = []
                    keys_response = iam.list_access_keys(
                        UserName=username
                    )["AccessKeyMetadata"]

                    for key in keys_response:
                        age_days = (
                            datetime.now(timezone.utc) - key["CreateDate"]
                        ).days

                        access_keys.append({
                            "id": key["AccessKeyId"],
                            "status": key["Status"],
                            "age_days": age_days
                        })

                    users_data.append({
                        "username": username,
                        "status": "active",
                        "role_level": "engineer",
                        "mfa_enabled": mfa_enabled,
                        "attached_policies": attached_policies,
                        "access_keys": access_keys
                    })

        except Exception as e:
            print(f"  [WARN] IAM collection partial failure: {e}")

        # Get password policy
        password_policy = {"policy_exists": False}
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            password_policy = {
                "policy_exists": True,
                "MinimumPasswordLength": policy.get("MinimumPasswordLength", 0),
                "RequireSymbols": policy.get("RequireSymbols", False),
                "RequireNumbers": policy.get("RequireNumbers", False),
                "RequireUppercaseCharacters": policy.get(
                    "RequireUppercaseCharacters", False
                ),
                "RequireLowercaseCharacters": policy.get(
                    "RequireLowercaseCharacters", False
                )
            }
        except iam.exceptions.NoSuchEntityException:
            pass
        except Exception as e:
            print(f"  [WARN] Password policy fetch failed: {e}")

        return {
            "users": users_data,
            "password_policy": password_policy
        }

    def collect_s3_state(self):
        """
        Extract S3 bucket configurations.

        Returns:
            Dict matching the s3-state.json schema
        """
        print("  Collecting S3 buckets...")

        s3 = self.session.client("s3")
        buckets_data = []

        try:
            buckets_response = s3.list_buckets()["Buckets"]

            for bucket in buckets_response:
                name = bucket["Name"]

                # Encryption
                encryption_enabled = False
                try:
                    s3.get_bucket_encryption(Bucket=name)
                    encryption_enabled = True
                except s3.exceptions.ClientError:
                    pass

                # Public access block
                public_access_block = {
                    "BlockPublicAcls": False,
                    "BlockPublicPolicy": False,
                    "IgnorePublicAcls": False,
                    "RestrictPublicBuckets": False
                }
                public_access_blocked = False

                try:
                    pab = s3.get_public_access_block(
                        Bucket=name
                    )["PublicAccessBlockConfiguration"]
                    public_access_block = pab
                    public_access_blocked = all(pab.values())
                except s3.exceptions.ClientError:
                    pass

                # Tags
                tags = {}
                try:
                    tag_response = s3.get_bucket_tagging(Bucket=name)
                    for tag in tag_response.get("TagSet", []):
                        tags[tag["Key"]] = tag["Value"]
                except s3.exceptions.ClientError:
                    pass

                if "classification" not in tags:
                    tags["classification"] = "internal"

                buckets_data.append({
                    "name": name,
                    "encryption_enabled": encryption_enabled,
                    "public_access_blocked": public_access_blocked,
                    "public_access_block": public_access_block,
                    "tags": tags
                })

        except Exception as e:
            print(f"  [WARN] S3 collection failure: {e}")

        return {"buckets": buckets_data}

    def collect_network_state(self):
        """
        Extract security group configurations.

        Returns:
            Dict matching the network-state.json schema
        """
        print("  Collecting security groups...")

        ec2 = self.session.client("ec2")
        groups_data = []

        try:
            response = ec2.describe_security_groups()

            for sg in response["SecurityGroups"]:
                inbound_rules = []

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)

                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")
                        if cidr:
                            inbound_rules.append({
                                "port": from_port,
                                "cidr": cidr
                            })

                groups_data.append({
                    "name": sg["GroupName"],
                    "vpc": sg.get("VpcId", "unknown"),
                    "inbound_rules": inbound_rules
                })

        except Exception as e:
            print(f"  [WARN] Network collection failure: {e}")

        return {"security_groups": groups_data}

    def write_state_files(self):
        """
        Collect all AWS state and write to input files.
        """
        print("\nLive AWS State Collection")
        print("=" * 60)

        iam_state = self.collect_iam_state()
        s3_state = self.collect_s3_state()
        network_state = self.collect_network_state()

        iam_file = self.inputs_dir / "iam-state.json"
        s3_file = self.inputs_dir / "s3-state.json"
        network_file = self.inputs_dir / "network-state.json"

        with open(iam_file, "w") as f:
            json.dump(iam_state, f, indent=2)
        print(f"\n  Wrote: {iam_file}")

        with open(s3_file, "w") as f:
            json.dump(s3_state, f, indent=2)
        print(f"  Wrote: {s3_file}")

        with open(network_file, "w") as f:
            json.dump(network_state, f, indent=2)
        print(f"  Wrote: {network_file}")

        print(f"\nCollection complete:")
        print(f"  IAM users: {len(iam_state['users'])}")
        print(f"  S3 buckets: {len(s3_state['buckets'])}")
        print(f"  Security groups: {len(network_state['security_groups'])}")


def main():
    project_root = Path(__file__).parent.parent
    inputs_dir = project_root / "sample-inputs"

    collector = LiveAWSCollector(inputs_dir)
    collector.write_state_files()


if __name__ == "__main__":
    main()
