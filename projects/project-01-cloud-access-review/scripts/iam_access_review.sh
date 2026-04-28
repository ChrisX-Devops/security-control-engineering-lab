#!/usr/bin/env bash

set -euo pipefail

OUTPUT="../evidence/iam-access-review-$(date +%F).txt"
mkdir -p ../evidence

echo "IAM Access Review - $(date)" > "$OUTPUT"
echo "==================================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

USERS=$(aws iam list-users --query 'Users[*].UserName' --output text)

for USER in $USERS; do
  echo "User: $USER" >> "$OUTPUT"

  POLICIES=$(aws iam list-attached-user-policies \
    --user-name "$USER" \
    --query 'AttachedPolicies[*].PolicyName' \
    --output text)

  if [[ -z "$POLICIES" ]]; then
    echo "  Attached Policies: None" >> "$OUTPUT"
  else
    echo "  Attached Policies: $POLICIES" >> "$OUTPUT"
  fi

  if echo "$POLICIES" | grep -q "AdministratorAccess"; then
    echo "  Risk: Over-permissioned (AdministratorAccess detected)" >> "$OUTPUT"
  else
    echo "  Risk: No immediate over-permissioning detected" >> "$OUTPUT"
  fi

  echo "" >> "$OUTPUT"
done

echo "[+] IAM access review complete: $OUTPUT"