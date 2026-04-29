#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="$BASE_DIR/policies/live-input.json"

mkdir -p "$BASE_DIR/policies"

echo '{"users":[' > "$OUTPUT"

FIRST=true

for USER in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  POLICIES=$(aws iam list-attached-user-policies \
    --user-name "$USER" \
    --query 'AttachedPolicies[*].PolicyName' \
    --output json)

  if [ "$FIRST" = true ]; then
    FIRST=false
  else
    echo "," >> "$OUTPUT"
  fi

  printf '{"name":"%s","attached_policies":%s}' "$USER" "$POLICIES" >> "$OUTPUT"
done

echo ']}' >> "$OUTPUT"

echo "[+] Exported live IAM data to $OUTPUT"