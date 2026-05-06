#!/bin/bash
# =============================================================
# Policy Engine Runner
# =============================================================
# Evaluates all OPA policies against test inputs and
# produces a unified violation report.
# =============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="$PROJECT_DIR/policies"
INPUTS_DIR="$PROJECT_DIR/test-inputs"
EVIDENCE_DIR="$PROJECT_DIR/evidence"
TODAY=$(date +%Y-%m-%d)

mkdir -p "$EVIDENCE_DIR"

REPORT_FILE="$EVIDENCE_DIR/policy-evaluation-$TODAY.txt"

echo "=============================================================" | tee "$REPORT_FILE"
echo "OPA POLICY EVALUATION REPORT"                                  | tee -a "$REPORT_FILE"
echo "Date: $TODAY"                                                  | tee -a "$REPORT_FILE"
echo "=============================================================" | tee -a "$REPORT_FILE"
echo ""                                                              | tee -a "$REPORT_FILE"

TOTAL_VIOLATIONS=0

# Evaluate IAM policies
echo "--- IAM POLICIES ---" | tee -a "$REPORT_FILE"
echo ""                     | tee -a "$REPORT_FILE"

for policy in "$POLICIES_DIR/iam"/*.rego; do
    POLICY_NAME=$(basename "$policy" .rego)
    PACKAGE=$(grep -m1 "^package" "$policy" | awk '{print $2}')

    echo "Policy: $POLICY_NAME"                | tee -a "$REPORT_FILE"
    echo "Package: $PACKAGE"                   | tee -a "$REPORT_FILE"

    RESULT=$(opa eval -d "$policy" -i "$INPUTS_DIR/iam-test-input.json" "data.$PACKAGE.deny" 2>/dev/null || echo "{}")
    VIOLATIONS=$(echo "$RESULT" | grep -o '"' | wc -l)
    VIOLATIONS=$((VIOLATIONS / 2))

    if [ "$VIOLATIONS" -gt 0 ]; then
        echo "Violations: $VIOLATIONS"          | tee -a "$REPORT_FILE"
        echo "$RESULT"                          | tee -a "$REPORT_FILE"
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + VIOLATIONS))
    else
        echo "Result: PASS - no violations"     | tee -a "$REPORT_FILE"
    fi
    echo ""                                     | tee -a "$REPORT_FILE"
done

# Evaluate S3 policies
echo "--- S3 POLICIES ---" | tee -a "$REPORT_FILE"
echo ""                    | tee -a "$REPORT_FILE"

for policy in "$POLICIES_DIR/s3"/*.rego; do
    POLICY_NAME=$(basename "$policy" .rego)
    PACKAGE=$(grep -m1 "^package" "$policy" | awk '{print $2}')

    echo "Policy: $POLICY_NAME"                | tee -a "$REPORT_FILE"
    echo "Package: $PACKAGE"                   | tee -a "$REPORT_FILE"

    RESULT=$(opa eval -d "$policy" -i "$INPUTS_DIR/s3-test-input.json" "data.$PACKAGE.deny" 2>/dev/null || echo "{}")
    VIOLATIONS=$(echo "$RESULT" | grep -o '"' | wc -l)
    VIOLATIONS=$((VIOLATIONS / 2))

    if [ "$VIOLATIONS" -gt 0 ]; then
        echo "Violations: $VIOLATIONS"          | tee -a "$REPORT_FILE"
        echo "$RESULT"                          | tee -a "$REPORT_FILE"
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + VIOLATIONS))
    else
        echo "Result: PASS - no violations"     | tee -a "$REPORT_FILE"
    fi
    echo ""                                     | tee -a "$REPORT_FILE"
done

# Evaluate network policies
echo "--- NETWORK POLICIES ---" | tee -a "$REPORT_FILE"
echo ""                         | tee -a "$REPORT_FILE"

for policy in "$POLICIES_DIR/network"/*.rego; do
    POLICY_NAME=$(basename "$policy" .rego)
    PACKAGE=$(grep -m1 "^package" "$policy" | awk '{print $2}')

    echo "Policy: $POLICY_NAME"                | tee -a "$REPORT_FILE"
    echo "Package: $PACKAGE"                   | tee -a "$REPORT_FILE"

    RESULT=$(opa eval -d "$policy" -i "$INPUTS_DIR/network-test-input.json" "data.$PACKAGE.deny" 2>/dev/null || echo "{}")
    VIOLATIONS=$(echo "$RESULT" | grep -o '"' | wc -l)
    VIOLATIONS=$((VIOLATIONS / 2))

    if [ "$VIOLATIONS" -gt 0 ]; then
        echo "Violations: $VIOLATIONS"          | tee -a "$REPORT_FILE"
        echo "$RESULT"                          | tee -a "$REPORT_FILE"
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + VIOLATIONS))
    else
        echo "Result: PASS - no violations"     | tee -a "$REPORT_FILE"
    fi
    echo ""                                     | tee -a "$REPORT_FILE"
done

echo "=============================================================" | tee -a "$REPORT_FILE"
echo "TOTAL VIOLATIONS DETECTED: $TOTAL_VIOLATIONS"                  | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE"                                 | tee -a "$REPORT_FILE"
echo "=============================================================" | tee -a "$REPORT_FILE"
