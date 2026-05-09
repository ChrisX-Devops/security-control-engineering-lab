#!/bin/bash
#
# Compliance Policy Engine - Full Pipeline Runner
#
# Usage:
#   ./run_engine.sh                    # Use existing input files
#   ./run_engine.sh --live             # Collect live AWS state first
#

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$PROJECT_DIR/scripts"

echo "============================================================"
echo "  Compliance Policy Engine"
echo "  $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo "============================================================"
echo ""

# Step 1: Collect live AWS state if requested
if [ "$1" = "--live" ]; then
    echo "STEP 1: Collecting live AWS state"
    echo "------------------------------------------------------------"
    python3 "$SCRIPTS_DIR/live_aws_collector.py"
    echo ""
fi

# Step 2: Run policy engine
echo "STEP 2: Running policy evaluations"
echo "------------------------------------------------------------"
python3 "$SCRIPTS_DIR/policy_engine.py"
echo ""

# Step 3: Generate reports
echo "STEP 3: Generating stakeholder reports"
echo "------------------------------------------------------------"
python3 "$SCRIPTS_DIR/report_generator.py"
echo ""

# Step 4: Detect standing alarms
echo "STEP 4: Detecting standing alarms"
echo "------------------------------------------------------------"
python3 "$SCRIPTS_DIR/standing_alarm_detector.py"
echo ""

echo "============================================================"
echo "  Pipeline complete"
echo "  Outputs saved to: $PROJECT_DIR/output/"
echo "============================================================"
