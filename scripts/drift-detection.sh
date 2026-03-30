#!/usr/bin/env bash
# =============================================================================
# drift-detection.sh
# Purpose: Detect configuration drift by comparing live infrastructure
#          against Terraform state. Alerts via PagerDuty/Slack on drift.
#
# Usage:
#   ./drift-detection.sh --env prod --alert-on-drift true
#   ./drift-detection.sh --env dev --alert-on-drift false
# =============================================================================

set -euo pipefail

# ─── Arguments ────────────────────────────────────────────────────────────────
ENV=""
ALERT_ON_DRIFT="true"
TERRAFORM_DIR=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --env)            ENV="$2";            shift 2 ;;
    --alert-on-drift) ALERT_ON_DRIFT="$2"; shift 2 ;;
    --dir)            TERRAFORM_DIR="$2";  shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

TERRAFORM_DIR="${TERRAFORM_DIR:-"$(dirname "$0")/../environments/${ENV}"}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="/tmp/drift-report-${ENV}-${TIMESTAMP}.txt"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Terraform Drift Detection"
echo "  Environment: ${ENV}"
echo "  Directory:   ${TERRAFORM_DIR}"
echo "  Timestamp:   ${TIMESTAMP}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Validate environment ─────────────────────────────────────────────────────
if [[ ! -d "${TERRAFORM_DIR}" ]]; then
  echo "ERROR: Terraform directory not found: ${TERRAFORM_DIR}"
  exit 1
fi

# ─── Run Terraform Plan ───────────────────────────────────────────────────────
echo ""
echo "▶ Running terraform plan to detect drift..."

cd "${TERRAFORM_DIR}"

terraform plan \
  -var-file="terraform.tfvars" \
  -detailed-exitcode \
  -no-color \
  -refresh=true \
  2>&1 | tee "${REPORT_FILE}"

PLAN_EXIT_CODE=${PIPESTATUS[0]}

# terraform plan -detailed-exitcode returns:
#   0 = Success, no changes (no drift)
#   1 = Error
#   2 = Success, changes present (DRIFT DETECTED)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

case ${PLAN_EXIT_CODE} in
  0)
    echo "  ✅ NO DRIFT DETECTED — infrastructure matches state"
    exit 0
    ;;
  1)
    echo "  ❌ TERRAFORM ERROR — plan failed"
    exit 1
    ;;
  2)
    echo "  ⚠️  DRIFT DETECTED — live infrastructure differs from Terraform state"
    echo ""
    
    # Count number of resources that changed
    CHANGES=$(grep -c "^  # " "${REPORT_FILE}" || true)
    echo "  Affected resources: ${CHANGES}"
    echo ""

    # Extract summary of changes
    echo "  Changed resources:"
    grep "^  # " "${REPORT_FILE}" | head -20 | sed 's/^/    /'

    if [[ "${ALERT_ON_DRIFT}" == "true" ]]; then
      echo ""
      echo "▶ Sending drift alert..."
      send_drift_alert "${ENV}" "${CHANGES}" "${REPORT_FILE}"
    fi

    exit 2
    ;;
esac

# ─── Alert Functions ──────────────────────────────────────────────────────────
send_drift_alert() {
  local env=$1
  local change_count=$2
  local report=$3

  # PagerDuty Alert (uncomment and configure in production)
  # PAGERDUTY_ROUTING_KEY="${PAGERDUTY_ROUTING_KEY:-}"
  # if [[ -n "${PAGERDUTY_ROUTING_KEY}" ]]; then
  #   curl -sS -X POST "https://events.pagerduty.com/v2/enqueue" \
  #     -H "Content-Type: application/json" \
  #     -d "{
  #       \"routing_key\": \"${PAGERDUTY_ROUTING_KEY}\",
  #       \"event_action\": \"trigger\",
  #       \"payload\": {
  #         \"summary\": \"Terraform drift detected in ${env} (${change_count} resources)\",
  #         \"severity\": \"warning\",
  #         \"source\": \"drift-detection\",
  #         \"custom_details\": {
  #           \"environment\": \"${env}\",
  #           \"changes\": \"${change_count}\",
  #           \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
  #         }
  #       }
  #     }"
  # fi

  # Slack Alert (uncomment and configure in production)  
  # SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
  # if [[ -n "${SLACK_WEBHOOK}" ]]; then
  #   curl -sS -X POST "${SLACK_WEBHOOK}" \
  #     -H "Content-Type: application/json" \
  #     -d "{
  #       \"text\": \":warning: *Terraform Drift Detected* in \`${env}\`\n${change_count} resource(s) differ from Terraform state.\nRun \`terraform apply\` or investigate unauthorized changes.\",
  #       \"username\": \"drift-detector\",
  #       \"icon_emoji\": \":terraform:\"
  #     }"
  # fi

  echo "  Alert sent (configure PAGERDUTY_ROUTING_KEY or SLACK_WEBHOOK for real alerts)"
}