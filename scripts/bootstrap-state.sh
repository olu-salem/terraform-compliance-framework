#!/usr/bin/env bash
# =============================================================================
# bootstrap-state.sh
# Purpose: Initialize remote Terraform state backend for a new environment.
#          Run this ONCE per account before deploying any Terraform.
#
# Creates:
#   - S3 bucket for Terraform state with versioning + encryption
#   - DynamoDB table for state locking
#   - KMS key for state file encryption
#
# Usage:
#   ./bootstrap-state.sh --account-id 123456789012 --region us-east-1 --env dev
# =============================================================================

set -euo pipefail

# ─── Argument Parsing ─────────────────────────────────────────────────────────
ACCOUNT_ID=""
REGION="us-east-1"
ENV=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --account-id) ACCOUNT_ID="$2"; shift 2 ;;
    --region)     REGION="$2";     shift 2 ;;
    --env)        ENV="$2";        shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$ACCOUNT_ID" || -z "$ENV" ]]; then
  echo "Usage: $0 --account-id <account_id> --region <region> --env <dev|staging|prod>"
  exit 1
fi

BUCKET_NAME="enterprise-tfstate-${ENV}-${ACCOUNT_ID}"
TABLE_NAME="enterprise-tfstate-lock-${ENV}"
KMS_ALIAS="alias/enterprise-tfstate-${ENV}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Terraform State Backend Bootstrap"
echo "  Account: ${ACCOUNT_ID}"
echo "  Region:  ${REGION}"
echo "  Env:     ${ENV}"
echo "  Bucket:  ${BUCKET_NAME}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── KMS Key ──────────────────────────────────────────────────────────────────
echo ""
echo "▶ Creating KMS key for state encryption..."

# Check if alias already exists
if aws kms describe-key --key-id "${KMS_ALIAS}" --region "${REGION}" &>/dev/null; then
  echo "  ✓ KMS key already exists: ${KMS_ALIAS}"
  KMS_KEY_ARN=$(aws kms describe-key --key-id "${KMS_ALIAS}" --region "${REGION}" \
    --query "KeyMetadata.Arn" --output text)
else
  KMS_KEY_ID=$(aws kms create-key \
    --description "Terraform state encryption key — ${ENV}" \
    --region "${REGION}" \
    --tags "TagKey=Environment,TagValue=${ENV}" "TagKey=ManagedBy,TagValue=bootstrap-script" \
    --query "KeyMetadata.KeyId" \
    --output text)

  aws kms create-alias \
    --alias-name "${KMS_ALIAS}" \
    --target-key-id "${KMS_KEY_ID}" \
    --region "${REGION}"

  aws kms enable-key-rotation \
    --key-id "${KMS_KEY_ID}" \
    --region "${REGION}"

  KMS_KEY_ARN="arn:aws:kms:${REGION}:${ACCOUNT_ID}:${KMS_ALIAS}"
  echo "  ✓ Created KMS key: ${KMS_KEY_ARN}"
fi

# ─── S3 Bucket ────────────────────────────────────────────────────────────────
echo ""
echo "▶ Creating S3 state bucket: ${BUCKET_NAME}..."

if aws s3api head-bucket --bucket "${BUCKET_NAME}" --region "${REGION}" &>/dev/null; then
  echo "  ✓ Bucket already exists: ${BUCKET_NAME}"
else
  aws s3api create-bucket \
    --bucket "${BUCKET_NAME}" \
    --region "${REGION}" \
    $([ "${REGION}" != "us-east-1" ] && echo "--create-bucket-configuration LocationConstraint=${REGION}")
  echo "  ✓ Bucket created"

  # Block all public access
  aws s3api put-public-access-block \
    --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration \
      "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  echo "  ✓ Public access blocked"

  # Enable versioning
  aws s3api put-bucket-versioning \
    --bucket "${BUCKET_NAME}" \
    --versioning-configuration Status=Enabled
  echo "  ✓ Versioning enabled"

  # Enable SSE-KMS encryption
  aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration "{
      \"Rules\": [{
        \"ApplyServerSideEncryptionByDefault\": {
          \"SSEAlgorithm\": \"aws:kms\",
          \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
        },
        \"BucketKeyEnabled\": true
      }]
    }"
  echo "  ✓ SSE-KMS encryption enabled"

  # Enforce HTTPS only
  aws s3api put-bucket-policy \
    --bucket "${BUCKET_NAME}" \
    --policy "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [{
        \"Sid\": \"DenyHTTP\",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:*\",
        \"Resource\": [\"arn:aws:s3:::${BUCKET_NAME}\", \"arn:aws:s3:::${BUCKET_NAME}/*\"],
        \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
      }]
    }"
  echo "  ✓ HTTPS-only policy applied"
fi

# ─── DynamoDB Lock Table ───────────────────────────────────────────────────────
echo ""
echo "▶ Creating DynamoDB lock table: ${TABLE_NAME}..."

if aws dynamodb describe-table --table-name "${TABLE_NAME}" --region "${REGION}" &>/dev/null; then
  echo "  ✓ DynamoDB table already exists: ${TABLE_NAME}"
else
  aws dynamodb create-table \
    --table-name "${TABLE_NAME}" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId="${KMS_KEY_ARN}" \
    --region "${REGION}" \
    --tags "Key=Environment,Value=${ENV}" "Key=ManagedBy,Value=bootstrap-script" \
    > /dev/null

  echo "  ✓ DynamoDB table created with SSE-KMS"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Bootstrap complete!"
echo ""
echo "  Use these values for terraform init:"
echo ""
echo "  terraform init \\"
echo "    -backend-config=\"bucket=${BUCKET_NAME}\" \\"
echo "    -backend-config=\"key=${ENV}/terraform.tfstate\" \\"
echo "    -backend-config=\"region=${REGION}\" \\"
echo "    -backend-config=\"dynamodb_table=${TABLE_NAME}\" \\"
echo "    -backend-config=\"kms_key_id=${KMS_KEY_ARN}\" \\"
echo "    -backend-config=\"encrypt=true\""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"