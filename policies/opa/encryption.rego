# =============================================================================
# OPA Policy: encryption.rego
# Purpose: Enforce encryption-at-rest and in-transit for all data resources.
#
# Controls mapped:
#   - PCI DSS 3.4  — Render PAN unreadable using strong cryptography
#   - HIPAA 164.312(a)(2)(iv) — Encryption and decryption
#   - NIST SC-28    — Protection of information at rest
#   - CIS 2.1.1     — Ensure S3 buckets use SSE
#   - SOC 2 CC6.1   — Logical and physical access controls
# =============================================================================

package enterprise.terraform

# ─── S3 Encryption Rules ──────────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  resource.change.actions[_] in {"create", "update"}

  rule := resource.change.after.rule[_]
  algorithm := rule.apply_server_side_encryption_by_default[_].sse_algorithm
  algorithm == "AES256"  # SSE-S3 — not CMK

  msg := sprintf(
    "ENCRYPTION-001: S3 bucket '%s' uses AES256 (SSE-S3) encryption. Enterprise policy requires SSE-KMS with a CMK (customer-managed key) for all buckets containing internal or higher classified data.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket"
  resource.change.actions[_] in {"create", "update"}

  # Check if no encryption config exists for this bucket
  not _s3_encryption_configured(resource.address)

  msg := sprintf(
    "ENCRYPTION-002: S3 bucket '%s' has no server-side encryption configuration. All S3 buckets must be encrypted.",
    [resource.address]
  )
}

_s3_encryption_configured(bucket_address) if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  resource.change.after.bucket == bucket_address
}

# ─── RDS Encryption Rules ─────────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type in {"aws_rds_cluster", "aws_db_instance"}
  resource.change.actions[_] in {"create", "update"}

  storage_encrypted := object.get(resource.change.after, "storage_encrypted", false)
  not storage_encrypted

  msg := sprintf(
    "ENCRYPTION-003: RDS resource '%s' does not have storage_encrypted = true. All RDS instances must be encrypted at rest (PCI DSS 3.4, HIPAA 164.312).",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type in {"aws_rds_cluster", "aws_db_instance"}
  resource.change.actions[_] in {"create", "update"}

  storage_encrypted := object.get(resource.change.after, "storage_encrypted", false)
  storage_encrypted

  kms_key := object.get(resource.change.after, "kms_key_id", "")
  count(kms_key) == 0

  msg := sprintf(
    "ENCRYPTION-004: RDS resource '%s' is encrypted but not using a CMK (kms_key_id is empty). Enterprise policy requires CMK for RDS encryption to enable key rotation and access control.",
    [resource.address]
  )
}

# ─── EBS Volume Encryption Rules ──────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_ebs_volume"
  resource.change.actions[_] in {"create", "update"}

  encrypted := object.get(resource.change.after, "encrypted", false)
  not encrypted

  msg := sprintf(
    "ENCRYPTION-005: EBS volume '%s' is not encrypted. All EBS volumes must be encrypted (CIS 2.2.1).",
    [resource.address]
  )
}

# ─── ElastiCache Encryption Rules ─────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_elasticache_replication_group"
  resource.change.actions[_] in {"create", "update"}

  at_rest := object.get(resource.change.after, "at_rest_encryption_enabled", false)
  not at_rest

  msg := sprintf(
    "ENCRYPTION-006: ElastiCache cluster '%s' does not have at_rest_encryption_enabled = true.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_elasticache_replication_group"
  resource.change.actions[_] in {"create", "update"}

  in_transit := object.get(resource.change.after, "transit_encryption_enabled", false)
  not in_transit

  msg := sprintf(
    "ENCRYPTION-007: ElastiCache cluster '%s' does not have transit_encryption_enabled = true. All data in transit must be encrypted (PCI DSS 4.2).",
    [resource.address]
  )
}

# ─── CloudWatch Logs Encryption Rules ─────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_log_group"
  resource.change.actions[_] in {"create", "update"}

  kms_key := object.get(resource.change.after, "kms_key_id", "")
  count(kms_key) == 0

  msg := sprintf(
    "ENCRYPTION-008: CloudWatch Log Group '%s' is not encrypted with a KMS key. Security-sensitive logs must be encrypted (NIST SC-28).",
    [resource.address]
  )
}

# ─── SQS/SNS Encryption Rules ─────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_sqs_queue"
  resource.change.actions[_] in {"create", "update"}

  kms_key := object.get(resource.change.after, "kms_master_key_id", "")
  count(kms_key) == 0

  msg := sprintf(
    "ENCRYPTION-009: SQS queue '%s' is not encrypted with a CMK. Use kms_master_key_id to enable SSE-KMS.",
    [resource.address]
  )
}