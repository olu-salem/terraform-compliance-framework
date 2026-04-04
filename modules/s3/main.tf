# =============================================================================
# MODULE: s3
# Description: Secure S3 bucket with versioning, CMK encryption, public access
#              block, access logging, lifecycle policies, and object lock.
#              Compliance: CIS 2.1.1-2.1.5, PCI DSS 3.4, NIST SC-28.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    Module    = "s3"
    ManagedBy = "terraform"
  })
}

# =============================================================================
# KMS KEY FOR S3 ENCRYPTION
# CIS 2.1.1 — Ensure S3 buckets use SSE-KMS (not SSE-S3)
# =============================================================================

resource "aws_kms_key" "s3" {
  count = var.create_kms_key ? 1 : 0

  description             = "KMS CMK for S3 bucket ${var.bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name    = "${var.bucket_name}-s3-kms"
    Purpose = "s3-encryption"
  })
}

resource "aws_kms_alias" "s3" {
  count = var.create_kms_key ? 1 : 0

  name          = "alias/${var.bucket_name}-s3"
  target_key_id = aws_kms_key.s3[0].key_id
}

locals {
  kms_key_arn = var.create_kms_key ? aws_kms_key.s3[0].arn : var.kms_key_arn
}

# =============================================================================
# S3 ACCESS LOG BUCKET (if logging to self — use a dedicated log bucket)
# CIS 2.6 — Ensure S3 bucket access logging is enabled
# =============================================================================

# Primary bucket
resource "aws_s3_bucket" "main" {
  bucket        = var.bucket_name
  force_destroy = var.environment == "prod" ? false : true

  tags = merge(local.common_tags, {
    Name = var.bucket_name
  })
}

# =============================================================================
# BLOCK ALL PUBLIC ACCESS
# CIS 2.1.5 — Ensure S3 buckets block public access
# =============================================================================

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# ENFORCE HTTPS — Deny all non-SSL requests
# PCI DSS 4.2 — Protect sensitive data in transit
# =============================================================================

resource "aws_s3_bucket_policy" "main" {
  bucket = aws_s3_bucket.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyNonTLS12"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*"
        ]
        Condition = {
          NumericLessThan = {
            "s3:TlsVersion" = "1.2"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.main]
}

# =============================================================================
# ENCRYPTION — SSE-KMS with CMK
# =============================================================================

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true # Reduce KMS request costs
  }
}

# =============================================================================
# VERSIONING — Required for audit trail and point-in-time recovery
# SOC 2 A1.2 — Recovery time objectives
# =============================================================================

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id

  versioning_configuration {
    status = "Enabled"
  }
}

# =============================================================================
# ACCESS LOGGING
# CIS 2.6 — Ensure S3 bucket access logging is enabled
# =============================================================================

resource "aws_s3_bucket_logging" "main" {
  count = var.access_log_bucket != null ? 1 : 0

  bucket        = aws_s3_bucket.main.id
  target_bucket = var.access_log_bucket
  target_prefix = "${var.bucket_name}/"
}

# =============================================================================
# LIFECYCLE RULES — Cost optimization while maintaining compliance retention
# =============================================================================

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    id     = "transition-old-versions"
    status = "Enabled"

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 90
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = "Enabled"

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = rule.value.expiration_days != null ? [1] : []
        content {
          days = rule.value.expiration_days
        }
      }
    }
  }
}

# =============================================================================
# OBJECT LOCK — Immutable storage for compliance/audit logs (WORM)
# PCI DSS 10.7 — Audit log retention
# =============================================================================

resource "aws_s3_bucket_object_lock_configuration" "main" {
  count = var.enable_object_lock ? 1 : 0

  bucket = aws_s3_bucket.main.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

# =============================================================================
# INTELLIGENT TIERING — Automatic cost optimization
# =============================================================================

resource "aws_s3_bucket_intelligent_tiering_configuration" "main" {
  count  = var.enable_intelligent_tiering ? 1 : 0
  bucket = aws_s3_bucket.main.id
  name   = "entire-bucket"

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
}