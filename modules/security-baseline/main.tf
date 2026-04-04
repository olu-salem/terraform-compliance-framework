# =============================================================================
# MODULE: security-baseline
# Description: Account-level security services — GuardDuty, Security Hub,
#              CloudTrail, AWS Config, SNS alerting.
#              Compliance: CIS 2.x/3.x, NIST AU-2/AU-6, SOC 2 CC7.
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
    Module    = "security-baseline"
    ManagedBy = "terraform"
  })
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =============================================================================
# KMS KEY FOR CLOUDTRAIL & LOGS
# CIS 2.7 — Ensure CloudTrail logs are encrypted at rest using KMS CMK
# =============================================================================

resource "aws_kms_key" "security" {
  description             = "KMS key for security services — CloudTrail, Config, SecurityHub logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.name}-${var.environment}-trail"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name    = "${var.name}-${var.environment}-security-kms"
    Purpose = "security-services-encryption"
  })
}

# =============================================================================
# CLOUDTRAIL
# CIS 2.1 — Ensure CloudTrail is enabled in all regions
# CIS 2.2 — Ensure CloudTrail log file validation is enabled
# CIS 2.7 — Ensure CloudTrail is encrypted with KMS CMK
# =============================================================================

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.name}-${var.environment}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(local.common_tags, {
    Name    = "${var.name}-${var.environment}-cloudtrail-logs"
    Purpose = "cloudtrail-audit-logs"
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security.arn
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.cloudtrail.arn}", "${aws_s3_bucket.cloudtrail.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name}-${var.environment}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security.arn
  tags              = local.common_tags
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${var.name}-${var.environment}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.name}-${var.environment}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true # Capture IAM, STS events
  is_multi_region_trail         = true # CIS 2.1 — All regions
  enable_log_file_validation    = true # CIS 2.2 — Tamper detection
  kms_key_id                    = aws_kms_key.security.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  # CIS 3.x — Log management console sign-in events
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-cloudtrail"
  })

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# =============================================================================
# GUARDDUTY
# CIS 3.x — Threat detection
# =============================================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true # Detect threats in S3 access patterns
    }
    kubernetes {
      audit_logs {
        enable = true # Detect Kubernetes threats
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = "SIX_HOURS"

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-guardduty"
  })
}

# =============================================================================
# AWS SECURITY HUB
# Aggregates findings from GuardDuty, Config, Inspector, Macie
# =============================================================================

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis_aws" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count         = var.enable_pci_standard ? 1 : 0
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
}

# =============================================================================
# SNS TOPIC FOR SECURITY ALERTS
# =============================================================================

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.name}-${var.environment}-security-alerts"
  kms_master_key_id = aws_kms_key.security.arn
  tags              = local.common_tags
}

resource "aws_sns_topic_subscription" "security_email" {
  count     = length(var.security_alert_emails)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_emails[count.index]
}

# =============================================================================
# CLOUDWATCH METRIC FILTERS + ALARMS (CIS 3.x)
# =============================================================================

# CIS 3.1 — Unauthorized API calls
resource "aws_cloudwatch_metric_filter" "unauthorized_api" {
  name           = "UnauthorizedAPICalls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.name}-${var.environment}-cis-3-1-unauthorized-api-calls"
  alarm_description   = "CIS 3.1 — Unauthorized API calls detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags
}

# CIS 3.3 — Root account usage
resource "aws_cloudwatch_metric_filter" "root_usage" {
  name           = "RootAccountUsage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "${var.name}-${var.environment}-cis-3-3-root-account-usage"
  alarm_description   = "CIS 3.3 — Root account login detected. Investigate immediately."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CISBenchmark"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags
}

# CIS 3.4 — IAM policy changes
resource "aws_cloudwatch_metric_filter" "iam_changes" {
  name           = "IAMPolicyChanges"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=SetDefaultPolicyVersion)}"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "${var.name}-${var.environment}-cis-3-4-iam-policy-changes"
  alarm_description   = "CIS 3.4 — IAM policy changes detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "ARN of the CloudTrail trail"
}

output "cloudtrail_bucket_name" {
  value       = aws_s3_bucket.cloudtrail.bucket
  description = "S3 bucket containing CloudTrail logs"
}

output "guardduty_detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "GuardDuty detector ID"
}

output "security_alerts_topic_arn" {
  value       = aws_sns_topic.security_alerts.arn
  description = "SNS topic ARN for security alerts — use for additional subscriptions"
}

output "security_kms_key_arn" {
  value       = aws_kms_key.security.arn
  description = "ARN of the KMS key used for security service encryption"
}