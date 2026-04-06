# =============================================================================
# MODULE: vpc — Variables
# =============================================================================

variable "name" {
  description = "Name prefix for all resources. Used in resource naming and tagging."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name))
    error_message = "Name must be lowercase alphanumeric with hyphens only."
  }
}

variable "environment" {
  description = "Deployment environment. Controls defaults for HA settings and logging retention."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for deployment."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC. Must be a valid RFC 1918 private address space."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }

  validation {
    condition = (
      startswith(var.vpc_cidr, "10.") ||
      startswith(var.vpc_cidr, "172.16.") ||
      startswith(var.vpc_cidr, "192.168.")
    )
    error_message = "VPC CIDR must be a private address space (RFC 1918)."
  }
}

variable "availability_zones" {
  description = "List of availability zones. Minimum 2 for HA, recommended 3 for production."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones required for high availability."
  }

  validation {
    condition     = length(var.availability_zones) <= 4
    error_message = "Maximum of 4 availability zones supported."
  }
}

variable "single_nat_gateway" {
  description = <<-EOT
    Use a single NAT gateway instead of one per AZ.
    Set true for dev/staging to reduce cost (~$32/month per NAT).
    MUST be false for production (NIST SA-17: Resilience of mission-critical services).
  EOT
  type        = bool
  default     = false

  # Lifecycle validation — warn if prod tries to use single NAT
}

variable "flow_log_retention_days" {
  description = <<-EOT
    CloudWatch log retention for VPC flow logs.
    NIST AU-11 / SOC 2 CC7.2 requires minimum 90 days online retention.
    PCI DSS 10.7 requires minimum 1 year.
    Default 365 days satisfies both.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = contains([7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 3653], var.flow_log_retention_days)
    error_message = "Flow log retention must be a valid CloudWatch Logs retention period value."
  }
}

variable "kms_key_arn" {
  description = "ARN of KMS CMK for encrypting VPC flow logs in CloudWatch. Required for PCI-DSS and HIPAA."
  type        = string
  default     = null
}

variable "require_cost_center_tag" {
  description = "When false, CostCenter is not required on var.tags (for accounts whose Organization tag policy rejects every CostCenter value you can set)."
  type        = bool
  default     = true
}

variable "tags" {
  description = <<-EOT
    Resource tags. The following tags are REQUIRED by OPA compliance policy:
      - Environment : dev | staging | prod
      - CostCenter  : Finance department code for chargeback (unless require_cost_center_tag = false)
      - Owner       : Team email address responsible for resource
      - DataClass   : public | internal | confidential | restricted
    
    Missing required tags will cause the OPA policy check to fail in CI/CD.
  EOT
  type        = map(string)

  validation {
    condition     = contains(keys(var.tags), "Environment")
    error_message = "Tag 'Environment' is required. OPA compliance policy: TAGGING-001."
  }

  validation {
    condition     = !var.require_cost_center_tag || contains(keys(var.tags), "CostCenter")
    error_message = "Tag 'CostCenter' is required. OPA compliance policy: TAGGING-002."
  }

  validation {
    condition     = contains(keys(var.tags), "Owner")
    error_message = "Tag 'Owner' is required. OPA compliance policy: TAGGING-003."
  }

  validation {
    condition     = contains(keys(var.tags), "DataClass")
    error_message = "Tag 'DataClass' is required. OPA compliance policy: TAGGING-004."
  }
}