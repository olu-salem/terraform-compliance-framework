# =============================================================================
# MODULE: s3 — Variables
# =============================================================================

variable "bucket_name" {
  description = "Globally unique S3 bucket name."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9\\-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be 3-63 lowercase alphanumeric characters or hyphens."
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string
}

variable "create_kms_key" {
  description = "Create a dedicated KMS key for this bucket. Set false to provide your own via kms_key_arn."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN. Only used when create_kms_key = false."
  type        = string
  default     = null
}

variable "access_log_bucket" {
  description = "S3 bucket name to send access logs. Use a dedicated centralized log bucket."
  type        = string
  default     = null
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock for WORM compliance. Required for PCI DSS audit logs."
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "Default retention days for Object Lock. Only applies when enable_object_lock = true."
  type        = number
  default     = 365
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain non-current object versions before deletion."
  type        = number
  default     = 365
}

variable "enable_intelligent_tiering" {
  description = "Enable S3 Intelligent Tiering for automatic cost optimization."
  type        = bool
  default     = true
}

variable "lifecycle_rules" {
  description = "Additional lifecycle rules for the bucket."
  type = list(object({
    id = string
    transitions = list(object({
      days          = number
      storage_class = string
    }))
    expiration_days = optional(number)
  }))
  default = []
}

variable "tags" {
  description = "Resource tags. CostCenter, Owner, Environment, and DataClass are required."
  type        = map(string)
}

# =============================================================================
# MODULE: s3 — Outputs
# =============================================================================