# =============================================================================
# MODULE: rds — Variables
# =============================================================================

variable "name" {
  description = "Name prefix for all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, or prod."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "vpc_id" {
  description = "VPC ID for the RDS security group."
  type        = string
}

variable "intra_subnet_ids" {
  description = "List of intra subnet IDs (no internet egress) for RDS instances."
  type        = list(string)
  validation {
    condition     = length(var.intra_subnet_ids) >= 2
    error_message = "RDS requires at least 2 subnets in different AZs for Multi-AZ."
  }
}

variable "allowed_security_group_ids" {
  description = "Security group IDs allowed to connect to RDS on port 5432."
  type        = list(string)
}

variable "engine_version" {
  description = "Aurora PostgreSQL engine version."
  type        = string
  default     = "15.4"
}

variable "instance_class" {
  description = "RDS instance class. Use db.r6g.* for production workloads."
  type        = string
  default     = "db.r6g.large"
}

variable "instance_count" {
  description = "Number of Aurora instances. Minimum 2 for production (writer + reader)."
  type        = number
  default     = 2
  validation {
    condition     = var.instance_count >= 1 && var.instance_count <= 15
    error_message = "Instance count must be between 1 and 15."
  }
}

variable "database_name" {
  description = "Name of the initial database to create."
  type        = string
  default     = "appdb"
}

variable "master_username" {
  description = "Master username for the RDS cluster. Password is auto-generated and stored in Secrets Manager."
  type        = string
  default     = "dbadmin"
}

variable "backup_retention_days" {
  description = "Number of days to retain automated backups. PCI DSS requires minimum 1 year."
  type        = number
  default     = 35
  validation {
    condition     = var.backup_retention_days >= 7
    error_message = "Backup retention must be at least 7 days."
  }
}

variable "max_connections_threshold" {
  description = "CloudWatch alarm threshold for database connections."
  type        = number
  default     = 500
}

variable "sns_alert_topic_arns" {
  description = "List of SNS topic ARNs for CloudWatch alarm notifications."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags. CostCenter, Owner, Environment, and DataClass are required."
  type        = map(string)
}