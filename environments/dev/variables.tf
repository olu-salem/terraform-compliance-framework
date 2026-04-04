# =============================================================================
# ENVIRONMENT: dev — Variables
# =============================================================================

variable "name" {
  description = "Name prefix for all resources."
  type        = string
  default     = "enterprise"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block."
  type        = string
  default     = "10.10.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "cost_center" {
  description = "Finance department cost center code."
  type        = string
}

variable "owner_email" {
  description = "Team email address responsible for this environment."
  type        = string
}

variable "project_name" {
  description = "Project name or JIRA key."
  type        = string
  default     = "PLATFORM"
}

variable "security_alert_emails" {
  description = "Email addresses for security and budget alerts."
  type        = list(string)
  default     = []
}

variable "dev_vpn_cidrs" {
  description = "CIDRs allowed to reach the EKS API (office/VPN IPs)."
  type        = list(string)
  default     = []
}

variable "monthly_budget_usd" {
  description = "Monthly AWS budget in USD. Alerts at 80% and 100% forecast."
  type        = string
  default     = "500"
}