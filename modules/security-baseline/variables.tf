# =============================================================================
# MODULE: security-baseline — Variables
# =============================================================================

variable "name" {
  description = "Name prefix for all resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev, staging, or prod."
  type        = string
}

variable "security_alert_emails" {
  description = "Email addresses to notify for security alerts (GuardDuty findings, CIS alarms)."
  type        = list(string)
  default     = []
}

variable "enable_pci_standard" {
  description = "Enable PCI DSS 3.2.1 standard in Security Hub. Enable for cardholder data environments."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Resource tags. CostCenter, Owner, Environment, and DataClass are required."
  type        = map(string)
}