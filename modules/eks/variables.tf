# =============================================================================
# MODULE: eks — Variables
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
  description = "ID of the VPC to deploy EKS into."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC. Used for security group rules."
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for EKS nodes and the API server ENIs."
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "EKS requires at least 2 subnets in different AZs."
  }
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster. Update regularly for security patches."
  type        = string
  default     = "1.29"
}

variable "public_api_endpoint" {
  description = <<-EOT
    Whether the EKS API server endpoint is publicly accessible.
    MUST be false for production environments.
    CIS EKS 4.6.6 — Ensure clusters are not publicly accessible.
  EOT
  type        = bool
  default     = false
}

variable "api_allowed_cidrs" {
  description = "CIDRs allowed to reach the public API endpoint. Only used if public_api_endpoint = true."
  type        = list(string)
  default     = []
}

variable "service_cidr" {
  description = "CIDR block for Kubernetes services. Must not overlap with VPC CIDR."
  type        = string
  default     = "172.20.0.0/16"
}

variable "permissions_boundary_arn" {
  description = "ARN of IAM permissions boundary policy. Applied to node group IAM role to limit blast radius."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "CloudWatch log retention for EKS control plane logs. SOC 2 requires minimum 90 days."
  type        = number
  default     = 365
}

variable "node_groups" {
  description = <<-EOT
    Map of managed node group configurations.
    Each key becomes the node group name suffix.
    Example:
    {
      "general" = {
        instance_types = ["m5.xlarge"]
        ami_type       = "AL2_x86_64"
        disk_size      = 50
        desired_size   = 3
        min_size       = 1
        max_size       = 10
        labels         = {}
        taints         = []
      }
    }
  EOT
  type = map(object({
    instance_types = list(string)
    ami_type       = string
    disk_size      = number
    desired_size   = number
    min_size       = number
    max_size       = number
    labels         = map(string)
    taints = list(object({
      key    = string
      value  = string
      effect = string
    }))
  }))
}

variable "addon_versions" {
  description = "Managed EKS add-on versions. Specify explicitly for production to avoid unexpected upgrades."
  type = object({
    coredns    = string
    kube_proxy = string
    vpc_cni    = string
    ebs_csi    = string
  })
  default = {
    coredns    = "v1.11.1-eksbuild.4"
    kube_proxy = "v1.29.0-eksbuild.1"
    vpc_cni    = "v1.16.2-eksbuild.1"
    ebs_csi    = "v1.27.0-eksbuild.1"
  }
}

variable "tags" {
  description = "Resource tags. CostCenter, Owner, Environment, and DataClass are required."
  type        = map(string)
}