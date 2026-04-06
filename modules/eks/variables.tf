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
  description = "Kubernetes version for the EKS cluster. Pin to a version returned by aws eks describe-cluster-versions in your region."
  type        = string
  default     = "1.35"
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
  description = <<-EOT
    Public routable CIDRs allowed to reach the EKS public API endpoint. Only used if public_api_endpoint = true.
    AWS rejects private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use office/VPN egress /32s.
    If empty while public access is on, defaults to 0.0.0.0/0 inside the module (dev/lab only; tighten for prod).
  EOT
  type    = list(string)
  default = []

  validation {
    condition = alltrue([
      for c in var.api_allowed_cidrs :
      !can(regex("^10\\.", split("/", c)[0]))
      && !can(regex("^172\\.(1[6-9]|2[0-9]|3[0-1])\\.", split("/", c)[0]))
      && !can(regex("^192\\.168\\.", split("/", c)[0]))
    ])
    error_message = "api_allowed_cidrs must be publicly routable; private RFC1918 CIDRs are rejected by EKS for public_access_cidrs."
  }
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
        ami_type       = "AL2023_x86_64_STANDARD"
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

variable "vpc_cni_use_prefix_delegation" {
  description = "When true, enable prefix delegation on the VPC CNI add-on. Disable for small dev clusters if CoreDNS stays DEGRADED."
  type        = bool
  default     = true
}

variable "vpc_cni_use_irsa" {
  description = "When true, attach the IRSA role to the VPC CNI add-on. When false, CNI uses the node instance role (AmazonEKS_CNI_Policy on nodes)."
  type        = bool
  default     = true
}

variable "coredns_addon_configuration_values" {
  description = <<-EOT
    Optional CoreDNS add-on configuration_values JSON string (aws eks describe-addon-configuration --addon-name coredns).
    Use null for AWS defaults. Small clusters often need replicaCount 1 and podDisruptionBudget.enabled false to leave DEGRADED.
  EOT
  type        = string
  default     = null
}

variable "enable_coredns_addon" {
  description = <<-EOT
    When false, do not manage the CoreDNS EKS add-on (avoids long apply timeouts if AWS reports DEGRADED forever).
    In-cluster DNS will not work until you add CoreDNS (console, eksctl, or set this back to true after fixing the cluster).
  EOT
  type        = bool
  default     = true
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
    coredns    = "v1.13.2-eksbuild.4"
    kube_proxy = "v1.35.3-eksbuild.2"
    vpc_cni    = "v1.21.1-eksbuild.7"
    ebs_csi    = "v1.57.1-eksbuild.1"
  }
}

variable "tags" {
  description = "Resource tags. CostCenter, Owner, Environment, and DataClass are required."
  type        = map(string)
}