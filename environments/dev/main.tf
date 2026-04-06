# =============================================================================
# ENVIRONMENT: dev
# Description: Development environment module composition.
#              Demonstrates how all modules are wired together.
#              Uses single NAT gateway and smaller instances for cost savings.
# =============================================================================

terraform {
  # S3 native state locking (use_lockfile) requires Terraform 1.10+.
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Values injected via CI/CD or terraform init -backend-config flags
    # bucket        = "enterprise-tfstate-dev-<account-id>"
    # key           = "dev/terraform.tfstate"
    # region        = "us-east-1"
    # use_lockfile  = true   # S3-native locks (replaces deprecated dynamodb_table)
    # encrypt       = true
    # kms_key_id    = "arn:aws:kms:..."
  }
}

provider "aws" {
  region = var.aws_region
  # default_tags omitted: they would create a cycle with local.common_tags (CostCenter uses
  # data.aws_caller_identity). All modules and the budget below set tags explicitly.
}

# Used for CostCenter fallback and S3 bucket naming (must exist before locals).
data "aws_caller_identity" "current" {}

locals {
  cost_center_tag = trimspace(var.cost_center) != "" ? var.cost_center : data.aws_caller_identity.current.account_id

  # Base tags always applied. CostCenter is optional when Organization tag policies reject every value.
  tags_base = {
    Environment = var.environment
    Owner       = var.owner_email
    DataClass   = "internal"
    ManagedBy   = "terraform"
    Project     = var.project_name
  }

  common_tags = var.omit_cost_center_tag ? local.tags_base : merge(local.tags_base, {
    CostCenter = local.cost_center_tag
  })
}

# =============================================================================
# SECURITY BASELINE — Deploy first, other modules use its outputs
# =============================================================================

module "security_baseline" {
  source = "../../modules/security-baseline"

  name        = var.name
  environment = var.environment

  security_alert_emails         = var.security_alert_emails
  enable_pci_standard           = false # Not needed for dev
  cloudtrail_s3_force_destroy = true  # Allow terraform destroy to empty versioned CloudTrail logs

  tags = local.common_tags
}

# =============================================================================
# VPC NETWORKING
# =============================================================================

module "vpc" {
  source = "../../modules/vpc"

  name               = var.name
  environment        = var.environment
  aws_region         = var.aws_region
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones

  single_nat_gateway      = true # Cost savings for dev
  flow_log_retention_days = 90   # Shorter retention for dev

  kms_key_arn = module.security_baseline.security_kms_key_arn

  require_cost_center_tag = !var.omit_cost_center_tag
  tags                    = local.common_tags
}

# =============================================================================
# EKS CLUSTER
# =============================================================================
# AWS allows only one Kubernetes minor version upgrade per UpdateClusterVersion
# (e.g. 1.29 -> 1.30 -> ...). After each apply finishes and the cluster is Active,
# bump kubernetes_version one minor and refresh addon_versions with:
#   aws eks describe-addon-versions --kubernetes-version <ver> --region <region> --addon-name <name>

module "eks" {
  source = "../../modules/eks"

  name        = var.name
  environment = var.environment

  vpc_id             = module.vpc.vpc_id
  vpc_cidr           = module.vpc.vpc_cidr_block
  private_subnet_ids = module.vpc.private_subnet_ids

  # One minor bump per apply (currently 1.30 in AWS -> 1.31).
  kubernetes_version  = "1.31"
  public_api_endpoint = true # Dev convenience — false in prod
  api_allowed_cidrs   = var.dev_vpn_cidrs

  log_retention_days = 90

  node_groups = {
    "general" = {
      instance_types = ["t3.medium"] # Dev sizing
      ami_type       = "AL2023_x86_64_STANDARD"
      disk_size      = 50
      desired_size   = 2
      min_size       = 1
      max_size       = 5
      labels = {
        "node-type" = "general"
      }
      taints = []
    }
  }

  addon_versions = {
    coredns    = "v1.11.4-eksbuild.33"
    kube_proxy = "v1.31.14-eksbuild.9"
    vpc_cni    = "v1.21.1-eksbuild.7"
    ebs_csi    = "v1.57.1-eksbuild.1"
  }

  # Dev: disable prefix delegation only; keep IRSA (clearing IRSA on UpdateAddon can fail with PassRole / cross-account errors).
  vpc_cni_use_prefix_delegation = false
  vpc_cni_use_irsa              = true

  # Skip managed CoreDNS in dev when it never reaches ACTIVE (DEGRADED timeouts). Re-enable after fixing the cluster or add CoreDNS manually.
  enable_coredns_addon = false

  # Used only when enable_coredns_addon = true
  coredns_addon_configuration_values = jsonencode({
    replicaCount = 1
    podDisruptionBudget = {
      enabled = false
    }
  })

  tags = local.common_tags
}

# =============================================================================
# RDS AURORA
# =============================================================================
# If apply fails with ResourceExistsException on the master secret, adopt it once:
#   terraform import 'module.rds.aws_secretsmanager_secret.rds_credentials' 'enterprise-dev/rds/master-credentials'
# If DecryptionFailure on the RDS secret KMS key: pending deletion -> cancel-key-deletion;
# disabled -> enable-key (same key id as in the error), then re-apply.
#   aws kms cancel-key-deletion --key-id <key-id> --region us-east-1
#   aws kms enable-key --key-id <key-id> --region us-east-1

module "rds" {
  source = "../../modules/rds"

  name        = var.name
  environment = var.environment

  vpc_id           = module.vpc.vpc_id
  intra_subnet_ids = module.vpc.intra_subnet_ids

  # Allow connections from EKS nodes
  allowed_security_group_ids = [module.eks.cluster_security_group_id]

  engine_version = "15.17"
  instance_class = "db.t3.medium" # Dev sizing
  instance_count = 1              # Single instance for dev

  backup_retention_days     = 7
  max_connections_threshold = 100
  sns_alert_topic_arns      = [module.security_baseline.security_alerts_topic_arn]

  # Lab: immediate secret delete avoids "name already scheduled for deletion" on quick destroy/recreate.
  master_secret_recovery_window_days = 0

  tags = local.common_tags
}

# =============================================================================
# S3 BUCKETS
# =============================================================================

module "app_assets_bucket" {
  source = "../../modules/s3"

  bucket_name       = "${var.name}-${var.environment}-app-assets-${data.aws_caller_identity.current.account_id}"
  environment       = var.environment
  create_kms_key    = true
  access_log_bucket = module.s3_access_logs_bucket.bucket_name

  enable_intelligent_tiering = true

  tags = merge(local.common_tags, {
    Purpose = "app-assets"
  })
}

module "s3_access_logs_bucket" {
  source = "../../modules/s3"

  bucket_name        = "${var.name}-${var.environment}-access-logs-${data.aws_caller_identity.current.account_id}"
  environment        = var.environment
  create_kms_key     = true
  enable_object_lock = true # WORM — immutable audit logs

  object_lock_retention_days = 365
  enable_intelligent_tiering = false

  tags = merge(local.common_tags, {
    Purpose = "access-logs"
  })
}

# =============================================================================
# AWS BUDGET ALERT — Cost governance
# =============================================================================

resource "aws_budgets_budget" "dev_monthly" {
  name         = "${var.name}-${var.environment}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.security_alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.security_alert_emails
  }
}