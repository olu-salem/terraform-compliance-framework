# =============================================================================
# ENVIRONMENT: dev
# Description: Development environment module composition.
#              Demonstrates how all modules are wired together.
#              Uses single NAT gateway and smaller instances for cost savings.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Values injected via CI/CD or terraform init -backend-config flags
    # bucket         = "enterprise-tfstate-dev-<account-id>"
    # key            = "dev/terraform.tfstate"
    # region         = "us-east-1"
    # dynamodb_table = "enterprise-tfstate-lock-dev"
    # encrypt        = true
    # kms_key_id     = "arn:aws:kms:..."
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Environment = var.environment
    CostCenter  = var.cost_center
    Owner       = var.owner_email
    DataClass   = "internal"
    ManagedBy   = "terraform"
    Project     = var.project_name
  }
}

# =============================================================================
# SECURITY BASELINE — Deploy first, other modules use its outputs
# =============================================================================

module "security_baseline" {
  source = "../../modules/security-baseline"

  name        = var.name
  environment = var.environment

  security_alert_emails = var.security_alert_emails
  enable_pci_standard   = false # Not needed for dev

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

  single_nat_gateway      = true  # Cost savings for dev
  flow_log_retention_days = 90    # Shorter retention for dev

  kms_key_arn = module.security_baseline.security_kms_key_arn

  tags = local.common_tags
}

# =============================================================================
# EKS CLUSTER
# =============================================================================

module "eks" {
  source = "../../modules/eks"

  name        = var.name
  environment = var.environment

  vpc_id             = module.vpc.vpc_id
  vpc_cidr           = module.vpc.vpc_cidr_block
  private_subnet_ids = module.vpc.private_subnet_ids

  kubernetes_version  = "1.29"
  public_api_endpoint = true  # Dev convenience — false in prod
  api_allowed_cidrs   = var.dev_vpn_cidrs

  log_retention_days = 90

  node_groups = {
    "general" = {
      instance_types = ["t3.medium"]  # Dev sizing
      ami_type       = "AL2_x86_64"
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
    coredns    = "v1.11.1-eksbuild.4"
    kube_proxy = "v1.29.0-eksbuild.1"
    vpc_cni    = "v1.16.2-eksbuild.1"
    ebs_csi    = "v1.27.0-eksbuild.1"
  }

  tags = local.common_tags
}

# =============================================================================
# RDS AURORA
# =============================================================================

module "rds" {
  source = "../../modules/rds"

  name        = var.name
  environment = var.environment

  vpc_id           = module.vpc.vpc_id
  intra_subnet_ids = module.vpc.intra_subnet_ids

  # Allow connections from EKS nodes
  allowed_security_group_ids = [module.eks.cluster_security_group_id]

  engine_version  = "15.4"
  instance_class  = "db.t3.medium"  # Dev sizing
  instance_count  = 1               # Single instance for dev

  backup_retention_days     = 7
  max_connections_threshold = 100
  sns_alert_topic_arns      = [module.security_baseline.security_alerts_topic_arn]

  tags = local.common_tags
}

# =============================================================================
# S3 BUCKETS
# =============================================================================

module "app_assets_bucket" {
  source = "../../modules/s3"

  bucket_name     = "${var.name}-${var.environment}-app-assets-${data.aws_caller_identity.current.account_id}"
  environment     = var.environment
  create_kms_key  = true
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
  enable_object_lock = true  # WORM — immutable audit logs

  object_lock_retention_days = 365
  enable_intelligent_tiering = false

  tags = merge(local.common_tags, {
    Purpose = "access-logs"
  })
}

# =============================================================================
# AWS BUDGET ALERT — Cost governance
# =============================================================================

data "aws_caller_identity" "current" {}

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