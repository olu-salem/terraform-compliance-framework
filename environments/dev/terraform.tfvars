# =============================================================================
# ENVIRONMENT: dev — Variable Values
# 
# NOTE: This file is committed to git — do NOT include secrets.
#       Secrets are injected via CI/CD environment variables or AWS Secrets Manager.
#
# Production tfvars are NOT committed — values are injected by CI/CD pipeline.
#
# Bootstrap remote state (once) — use YOUR account ID locally; do not commit it here.
#   scripts/bootstrap-state.ps1 -AccountId <YOUR_ACCOUNT_ID> -Region us-east-1 -Env dev
# State bucket name pattern: enterprise-tfstate-dev-<YOUR_ACCOUNT_ID>
# After bootstrap, use terraform init with use_lockfile=true (S3 locking; Terraform 1.10+).
# =============================================================================

name        = "enterprise"
environment = "dev"
aws_region  = "us-east-1"

vpc_cidr = "10.10.0.0/16"
availability_zones = [
  "us-east-1a",
  "us-east-1b",
  "us-east-1c"
]

# Org tag policy rejects CostCenter values: skip the tag in dev (not for production).
omit_cost_center_tag = true

owner_email = "platform-team@company.com"
project_name = "PLATFORM"

# Security alerts
security_alert_emails = [
  "platform-oncall@company.com"
]

# Public egress IPs allowed to reach the EKS public API (e.g. office /32). Private CIDRs are invalid here.
# Empty: module uses 0.0.0.0/0 when public_api_endpoint is true (lab only).
dev_vpn_cidrs = []

# Budget — alert at $400 (80%) and forecast $500 (100%)
monthly_budget_usd = "500"