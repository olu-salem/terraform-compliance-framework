# =============================================================================
# ENVIRONMENT: dev — Variable Values
# 
# NOTE: This file is committed to git — do NOT include secrets.
#       Secrets are injected via CI/CD environment variables or AWS Secrets Manager.
#
# Production tfvars are NOT committed — values are injected by CI/CD pipeline.
# =============================================================================

name       = "enterprise"
environment = "dev"
aws_region = "us-east-1"

vpc_cidr = "10.10.0.0/16"
availability_zones = [
  "us-east-1a",
  "us-east-1b",
  "us-east-1c"
]

# Cost governance — required by OPA tagging policy
cost_center  = "engineering-platform"
owner_email  = "platform-team@company.com"
project_name = "PLATFORM"

# Security alerts
security_alert_emails = [
  "platform-oncall@company.com"
]

# Allow VPN/office IPs to reach EKS API (dev only)
dev_vpn_cidrs = [
  "10.0.0.0/8"  # Internal network — replace with actual VPN/office CIDRs
]

# Budget — alert at $400 (80%) and forecast $500 (100%)
monthly_budget_usd = "500"