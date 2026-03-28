# Enterprise Terraform IaC Compliance Framework

[![Terraform](https://img.shields.io/badge/Terraform-1.6+-purple?logo=terraform)](https://www.terraform.io/)
[![tfsec](https://img.shields.io/badge/tfsec-passing-green)](https://github.com/aquasecurity/tfsec)
[![checkov](https://img.shields.io/badge/checkov-passing-green)](https://www.checkov.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/effieksa/terraform-compliance-framework/actions/workflows/terraform-ci.yml/badge.svg)](https://github.com/effieksa/terraform-compliance-framework/actions)

A production grade, modular Terraform framework for enterprises that enforces security compliance, cost governance, and operational best practices as code. Built with **SOC 2**, **PCI-DSS**, **HIPAA**, and **NIST 800-53** control mappings baked directly into the infrastructure modules.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Module Catalog](#module-catalog)
- [Compliance Coverage](#compliance-coverage)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Environment Deployments](#environment-deployments)
- [CI/CD Pipeline](#cicd-pipeline)
- [Security Scanning](#security-scanning)
- [Testing](#testing)
- [Cost Governance](#cost-governance)
- [Runbook](#runbook)
- [Contributing](#contributing)

---

## Overview

This framework addresses a critical enterprise challenge: teams provision AWS infrastructure inconsistently, creating security gaps, compliance violations, and cost overruns. By providing **pre approved, compliance validated Terraform modules**, this platform allows developers to self serve infrastructure while guaranteeing security guardrails are enforced automatically not manually reviewed.

**Key outcomes this framework delivers:**
- Reduce infrastructure provisioning from weeks to hours
- Eliminate 90%+ of configuration drift incidents
- Pass SOC 2 / PCI-DSS audits without manual evidence collection
- Block non compliant deployments before they reach production
- Enforce cost tagging and budget guardrails across all accounts

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENTERPRISE AWS ORGANIZATION                       │
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │  Management │    │   Security  │    │      Shared Services    │ │
│  │   Account   │    │   Account   │    │        Account          │ │
│  │             │    │ GuardDuty   │    │  Terraform State (S3)   │ │
│  │ AWS Control │    │ Security Hub│    │  DynamoDB Lock Table    │ │
│  │   Tower     │    │ CloudTrail  │    │  ECR / Artifact Repo    │ │
│  └─────────────┘    └─────────────┘    └─────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    WORKLOAD ACCOUNTS                        │   │
│  │                                                             │   │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │   │
│  │   │     DEV      │  │   STAGING    │  │     PROD     │    │   │
│  │   │              │  │              │  │              │    │   │
│  │   │  VPC Module  │  │  VPC Module  │  │  VPC Module  │    │   │
│  │   │  EKS Module  │  │  EKS Module  │  │  EKS Module  │    │   │
│  │   │  RDS Module  │  │  RDS Module  │  │  RDS Module  │    │   │
│  │   │  IAM Module  │  │  IAM Module  │  │  IAM Module  │    │   │
│  │   │  S3  Module  │  │  S3  Module  │  │  S3  Module  │    │   │
│  │   └──────────────┘  └──────────────┘  └──────────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE & GUARDRAIL LAYERS                    │
│                                                                     │
│  GitHub Actions CI/CD                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │terraform │  │  tfsec   │  │ checkov  │  │   Terratest Go   │  │
│  │fmt+valid │→ │ security │→ │ policy   │→ │  infra tests     │  │
│  │          │  │  scan    │  │  scan    │  │                  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘  │
│                                                                     │
│  OPA Policy Engine                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌─────────────────────┐   │
│  │  Tagging      │  │  Encryption   │  │  Network Isolation  │   │
│  │  Enforcement  │  │  Requirement  │  │  Guardrails         │   │
│  └───────────────┘  └───────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Security & Compliance
- **Encryption at rest and in transit** enforced on all storage and database modules
- **Least privilege IAM** with permission boundaries and automated policy generation
- **VPC flow logs** enabled by default with centralized log aggregation
- **AWS Security Hub**, **GuardDuty**, and **CloudTrail** deployed via security baseline module
- **KMS customer-managed keys (CMK)** for EKS secrets, RDS, and S3 encryption

### Compliance Guardrails
- **OPA/Rego policies** enforce mandatory resource tagging before any apply
- **tfsec** and **checkov** integrated in CI/CD to block non compliant PRs
- **CIS AWS Benchmark** controls mapped to each module variable
- **Drift detection** via automated Terraform plan runs with PagerDuty alerting

### Operational Excellence
- **Modular design** each module is independently versioned and tested
- **Remote state** with S3 backend, DynamoDB locking, and cross account state sharing
- **Multi environment** dev/staging/prod with environment specific variable overrides
- **Terratest** Go tests validate module behavior before merging

### Cost Governance
- Mandatory `CostCenter` and `Owner` tags enforced by OPA policy
- AWS Budget alerts provisioned alongside workload infrastructure
- Right sized instance recommendations built into module variable defaults

---

## Module Catalog

| Module | Description | Compliance Controls |
|---|---|---|
| `modules/vpc` | Multi AZ VPC with public/private/intra subnets, NAT gateway, VPC flow logs | CIS 3.9, NIST AC-4, PCI 1.3 |
| `modules/eks` | EKS cluster with managed node groups, IRSA, secrets encryption, audit logs | CIS 5.1, NIST SI-2, SOC2 CC6 |
| `modules/rds` | Aurora PostgreSQL multi AZ, automated backups, CMK encryption, no public access | PCI 3.4, HIPAA 164.312, SOC2 CC6 |
| `modules/iam` | IAM roles with permission boundaries, least privilege policies, MFA enforcement | NIST AC-2, CIS 1.x, SOC2 CC6 |
| `modules/s3` | S3 buckets with versioning, encryption, public access block, access logging | CIS 2.1, PCI 3.4, NIST SC-28 |
| `modules/security-baseline` | GuardDuty, Security Hub, CloudTrail, Config rules, SNS alerting | CIS 2.x/3.x, NIST AU-2, SOC2 CC7 |

---

## Compliance Coverage

| Framework | Controls Covered | Module Mapping |
|---|---|---|
| **CIS AWS Benchmark v1.5** | 1.x IAM, 2.x Storage, 3.x Logging, 4.x Monitoring, 5.x Networking | All modules |
| **NIST 800-53 Rev5** | AC (Access Control), AU (Audit), SC (System Comms), SI (Integrity) | IAM, Security-Baseline, VPC |
| **PCI-DSS v3.2.1** | Req 1 (Network), 2 (Config), 3 (Data Protection), 7 (Access), 10 (Logging) | RDS, S3, VPC, IAM |
| **SOC 2 Type II** | CC6 (Logical Access), CC7 (Change Mgmt), CC8 (Risk Mgmt) | All modules |
| **HIPAA** | 164.312 (Technical Safeguards), 164.308 (Admin Safeguards) | RDS, S3, EKS |

---

## Prerequisites

```bash
# Required tooling
terraform >= 1.6.0
aws-cli >= 2.0
go >= 1.21        # for Terratest
tfsec >= 1.28     # security scanning
checkov >= 3.0    # policy scanning
opa >= 0.58       # policy evaluation

# Install security scanning tools
brew install tfsec checkov
brew install open-policy-agent/opa/opa

# Configure AWS credentials
aws configure --profile enterprise-dev
aws configure --profile enterprise-prod
```

---

## Quick Start

### 1. Bootstrap Remote State

Before deploying any environments, provision the remote state backend in your shared services account:

```bash
cd scripts/
chmod +x bootstrap-state.sh
./bootstrap-state.sh --account-id 123456789012 --region us-east-1 --env dev
```

This creates:
- S3 bucket with versioning, encryption, and access logging
- DynamoDB table for state locking
- KMS key for state file encryption
- IAM roles for cross-account state access

### 2. Deploy an Environment

```bash
cd environments/dev

# Initialize with remote backend
terraform init \
  -backend-config="bucket=enterprise-tfstate-dev-123456789012" \
  -backend-config="key=dev/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=enterprise-tfstate-lock-dev"

# Review the plan
terraform plan -var-file="terraform.tfvars" -out=tfplan

# Apply (CI/CD only in production)
terraform apply tfplan
```

### 3. Use a Module Directly

```hcl
module "vpc" {
  source = "github.com/effieksa/terraform-compliance-framework//modules/vpc?ref=v1.2.0"

  name               = "my-app"
  environment        = "prod"
  aws_region         = "us-east-1"
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

  # Compliance tags — enforced by OPA policy, cannot be omitted
  tags = {
    Environment = "prod"
    CostCenter  = "engineering-platform"
    Owner       = "platform-team@company.com"
    DataClass   = "internal"
    Compliance  = "pci-dss"
  }
}
```

---

## Environment Deployments

```
environments/
├── dev/
│   ├── main.tf          # Module composition for dev
│   ├── variables.tf     # Input variable declarations
│   ├── outputs.tf       # Output values
│   ├── terraform.tfvars # Dev-specific values (committed)
│   └── backend.tf       # Remote state config
├── staging/
│   └── ...              # Same structure, staging values
└── prod/
    └── ...              # Same structure, production values
                         # (tfvars NOT committed — injected by CI/CD)
```

Each environment inherits the same module versions but overrides:
- Instance sizes / node counts
- Multi-AZ / redundancy settings
- Backup retention periods
- Monitoring alert thresholds

---

## CI/CD Pipeline

The GitHub Actions pipeline enforces a **compliance gate** on every pull request. No infrastructure change reaches production without passing all stages.

```
PR Opened
    │
    ▼
┌─────────────────┐
│  terraform fmt  │ ── Fails PR if formatting is inconsistent
│  terraform init │
│  terraform      │
│  validate       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     tfsec       │ ── Fails PR on HIGH/CRITICAL security issues
│  security scan  │    (CIS benchmarks, encryption, public access)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    checkov      │ ── Fails PR on policy violations
│  policy scan    │    (tagging, backup, logging requirements)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  OPA policies   │ ── Evaluates terraform plan JSON against
│  evaluation     │    Rego rules for custom enterprise policies
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  terraform plan │ ── Posts plan diff as PR comment
│  (PR comment)   │    Requires human approval for prod
└────────┬────────┘
         │ (merge to main)
         ▼
┌─────────────────┐
│  terraform      │ ── Auto-applies to dev/staging
│  apply          │    Manual approval gate for prod
└─────────────────┘
```

---

## Security Scanning

### tfsec — CIS Benchmark Checks

```bash
# Run locally before committing
tfsec modules/ --minimum-severity HIGH

# Run against a specific module
tfsec modules/rds/ --format json | jq '.results[] | {rule_id, description, severity}'
```

### checkov — Policy Compliance Checks

```bash
# Full scan with compliance framework output
checkov -d . --framework terraform --check CKV_AWS_* \
  --output-file-path reports/ --output json

# Check against specific compliance frameworks
checkov -d . --compliance PCI_DSS SOC2 HIPAA
```

### OPA Policy Evaluation

```bash
# Validate terraform plan against enterprise OPA policies
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

opa eval \
  --input tfplan.json \
  --data policies/opa/tagging.rego \
  --data policies/opa/encryption.rego \
  --data policies/opa/networking.rego \
  "data.enterprise.terraform.deny"
```

---

## Testing

Infrastructure tests are written in Go using [Terratest](https://terratest.gruntwork.io/). They deploy real infrastructure, validate behavior, and destroy it.

```bash
cd tests/

# Run VPC module tests
go test -v -run TestVPCModule -timeout 30m

# Run EKS module tests (longer — spins up real cluster)
go test -v -run TestEKSModule -timeout 60m

# Run all tests
go test -v ./... -timeout 90m
```

**What the tests validate:**
- VPC CIDRs and subnet counts are correct
- Private subnets have no direct internet route
- RDS is not publicly accessible
- S3 buckets block public access
- EKS cluster encryption is enabled
- Security groups don't allow `0.0.0.0/0` ingress on sensitive ports

---

## Cost Governance

Every module provisions an **AWS Budget alert** alongside the resource:

```hcl
# Automatically provisioned by each environment root module
resource "aws_budgets_budget" "environment" {
  name         = "${var.environment}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator = "GREATER_THAN"
    threshold           = 80
    threshold_type      = "PERCENTAGE"
    notification_type   = "ACTUAL"
    subscriber_email_addresses = [var.cost_alert_email]
  }
}
```

Mandatory cost allocation tags enforced by OPA:
- `CostCenter` — maps to finance department code
- `Owner` — team email for chargeback
- `Environment` — dev / staging / prod
- `Project` — JIRA project key

---

## Runbook

### Recovering from State Lock

```bash
# If a pipeline fails mid-apply, the DynamoDB lock may persist
# View current lock
aws dynamodb get-item \
  --table-name enterprise-tfstate-lock-dev \
  --key '{"LockID": {"S": "dev/terraform.tfstate"}}'

# Force unlock (use with caution — confirm no apply is running)
terraform force-unlock <LOCK_ID>
```

### Investigating Drift

```bash
# Run drift detection manually
terraform plan -detailed-exitcode -var-file="terraform.tfvars"
# Exit code 0 = no changes, 1 = error, 2 = drift detected

# Script-driven drift check (used by CI scheduled job)
./scripts/drift-detection.sh --env prod --alert-on-drift true
```

### Rolling Back a Bad Apply

```bash
# List state history (S3 versioning enabled)
aws s3api list-object-versions \
  --bucket enterprise-tfstate-prod-123456789012 \
  --prefix prod/terraform.tfstate

# Restore previous state version
aws s3api get-object \
  --bucket enterprise-tfstate-prod-123456789012 \
  --key prod/terraform.tfstate \
  --version-id <VERSION_ID> \
  terraform.tfstate.backup

# Apply previous state
terraform apply -target=<affected_resource>
```

---

## Project Structure

```
terraform-compliance-framework/
├── README.md
├── .github/
│   └── workflows/
│       ├── terraform-ci.yml        # PR validation pipeline
│       └── terraform-cd.yml        # Apply pipeline
├── modules/
│   ├── vpc/                        # VPC networking module
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── README.md
│   ├── eks/                        # EKS cluster module
│   ├── rds/                        # RDS Aurora module
│   ├── iam/                        # IAM roles & policies module
│   ├── s3/                         # S3 bucket module
│   └── security-baseline/          # GuardDuty/SecurityHub/CloudTrail
├── environments/
│   ├── dev/
│   ├── staging/
│   └── prod/
├── policies/
│   ├── opa/                        # OPA/Rego policy files
│   │   ├── tagging.rego
│   │   ├── encryption.rego
│   │   └── networking.rego
│   └── checkov/                    # Custom checkov policies
│       └── custom_checks.py
├── tests/
│   ├── vpc_test.go
│   ├── eks_test.go
│   ├── rds_test.go
│   └── helpers_test.go
├── scripts/
│   ├── bootstrap-state.sh
│   └── drift-detection.sh
└── docs/
    ├── compliance-matrix.md
    └── onboarding-guide.md
```

---

## Contributing

1. Fork and create a feature branch: `git checkout -b feat/add-elasticache-module`
2. Run local compliance checks: `make lint security test`
3. Ensure all Terratest tests pass
4. Submit PR — the CI pipeline must be green before review
5. One senior engineer approval required for module changes
6. Direct commits to `main` are blocked

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## License

MIT — see [LICENSE](LICENSE)