# Adopt AWS objects that still exist after a partial destroy (empty or drifted state).
# Run: .\scripts\adopt-dev-orphan-imports.ps1  (from repo root)
# Requires: terraform init in environments/dev, AWS credentials.
$ErrorActionPreference = "Stop"
$DevDir = Join-Path $PSScriptRoot "..\environments\dev" | Resolve-Path
Set-Location $DevDir

if (-not $env:AWS_DEFAULT_REGION -and -not $env:AWS_REGION) {
    $env:AWS_DEFAULT_REGION = "us-east-1"
}

Write-Host "Importing orphaned resources (assumes enterprise / dev naming)."
Write-Host "If RDS secret import fails, run:"
Write-Host "  aws secretsmanager restore-secret --secret-id enterprise-dev/rds/master-credentials --region $($env:AWS_DEFAULT_REGION)"
Write-Host ""

terraform import 'module.eks.aws_eks_node_group.main["general"]' 'enterprise-dev-eks:enterprise-dev-eks-general'
terraform import 'module.eks.aws_cloudwatch_log_group.eks_cluster' '/aws/eks/enterprise-dev-eks/cluster'
terraform import 'module.vpc.aws_cloudwatch_log_group.flow_logs' '/aws/vpc/enterprise-dev/flow-logs'
terraform import 'module.rds.aws_secretsmanager_secret.rds_credentials' 'enterprise-dev/rds/master-credentials'

Write-Host ""
Write-Host "Done. Run terraform plan, then terraform apply."
