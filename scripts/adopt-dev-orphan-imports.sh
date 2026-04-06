#!/usr/bin/env bash
# Adopt AWS objects that still exist after a partial destroy (empty or drifted state).
# Run from repo root or any cwd — uses paths relative to this script.
# Requires: terraform init in environments/dev, AWS credentials, correct region.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV_DIR="${SCRIPT_DIR}/../environments/dev"
cd "$DEV_DIR"

# Git Bash (MSYS) rewrites arguments that look like Unix paths, e.g. /aws/eks/... ->
# C:/Program Files/Git/aws/eks/... which breaks CloudWatch log group import IDs.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
export AWS_DEFAULT_REGION="$REGION"

echo "Importing orphaned resources (names assume name=enterprise, environment=dev in tfvars)."
echo "If import fails for the RDS secret, restore it first:"
echo "  aws secretsmanager restore-secret --secret-id enterprise-dev/rds/master-credentials --region $REGION"
echo "If a previous Git Bash run imported the EKS log group with a C:/Program Files/Git/... id, fix state then re-run:"
echo "  terraform state rm 'module.eks.aws_cloudwatch_log_group.eks_cluster'"
echo ""

terraform import 'module.eks.aws_eks_node_group.main["general"]' 'enterprise-dev-eks:enterprise-dev-eks-general'
terraform import 'module.eks.aws_cloudwatch_log_group.eks_cluster' '/aws/eks/enterprise-dev-eks/cluster'
terraform import 'module.vpc.aws_cloudwatch_log_group.flow_logs' '/aws/vpc/enterprise-dev/flow-logs'
terraform import 'module.rds.aws_secretsmanager_secret.rds_credentials' 'enterprise-dev/rds/master-credentials'

echo ""
echo "Done. Run: terraform plan  then  terraform apply"
