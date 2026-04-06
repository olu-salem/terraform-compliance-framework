# =============================================================================
# ENVIRONMENT: dev — Outputs
# =============================================================================

output "vpc_id" {
  description = "ID of the VPC."
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs for workloads."
  value       = module.vpc.private_subnet_ids
}

output "eks_cluster_name" {
  description = "EKS cluster name for kubectl / aws eks update-kubeconfig."
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS API server endpoint."
  value       = module.eks.cluster_endpoint
}

output "rds_cluster_endpoint" {
  description = "Aurora writer endpoint."
  value       = module.rds.cluster_endpoint
  sensitive   = true
}

output "app_assets_bucket_name" {
  description = "Application assets S3 bucket."
  value       = module.app_assets_bucket.bucket_name
}

output "security_alerts_topic_arn" {
  description = "SNS topic for security and CIS alarms."
  value       = module.security_baseline.security_alerts_topic_arn
}

output "cloudtrail_arn" {
  description = "CloudTrail trail ARN."
  value       = module.security_baseline.cloudtrail_arn
}
