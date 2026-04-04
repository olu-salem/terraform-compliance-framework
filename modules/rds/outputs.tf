# =============================================================================
# MODULE: rds — Outputs
# =============================================================================

output "cluster_id" {
  description = "RDS Aurora cluster ID"
  value       = aws_rds_cluster.main.id
}

output "cluster_endpoint" {
  description = "Writer endpoint for the Aurora cluster"
  value       = aws_rds_cluster.main.endpoint
  sensitive   = true
}

output "cluster_reader_endpoint" {
  description = "Read-only endpoint for Aurora read replicas"
  value       = aws_rds_cluster.main.reader_endpoint
  sensitive   = true
}

output "cluster_port" {
  description = "Database port (5432 for PostgreSQL)"
  value       = aws_rds_cluster.main.port
}

output "database_name" {
  description = "Name of the initial database"
  value       = aws_rds_cluster.main.database_name
}

output "credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials"
  value       = aws_secretsmanager_secret.rds_credentials.arn
}

output "security_group_id" {
  description = "Security group ID for the RDS cluster — add to allowed_security_group_ids for app connectivity"
  value       = aws_security_group.rds.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for RDS encryption"
  value       = aws_kms_key.rds.arn
}