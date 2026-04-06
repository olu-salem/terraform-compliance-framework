# =============================================================================
# MODULE: s3 — Outputs
# =============================================================================

output "bucket_name" {
  description = "Name (id) of the S3 bucket. Uses var.bucket_name so dependents (e.g. access logging) can plan without unknown values."
  value       = var.bucket_name
}

output "bucket_arn" {
  description = "ARN of the S3 bucket."
  value       = aws_s3_bucket.main.arn
}
