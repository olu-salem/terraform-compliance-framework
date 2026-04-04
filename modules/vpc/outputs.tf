# =============================================================================
# MODULE: vpc — Outputs
# =============================================================================

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (for load balancers and NAT gateways only)"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs (for EKS nodes, application workloads)"
  value       = aws_subnet.private[*].id
}

output "intra_subnet_ids" {
  description = "List of intra subnet IDs (for RDS, ElastiCache — no internet egress)"
  value       = aws_subnet.intra[*].id
}

output "nat_gateway_ids" {
  description = "List of NAT gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "nat_public_ips" {
  description = "Public IP addresses of NAT gateways — add to allowlists for outbound traffic"
  value       = aws_eip.nat[*].public_ip
}

output "flow_log_group_name" {
  description = "CloudWatch log group name for VPC flow logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "flow_log_id" {
  description = "ID of the VPC flow log"
  value       = aws_flow_log.main.id
}

output "private_route_table_ids" {
  description = "List of private route table IDs — use for VPC endpoint associations"
  value       = aws_route_table.private[*].id
}

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}