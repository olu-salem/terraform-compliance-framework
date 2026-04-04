# =============================================================================
# MODULE: vpc
# Description: Production-grade VPC with multi-AZ subnets, NAT gateways,
#              VPC flow logs, and network ACLs. Compliance-first design
#              enforcing CIS AWS Benchmark 3.9, NIST AC-4, PCI DSS 1.3.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  # Derive subnet counts from AZ list
  az_count = length(var.availability_zones)

  # CIDR calculations — public subnets get /24, private get /22 (more IPs for workloads)
  public_subnet_cidrs  = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 1)]
  intra_subnet_cidrs   = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 100)]

  # Unified resource tags merged with required compliance tags
  common_tags = merge(var.tags, {
    Module      = "vpc"
    ManagedBy   = "terraform"
    LastUpdated = timestamp()
  })
}

# =============================================================================
# VPC
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  # CIS 3.9 — Ensure VPC flow logging is enabled in all VPCs (done below)
  # NIST SC-7 — Boundary protection through subnet isolation

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-vpc"
  })
}

# =============================================================================
# INTERNET GATEWAY
# =============================================================================

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-igw"
  })
}

# =============================================================================
# PUBLIC SUBNETS
# Purpose: Load balancers and NAT gateways only — no application workloads
# =============================================================================

resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false # CIS 5.4 — No auto-assign public IPs

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-public-${var.availability_zones[count.index]}"
    Tier = "public"
    # EKS external load balancer discovery tag
    "kubernetes.io/role/elb" = "1"
  })
}

# =============================================================================
# PRIVATE SUBNETS
# Purpose: All application workloads, EKS nodes, RDS instances
# =============================================================================

resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-private-${var.availability_zones[count.index]}"
    Tier = "private"
    # EKS internal load balancer discovery tag
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# =============================================================================
# INTRA SUBNETS (no NAT gateway route)
# Purpose: Isolated resources — RDS, ElastiCache — that need no internet egress
# PCI DSS 1.3 — Prohibit direct inbound/outbound internet access for the CDE
# =============================================================================

resource "aws_subnet" "intra" {
  count = local.az_count

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.intra_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-intra-${var.availability_zones[count.index]}"
    Tier = "intra"
  })
}

# =============================================================================
# ELASTIC IPs & NAT GATEWAYS
# One NAT per AZ for HA. Single-NAT mode available for dev cost savings.
# =============================================================================

resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : local.az_count
  domain = "vpc"

  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-nat-eip-${count.index + 1}"
  })
}

resource "aws_nat_gateway" "main" {
  count = var.single_nat_gateway ? 1 : local.az_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-nat-${count.index + 1}"
  })
}

# =============================================================================
# ROUTE TABLES
# =============================================================================

# Public route table — routes to IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route tables — one per AZ, routes through NAT gateway
resource "aws_route_table" "private" {
  count  = local.az_count
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.main[0].id : aws_nat_gateway.main[count.index].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-private-rt-${var.availability_zones[count.index]}"
  })
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Intra route table — no default route (fully isolated)
resource "aws_route_table" "intra" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-intra-rt"
  })
}

resource "aws_route_table_association" "intra" {
  count          = local.az_count
  subnet_id      = aws_subnet.intra[count.index].id
  route_table_id = aws_route_table.intra.id
}

# =============================================================================
# VPC FLOW LOGS
# CIS 3.9 — Ensure VPC flow logging is enabled in all VPCs
# NIST AU-2 — Event logging
# =============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.name}-${var.environment}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name}-${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.name}-${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL" # Capture ACCEPT, REJECT, and ALL traffic
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-flow-log"
  })
}

# =============================================================================
# NETWORK ACLs
# Default NACL is too permissive — replace with explicit allow rules
# =============================================================================

resource "aws_default_network_acl" "default" {
  default_network_acl_id = aws_vpc.main.default_network_acl_id

  # Explicit deny all — subnets use custom NACLs below
  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-default-nacl-deny-all"
  })
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 65535
  }

  # Allow return traffic from NAT gateway (ephemeral ports)
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-private-nacl"
  })
}

# =============================================================================
# DEFAULT SECURITY GROUP — Deny all traffic
# CIS 5.4 — Ensure the default security group of every VPC restricts all traffic
# =============================================================================

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # No ingress or egress rules — all traffic denied

  tags = merge(local.common_tags, {
    Name = "${var.name}-${var.environment}-default-sg-deny-all"
  })
}