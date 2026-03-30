# =============================================================================
# OPA Policy: networking.rego
# Purpose: Enforce network isolation, prevent public exposure,
#          and validate security group rules.
#
# Controls mapped:
#   - CIS 5.2  — No security group allows unrestricted inbound SSH (port 22)
#   - CIS 5.3  — No security group allows unrestricted inbound RDP (port 3389)
#   - CIS 5.4  — Default security group restricts all traffic
#   - PCI 1.2  — No direct public internet access for cardholder data
#   - NIST SC-7 — Boundary protection
# =============================================================================

package enterprise.terraform

# ─── Constants ────────────────────────────────────────────────────────────────

dangerous_ports := {22, 3389, 1521, 3306, 5432, 27017, 6379, 9200, 9300, 2379}

public_cidrs := {"0.0.0.0/0", "::/0"}

# ─── Security Group Rules ─────────────────────────────────────────────────────

# CIS 5.2 — No unrestricted SSH (port 22) ingress
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.actions[_] in {"create", "update"}

  rule := resource.change.after
  rule.type == "ingress"
  rule.from_port <= 22
  rule.to_port >= 22
  rule.cidr_blocks[_] in public_cidrs

  msg := sprintf(
    "NETWORKING-001 (CIS 5.2): Security group rule '%s' allows unrestricted SSH access (0.0.0.0/0:22). Restrict to specific IP ranges or use AWS Systems Manager Session Manager instead.",
    [resource.address]
  )
}

# CIS 5.3 — No unrestricted RDP (port 3389) ingress
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.actions[_] in {"create", "update"}

  rule := resource.change.after
  rule.type == "ingress"
  rule.from_port <= 3389
  rule.to_port >= 3389
  rule.cidr_blocks[_] in public_cidrs

  msg := sprintf(
    "NETWORKING-002 (CIS 5.3): Security group rule '%s' allows unrestricted RDP access (0.0.0.0/0:3389). Restrict to specific IP ranges.",
    [resource.address]
  )
}

# Block unrestricted ingress on any database port
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.actions[_] in {"create", "update"}

  rule := resource.change.after
  rule.type == "ingress"

  dangerous_port := dangerous_ports[_]
  rule.from_port <= dangerous_port
  rule.to_port >= dangerous_port
  rule.cidr_blocks[_] in public_cidrs

  not dangerous_port in {22, 3389}  # Already handled above

  msg := sprintf(
    "NETWORKING-003: Security group rule '%s' allows unrestricted public access on database/service port %d. Restrict to VPC CIDR or specific security groups.",
    [resource.address, dangerous_port]
  )
}

# Block inline security group rules with 0.0.0.0/0 ingress on sensitive ports
deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  resource.change.actions[_] in {"create", "update"}

  ingress := resource.change.after.ingress[_]
  ingress.from_port == 0
  ingress.to_port == 0
  ingress.protocol == "-1"
  ingress.cidr_blocks[_] in public_cidrs

  msg := sprintf(
    "NETWORKING-004: Security group '%s' has an ingress rule allowing all traffic (port 0-0 protocol -1) from the public internet. This is not permitted.",
    [resource.address]
  )
}

# ─── RDS Public Access ────────────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type in {"aws_db_instance", "aws_rds_cluster_instance"}
  resource.change.actions[_] in {"create", "update"}

  publicly_accessible := object.get(resource.change.after, "publicly_accessible", false)
  publicly_accessible

  msg := sprintf(
    "NETWORKING-005 (PCI 1.2): RDS instance '%s' has publicly_accessible = true. Database instances must never be publicly accessible.",
    [resource.address]
  )
}

# ─── EKS Public API Endpoint ──────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_eks_cluster"
  resource.change.actions[_] in {"create", "update"}

  # Get the vpc_config block
  vpc_config := resource.change.after.vpc_config[_]
  endpoint_public_access := object.get(vpc_config, "endpoint_public_access", false)
  endpoint_public_access

  # It's public AND no CIDR restrictions (defaults to 0.0.0.0/0)
  public_cidrs_allowed := object.get(vpc_config, "public_access_cidrs", ["0.0.0.0/0"])
  "0.0.0.0/0" in public_cidrs_allowed

  msg := sprintf(
    "NETWORKING-006 (CIS EKS 4.6.6): EKS cluster '%s' has a public API endpoint accessible from 0.0.0.0/0. Restrict public_access_cidrs to known IP ranges, or set endpoint_public_access = false.",
    [resource.address]
  )
}

# ─── S3 Public Access ─────────────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] in {"create", "update"}

  config := resource.change.after
  not config.block_public_acls

  msg := sprintf(
    "NETWORKING-007 (CIS 2.1.5): S3 bucket public access block '%s' does not have block_public_acls = true.",
    [resource.address]
  )
}

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.actions[_] in {"create", "update"}

  config := resource.change.after
  not config.restrict_public_buckets

  msg := sprintf(
    "NETWORKING-008 (CIS 2.1.5): S3 bucket public access block '%s' does not have restrict_public_buckets = true.",
    [resource.address]
  )
}

# ─── Subnet Configuration ─────────────────────────────────────────────────────

deny[msg] if {
  resource := input.resource_changes[_]
  resource.type == "aws_subnet"
  resource.change.actions[_] in {"create", "update"}

  map_public := object.get(resource.change.after, "map_public_ip_on_launch", false)
  map_public

  msg := sprintf(
    "NETWORKING-009 (CIS 5.4): Subnet '%s' has map_public_ip_on_launch = true. Instances should not auto-assign public IPs. Use explicit Elastic IPs only where required.",
    [resource.address]
  )
}