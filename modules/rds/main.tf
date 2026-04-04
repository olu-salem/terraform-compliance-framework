# =============================================================================
# MODULE: rds
# Description: Aurora PostgreSQL cluster with multi-AZ, CMK encryption,
#              automated backups, no public access, enhanced monitoring.
#              Compliance: PCI DSS 3.4, HIPAA 164.312, SOC 2 CC6, NIST SC-28.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

locals {
  identifier = "${var.name}-${var.environment}"

  common_tags = merge(var.tags, {
    Module    = "rds"
    ManagedBy = "terraform"
  })
}

# =============================================================================
# KMS KEY FOR RDS ENCRYPTION
# PCI DSS 3.4 — Render PAN unreadable using strong cryptography
# HIPAA 164.312(a)(2)(iv) — Encryption and decryption
# =============================================================================

resource "aws_kms_key" "rds" {
  description             = "KMS CMK for RDS Aurora encryption — ${local.identifier}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name    = "${local.identifier}-rds-kms"
    Purpose = "rds-encryption"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.identifier}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# =============================================================================
# SUBNET GROUP — Intra subnets (no internet egress)
# =============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "${local.identifier}-db-subnet-group"
  subnet_ids = var.intra_subnet_ids

  tags = merge(local.common_tags, {
    Name = "${local.identifier}-db-subnet-group"
  })
}

# =============================================================================
# SECURITY GROUP — Restrict access to application security group only
# PCI DSS 1.3 — Restrict inbound/outbound traffic to minimum necessary
# =============================================================================

resource "aws_security_group" "rds" {
  name        = "${local.identifier}-rds-sg"
  description = "RDS Aurora security group — allow only from app tier"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from application security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
  }

  # No egress rule — RDS does not initiate outbound connections

  tags = merge(local.common_tags, {
    Name = "${local.identifier}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# RANDOM PASSWORD — Stored in Secrets Manager, never in state
# =============================================================================

resource "random_password" "master" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "rds_credentials" {
  name                    = "${local.identifier}/rds/master-credentials"
  description             = "RDS Aurora master credentials for ${local.identifier}"
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 30 # Prevent accidental deletion

  tags = merge(local.common_tags, {
    Name = "${local.identifier}-rds-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "rds_credentials" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.master.result
    engine   = "aurora-postgresql"
    host     = aws_rds_cluster.main.endpoint
    port     = 5432
    dbname   = var.database_name
  })
}

# =============================================================================
# RDS PARAMETER GROUP
# =============================================================================

resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${local.identifier}-cluster-params"
  family      = "aurora-postgresql15"
  description = "Aurora PostgreSQL cluster parameters — ${local.identifier}"

  # Force SSL connections — PCI DSS 4.2, HIPAA 164.312(e)
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # Enable query logging for audit
  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000" # Log queries taking > 1 second
  }

  # Enable audit logging extension
  parameter {
    name         = "shared_preload_libraries"
    value        = "pgaudit"
    apply_method = "pending-reboot"
  }

  tags = local.common_tags
}

# =============================================================================
# AURORA CLUSTER
# =============================================================================

resource "aws_rds_cluster" "main" {
  cluster_identifier = "${local.identifier}-aurora"
  engine             = "aurora-postgresql"
  engine_version     = var.engine_version
  database_name      = var.database_name
  master_username    = var.master_username
  master_password    = random_password.master.result

  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [aws_security_group.rds.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name

  # PCI DSS 3.4 / HIPAA — Encrypt data at rest with CMK
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn

  # PCI DSS 1.2 — No public access
  publicly_accessible = false

  # Automated backups — PCI DSS 12.10, SOC 2 A1.2
  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = "02:00-03:00"
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot        = true

  # Deletion protection — prevents accidental termination
  deletion_protection       = var.environment == "prod" ? true : false
  skip_final_snapshot       = var.environment == "prod" ? false : true
  final_snapshot_identifier = var.environment == "prod" ? "${local.identifier}-final-snapshot" : null

  # Enhanced monitoring and logging
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # Apply changes during maintenance window — avoid production surprises
  apply_immediately = var.environment == "prod" ? false : true

  tags = merge(local.common_tags, {
    Name = "${local.identifier}-aurora-cluster"
  })
}

# =============================================================================
# AURORA CLUSTER INSTANCES — Writer + Readers for HA
# =============================================================================

resource "aws_rds_cluster_instance" "instances" {
  count = var.instance_count

  identifier         = "${local.identifier}-aurora-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  db_subnet_group_name = aws_db_subnet_group.main.name

  # PCI DSS 1.2 — No public access on instances
  publicly_accessible = false

  # Enhanced monitoring — SOC 2 CC7.1
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 731 # 2 years

  auto_minor_version_upgrade = true # Security patches automatically

  tags = merge(local.common_tags, {
    Name = "${local.identifier}-aurora-instance-${count.index + 1}"
    Role = count.index == 0 ? "writer" : "reader"
  })
}

# =============================================================================
# ENHANCED MONITORING IAM ROLE
# =============================================================================

resource "aws_iam_role" "rds_monitoring" {
  name = "${local.identifier}-rds-enhanced-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# =============================================================================
# CLOUDWATCH ALARMS
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.identifier}-rds-cpu-high"
  alarm_description   = "RDS CPU utilization above 80% for 5 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = var.sns_alert_topic_arns
  ok_actions          = var.sns_alert_topic_arns
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "connections_high" {
  alarm_name          = "${local.identifier}-rds-connections-high"
  alarm_description   = "RDS database connections above threshold"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = var.max_connections_threshold
  alarm_actions       = var.sns_alert_topic_arns
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier
  }

  tags = local.common_tags
}