# Compliance Control Matrix

Detailed mapping of each Terraform module to specific compliance framework controls.
This document is maintained alongside module code changes and reviewed during audits.

---

## CIS AWS Foundations Benchmark v1.5

| CIS Control | Description | Implementation | Module |
|---|---|---|---|
| 1.1 | Maintain current contact details | AWS Account config | N/A |
| 1.4 | Ensure no root access keys exist | IAM module | `modules/iam` |
| 1.5 | Ensure MFA for root account | IAM module | `modules/iam` |
| 1.14 | Ensure hardware MFA for root | IAM policy | `modules/iam` |
| 2.1.1 | S3 encryption (SSE) | `aws_s3_bucket_server_side_encryption_configuration` | `modules/s3` |
| 2.1.2 | S3 no AWS managed keys (use CMK) | KMS key in S3 module | `modules/s3` |
| 2.1.5 | S3 public access block | `aws_s3_bucket_public_access_block` | `modules/s3` |
| 2.2.1 | EBS volume encryption | Default encryption + OPA policy | `policies/opa/encryption.rego` |
| 2.6 | S3 access logging | `aws_s3_bucket_logging` | `modules/s3` |
| 2.7 | CloudTrail encryption (KMS) | `aws_cloudtrail.kms_key_id` | `modules/security-baseline` |
| 2.8 | KMS key rotation | `enable_key_rotation = true` | All KMS resources |
| 2.9 | VPC flow logs | `aws_flow_log` | `modules/vpc` |
| 3.1 | Unauthorized API call alarm | CloudWatch metric filter | `modules/security-baseline` |
| 3.3 | Root account usage alarm | CloudWatch metric filter | `modules/security-baseline` |
| 3.4 | IAM policy change alarm | CloudWatch metric filter | `modules/security-baseline` |
| 4.1 | No unrestricted SSH (port 22) | OPA policy + SG rules | `policies/opa/networking.rego` |
| 4.2 | No unrestricted RDP (port 3389) | OPA policy + SG rules | `policies/opa/networking.rego` |
| 5.1 | No default VPC | VPC module + manual check | `modules/vpc` |
| 5.4 | Default SG restricts all traffic | `aws_default_security_group` | `modules/vpc` |

---

## NIST 800-53 Rev 5

| Control Family | Control | Description | Module/Policy |
|---|---|---|---|
| AC | AC-2 | Account Management | `modules/iam` |
| AC | AC-3 | Access Enforcement | IAM policies, SGs | `modules/iam` |
| AC | AC-4 | Information Flow | VPC subnets, NACLs | `modules/vpc` |
| AC | AC-6 | Least Privilege | Permission boundaries | `modules/iam`, `modules/eks` |
| AC | AC-17 | Remote Access | VPN CIDRs, SSM | `modules/eks` |
| AU | AU-2 | Event Logging | CloudTrail all events | `modules/security-baseline` |
| AU | AU-6 | Audit Review | Security Hub, SIEM | `modules/security-baseline` |
| AU | AU-9 | Protection of Audit Info | S3 versioning, object lock | `modules/s3` |
| AU | AU-11 | Audit Record Retention | 365-day default retention | All log groups |
| SC | SC-7 | Boundary Protection | VPC, NACLs, SGs | `modules/vpc` |
| SC | SC-8 | Transmission Confidentiality | TLS enforcement | S3 policy, RDS SSL |
| SC | SC-12 | Cryptographic Key Management | KMS CMKs, rotation | All modules |
| SC | SC-28 | Protection at Rest | KMS encryption | All data modules |
| SI | SI-2 | Flaw Remediation | Patch manager, AMI pipeline | `modules/eks` |
| SI | SI-4 | System Monitoring | GuardDuty, Security Hub | `modules/security-baseline` |
| SI | SI-7 | Software Integrity | CloudTrail, log validation | `modules/security-baseline` |

---

## PCI DSS v3.2.1

| Requirement | Description | Implementation |
|---|---|---|
| 1.1 | Network security controls | VPC, SGs, NACLs | `modules/vpc` |
| 1.2 | No public internet for CDE | `publicly_accessible = false`, intra subnets | `modules/rds`, `modules/vpc` |
| 1.3 | Restrict inbound/outbound CDE traffic | OPA networking policy | `policies/opa/networking.rego` |
| 2.2 | System configuration standards | CIS-hardened AMIs, Terraform baselines | All modules |
| 3.4 | Render PAN unreadable (encryption) | RDS KMS encryption | `modules/rds` |
| 3.5 | Protect cryptographic keys | KMS key policies, rotation | All KMS resources |
| 4.2 | No unprotected PAN over open networks | SSL enforcement on S3, RDS | `modules/s3`, `modules/rds` |
| 7.1 | Limit access to system components | IAM least privilege | `modules/iam` |
| 10.1 | Implement audit trails | CloudTrail all-region | `modules/security-baseline` |
| 10.5 | Secure audit trails | S3 versioning, object lock | `modules/s3` |
| 10.7 | Retain audit trail 1 year | 365-day log retention | All modules |
| 11.5 | Deploy change-detection mechanisms | CloudTrail, drift detection | `modules/security-baseline`, `scripts/drift-detection.sh` |

---

## SOC 2 Type II

| Trust Service Criteria | Description | Implementation |
|---|---|---|
| CC6.1 | Logical and physical access controls | IAM, VPC, SGs | `modules/iam`, `modules/vpc` |
| CC6.2 | Authentication, authorization | IRSA, RBAC, MFA | `modules/eks`, `modules/iam` |
| CC6.3 | Remove access for terminated users | IAM automation | `modules/iam` |
| CC6.6 | Logical access security measures | KMS, encryption | All modules |
| CC6.7 | Restrict transmission of data | TLS, VPC isolation | `modules/vpc`, `modules/s3` |
| CC7.1 | System monitoring | GuardDuty, Security Hub | `modules/security-baseline` |
| CC7.2 | Log monitoring | CloudWatch, alerts | `modules/security-baseline` |
| CC7.3 | Security event evaluation | SIEM integration | `modules/security-baseline` |
| CC8.1 | Change management controls | Terraform, CI/CD gates | `.github/workflows/` |
| A1.1 | Capacity management | Auto-scaling, budgets | `modules/eks`, environments |
| A1.2 | Recovery time objectives | Multi-AZ, backups | `modules/rds`, `modules/vpc` |

---

*Last updated: See git history*  
*Review cadence: Quarterly or after major module changes*