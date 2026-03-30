# =============================================================================
# OPA Policy: tagging.rego
# Purpose: Enforce mandatory resource tagging across all Terraform resources.
# 
# Usage:
#   terraform show -json tfplan.binary > tfplan.json
#   opa eval --input tfplan.json --data tagging.rego "data.enterprise.terraform.deny"
#
# Required tags (all resources):
#   - Environment : dev | staging | prod
#   - CostCenter  : Finance department code
#   - Owner       : Team email address
#   - DataClass   : public | internal | confidential | restricted
# =============================================================================

package enterprise.terraform

import future.keywords.in
import future.keywords.if

# ─── Constants ────────────────────────────────────────────────────────────────

required_tags := {
  "Environment",
  "CostCenter",
  "Owner",
  "DataClass"
}

valid_environments := {"dev", "staging", "prod"}

valid_data_classifications := {"public", "internal", "confidential", "restricted"}

# Resource types exempt from tagging (AWS-managed, no tag support)
exempt_resource_types := {
  "aws_iam_role_policy_attachment",
  "aws_iam_role_policy",
  "aws_route_table_association",
  "aws_subnet_route_table_association",
  "aws_main_route_table_association"
}

# ─── Helper Rules ─────────────────────────────────────────────────────────────

# Get all resources being created or updated
planned_resources[resource] if {
  resource := input.resource_changes[_]
  resource.change.actions[_] in {"create", "update"}
  not resource.type in exempt_resource_types
}

# Get tags from a resource's planned values
get_tags(resource) := tags if {
  tags := resource.change.after.tags
} else := {}

# ─── Deny Rules ───────────────────────────────────────────────────────────────

deny[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  required_tag := required_tags[_]
  not tags[required_tag]

  msg := sprintf(
    "TAGGING-001: Resource '%s' (%s) is missing required tag '%s'. All resources must have: %s",
    [resource.address, resource.type, required_tag, concat(", ", required_tags)]
  )
}

deny[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  env := tags["Environment"]
  not env in valid_environments

  msg := sprintf(
    "TAGGING-002: Resource '%s' has invalid Environment tag '%s'. Must be one of: %s",
    [resource.address, env, concat(", ", valid_environments)]
  )
}

deny[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  data_class := tags["DataClass"]
  not data_class in valid_data_classifications

  msg := sprintf(
    "TAGGING-003: Resource '%s' has invalid DataClass tag '%s'. Must be one of: %s",
    [resource.address, data_class, concat(", ", valid_data_classifications)]
  )
}

deny[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  owner := tags["Owner"]
  not regex.match(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, owner)

  msg := sprintf(
    "TAGGING-004: Resource '%s' has invalid Owner tag '%s'. Must be a valid email address (e.g., platform-team@company.com)",
    [resource.address, owner]
  )
}

deny[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  cost_center := tags["CostCenter"]
  count(cost_center) == 0

  msg := sprintf(
    "TAGGING-005: Resource '%s' has empty CostCenter tag. Must contain a valid finance department code.",
    [resource.address]
  )
}

# ─── Warn Rules (non-blocking, advisory) ──────────────────────────────────────

warn[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  not tags["Compliance"]

  msg := sprintf(
    "TAGGING-WARN-001: Resource '%s' does not have a 'Compliance' tag. Consider adding the applicable framework (e.g., pci-dss, hipaa, soc2).",
    [resource.address]
  )
}

warn[msg] if {
  resource := planned_resources[_]
  tags := get_tags(resource)

  not tags["Project"]

  msg := sprintf(
    "TAGGING-WARN-002: Resource '%s' does not have a 'Project' tag. Adding a JIRA project key aids cost attribution.",
    [resource.address]
  )
}