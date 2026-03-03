# -----------------------------------------------------------------------------
# PIM FOR GROUPS - POLICY CONFIGURATION
# -----------------------------------------------------------------------------
#
# This file configures the PIM policy settings for the privileged access group:
# - MFA required on activation
# - Justification required on activation  
# - Peer approval required (4-eyes principle)
# - Maximum activation duration
# - Email notifications to group members
#
# PIM policies are automatically created when a group is first used with PIM.
# We need to:
# 1. Get the existing policy assignment for the group
# 2. Update the policy rules
#
# API Reference: https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicy
# -----------------------------------------------------------------------------

locals {
  # Build the enabled rules list based on configuration
  pim_enabled_rules = compact([
    var.pim_require_mfa ? "MultiFactorAuthentication" : "",
    var.pim_require_justification ? "Justification" : "",
    var.pim_require_approval ? "Approval" : "",
  ])

  # ISO 8601 duration for max activation
  pim_max_duration = "PT${var.pim_max_activation_hours}H"
}

# -----------------------------------------------------------------------------
# Get the PIM policy assignment for the group
# -----------------------------------------------------------------------------

# First, we need to discover the policy assignment ID for this group
# The policy is automatically created when we first interact with PIM for the group
data "azapi_resource_list" "pim_policy_assignments" {
  type      = "Microsoft.Graph/policies/roleManagementPolicyAssignments@v1.0"
  parent_id = "/"

  # Filter to only get assignments for our group (member scope)
  query_parameters = {
    "$filter" = "scopeId eq '${azuread_group.privileged_access.object_id}' and scopeType eq 'Group' and roleDefinitionId eq 'member'"
  }

  response_export_values = ["*"]

  depends_on = [azuread_group.privileged_access]
}

# Also get the policy for owner scope (if we want to manage ownership eligibility)
data "azapi_resource_list" "pim_policy_assignments_owner" {
  type      = "Microsoft.Graph/policies/roleManagementPolicyAssignments@v1.0"
  parent_id = "/"

  query_parameters = {
    "$filter" = "scopeId eq '${azuread_group.privileged_access.object_id}' and scopeType eq 'Group' and roleDefinitionId eq 'owner'"
  }

  response_export_values = ["*"]

  depends_on = [azuread_group.privileged_access]
}

# -----------------------------------------------------------------------------
# Extract policy IDs from the list response
# -----------------------------------------------------------------------------

locals {
  # Parse the policy assignment list to get the policy ID
  # The response format is: { "value": [ { "id": "...", "policyId": "...", ... } ] }
  policy_assignments_member = try(
    jsondecode(data.azapi_resource_list.pim_policy_assignments.output).value,
    []
  )

  policy_id_member = length(local.policy_assignments_member) > 0 ? local.policy_assignments_member[0].policyId : null

  policy_assignments_owner = try(
    jsondecode(data.azapi_resource_list.pim_policy_assignments_owner.output).value,
    []
  )

  policy_id_owner = length(local.policy_assignments_owner) > 0 ? local.policy_assignments_owner[0].policyId : null
}

# -----------------------------------------------------------------------------
# Get current policy rules (to identify rule IDs)
# -----------------------------------------------------------------------------

data "azapi_resource" "pim_policy_member" {
  count = local.policy_id_member != null ? 1 : 0

  type      = "Microsoft.Graph/policies/roleManagementPolicies@v1.0"
  name      = local.policy_id_member
  parent_id = "/"

  query_parameters = {
    "$expand" = "rules"
  }

  response_export_values = ["*"]
}

# -----------------------------------------------------------------------------
# Parse rule IDs from the policy
# -----------------------------------------------------------------------------

locals {
  # Parse the policy rules to find the specific rule IDs we need to update
  policy_rules_member = local.policy_id_member != null ? try(
    jsondecode(data.azapi_resource.pim_policy_member[0].output).rules,
    []
  ) : []

  # Find rule IDs by rule type
  # Rule types we care about:
  # - Enablement_EndUser_Assignment: Controls MFA, justification, ticketing
  # - Approval_EndUser_Assignment: Controls approval requirements
  # - Expiration_EndUser_Assignment: Controls activation duration
  # - Notification_Requestor_EndUser_Assignment: Notification to requestor
  # - Notification_Approver_EndUser_Assignment: Notification to approvers
  # - Notification_Admin_EndUser_Assignment: Notification to admins

  rule_id_enablement = try(
    [for r in local.policy_rules_member : r.id if r["@odata.type"] == "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule" && can(regex("EndUser_Assignment", r.id))][0],
    null
  )

  rule_id_approval = try(
    [for r in local.policy_rules_member : r.id if r["@odata.type"] == "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"][0],
    null
  )

  rule_id_expiration = try(
    [for r in local.policy_rules_member : r.id if r["@odata.type"] == "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule" && can(regex("EndUser_Assignment", r.id))][0],
    null
  )

  rule_id_notification_requestor = try(
    [for r in local.policy_rules_member : r.id if r["@odata.type"] == "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule" && can(regex("Notification_Requestor_EndUser_Assignment", r.id))][0],
    null
  )

  rule_id_notification_approver = try(
    [for r in local.policy_rules_member : r.id if r["@odata.type"] == "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule" && can(regex("Notification_Approver_EndUser_Assignment", r.id))][0],
    null
  )
}

# -----------------------------------------------------------------------------
# Update PIM policy rules
# -----------------------------------------------------------------------------

# Update the policy rules using PATCH
# We update multiple rules in a single request
resource "azapi_update_resource" "pim_policy_assignment_rules" {
  count = local.policy_id_member != null ? 1 : 0

  type        = "Microsoft.Graph/policies/roleManagementPolicies@v1.0"
  resource_id = local.policy_id_member

  body = jsonencode({
    rules = concat(
      # Enablement rule - controls MFA and justification
      local.rule_id_enablement != null ? [{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
        id            = local.rule_id_enablement
        enabledRules  = local.pim_enabled_rules
        target = {
          caller       = "EndUser"
          operations   = ["All"]
          level        = "Assignment"
          inheritableSettings = []
          enforcedSettings    = []
        }
      }] : [],

      # Approval rule - controls peer approval (4-eyes)
      local.rule_id_approval != null && var.pim_require_approval ? [{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
        id            = local.rule_id_approval
        setting = {
          isApprovalRequired               = true
          isApprovalRequiredForExtension   = false
          isRequestorJustificationRequired = var.pim_require_justification
          approvalMode                     = "SingleStage"
          approvalStages = [{
            approvalStageTimeOutInDays      = 1
            isApproverJustificationRequired = true
            isEscalationEnabled             = false
            escalationTimeInMinutes         = 0
            # Approve by any other member of the same group (4-eyes principle)
            primaryApprovers = [{
              "@odata.type" = "#microsoft.graph.groupMembers"
              groupId       = azuread_group.privileged_access.object_id
              description   = "Group members (peer approval)"
              isBackup      = false
            }]
            escalationApprovers = []
          }]
        }
        target = {
          caller       = "EndUser"
          operations   = ["All"]
          level        = "Assignment"
          inheritableSettings = []
          enforcedSettings    = []
        }
      }] : [],

      # Expiration rule - controls max activation duration
      local.rule_id_expiration != null ? [{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        id            = local.rule_id_expiration
        isExpirationRequired = true
        maximumDuration      = local.pim_max_duration
        target = {
          caller       = "EndUser"
          operations   = ["All"]
          level        = "Assignment"
          inheritableSettings = []
          enforcedSettings    = []
        }
      }] : [],

      # Notification rules - notify all group members
      local.rule_id_notification_approver != null && var.pim_send_notifications ? [{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
        id            = local.rule_id_notification_approver
        notificationType           = "Email"
        recipientType              = "Approver"
        isDefaultRecipientsEnabled = true
        notificationLevel          = "All"
        notificationRecipients     = []  # Empty means use default (group members)
        target = {
          caller       = "EndUser"
          operations   = ["All"]
          level        = "Assignment"
          inheritableSettings = []
          enforcedSettings    = []
        }
      }] : []
    )
  })

  depends_on = [
    data.azapi_resource.pim_policy_member
  ]
}
