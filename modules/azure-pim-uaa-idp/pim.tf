# -----------------------------------------------------------------------------
# PIM FOR GROUPS - ELIGIBLE MEMBERSHIP ASSIGNMENTS
# -----------------------------------------------------------------------------
#
# This file creates PIM eligibility assignments for users, making them
# ELIGIBLE (not active) members of the privileged access group.
#
# Users must activate their membership via PIM portal to gain actual access.
#
# API Reference: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-for-groups-api-overview
# -----------------------------------------------------------------------------

# Get current timestamp for schedule start
resource "time_static" "eligibility_start" {}

# Create eligibility schedule requests for each user
# This makes users eligible to activate group membership, but not active members
resource "azapi_resource" "pim_eligibility" {
  for_each = toset(var.eligible_member_ids)

  type = "Microsoft.Graph/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests@v1.0"
  name = "eligibility-${each.key}"

  # Parent is the root since this is a top-level Graph API resource
  parent_id = "/"

  body = jsonencode({
    accessId      = "member"              # "member" or "owner"
    principalId   = each.key              # User object ID
    groupId       = azuread_group.privileged_access.object_id
    action        = "adminAssign"         # Admin is assigning eligibility
    justification = "Eligibility managed by Terraform for just-in-time privileged access"

    scheduleInfo = {
      startDateTime = time_static.eligibility_start.rfc3339
      expiration = var.pim_eligibility_permanent ? {
        type = "noExpiration"
      } : {
        type     = "afterDuration"
        duration = "P${var.pim_eligibility_duration_days}D"  # ISO 8601 duration
      }
    }
  })

  # Ignore changes to scheduleInfo since startDateTime would change
  lifecycle {
    ignore_changes = [body]
  }

  depends_on = [
    azuread_group.privileged_access,
    azapi_resource.pim_policy_assignment_rules
  ]

  response_export_values = ["*"]
}
