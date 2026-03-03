# -----------------------------------------------------------------------------
# REQUIRED VARIABLES
# -----------------------------------------------------------------------------

variable "uaa_entity_id" {
  description = "UAA SAML entity ID (audience). This is typically the UAA's SAML metadata URL, e.g., https://uaa.sys.example.com/saml/metadata"
  type        = string

  validation {
    condition     = can(regex("^https?://", var.uaa_entity_id))
    error_message = "uaa_entity_id must be a valid URL starting with http:// or https://"
  }
}

variable "uaa_acs_urls" {
  description = "UAA Assertion Consumer Service URLs. These are the endpoints where Azure AD will POST SAML responses, e.g., https://uaa.sys.example.com/saml/SSO/alias/uaa.sys.example.com"
  type        = list(string)

  validation {
    condition     = length(var.uaa_acs_urls) > 0
    error_message = "At least one ACS URL must be provided"
  }

  validation {
    condition     = alltrue([for url in var.uaa_acs_urls : can(regex("^https://", url))])
    error_message = "All ACS URLs must use HTTPS"
  }
}

variable "eligible_member_ids" {
  description = "List of Azure AD user object IDs to make eligible for group membership via PIM. These users will be able to activate their membership when needed."
  type        = list(string)

  validation {
    condition     = length(var.eligible_member_ids) >= 2
    error_message = "At least 2 eligible members are required for 4-eyes approval (one to request, one to approve)"
  }

  validation {
    condition     = alltrue([for id in var.eligible_member_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "All member IDs must be valid UUIDs (Azure AD object IDs)"
  }
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - Azure AD Group Configuration
# -----------------------------------------------------------------------------

variable "group_name" {
  description = "Name of the Azure AD security group for privileged access"
  type        = string
  default     = "AAD-CredHub-Admins"

  validation {
    condition     = length(var.group_name) >= 3 && length(var.group_name) <= 256
    error_message = "Group name must be between 3 and 256 characters"
  }
}

variable "group_description" {
  description = "Description of the Azure AD security group"
  type        = string
  default     = "Privileged access group for CredHub administrators. Membership is managed via PIM with just-in-time activation, MFA, and peer approval."
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - Azure AD Application Configuration
# -----------------------------------------------------------------------------

variable "application_name" {
  description = "Display name of the Azure AD SAML application for UAA federation"
  type        = string
  default     = "UAA-CredHub-SAML"

  validation {
    condition     = length(var.application_name) >= 3 && length(var.application_name) <= 256
    error_message = "Application name must be between 3 and 256 characters"
  }
}

variable "uaa_logout_url" {
  description = "UAA single logout URL (optional). If provided, Azure AD will redirect here after logout."
  type        = string
  default     = null
}

variable "app_roles" {
  description = "List of app roles to create in the Azure AD application. Each role maps to a UAA scope via external group mapping."
  type = list(object({
    value        = string
    display_name = string
    description  = string
  }))
  default = [
    {
      value        = "credhub-admin"
      display_name = "CredHub Administrator"
      description  = "Full administrative access to CredHub secrets management"
    }
  ]

  validation {
    condition     = length(var.app_roles) > 0
    error_message = "At least one app role must be defined"
  }

  validation {
    condition     = alltrue([for role in var.app_roles : can(regex("^[a-z0-9-]+$", role.value))])
    error_message = "App role values must contain only lowercase letters, numbers, and hyphens"
  }
}

variable "certificate_validity_years" {
  description = "Validity period in years for the SAML signing certificate"
  type        = number
  default     = 2

  validation {
    condition     = var.certificate_validity_years >= 1 && var.certificate_validity_years <= 10
    error_message = "Certificate validity must be between 1 and 10 years"
  }
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - PIM Configuration
# -----------------------------------------------------------------------------

variable "pim_max_activation_hours" {
  description = "Maximum duration in hours for PIM activation. After this period, group membership is automatically revoked."
  type        = number
  default     = 4

  validation {
    condition     = var.pim_max_activation_hours >= 1 && var.pim_max_activation_hours <= 24
    error_message = "Maximum activation hours must be between 1 and 24"
  }
}

variable "pim_require_mfa" {
  description = "Whether to require multi-factor authentication when activating PIM membership"
  type        = bool
  default     = true
}

variable "pim_require_justification" {
  description = "Whether to require a justification message when activating PIM membership"
  type        = bool
  default     = true
}

variable "pim_require_approval" {
  description = "Whether to require peer approval (4-eyes principle) when activating PIM membership. Approvers are other eligible members of the same group."
  type        = bool
  default     = true
}

variable "pim_eligibility_permanent" {
  description = "Whether PIM eligibility is permanent or time-bound. If false, use pim_eligibility_duration_days."
  type        = bool
  default     = true
}

variable "pim_eligibility_duration_days" {
  description = "Duration in days for PIM eligibility if not permanent. Only used when pim_eligibility_permanent is false."
  type        = number
  default     = 365

  validation {
    condition     = var.pim_eligibility_duration_days >= 1 && var.pim_eligibility_duration_days <= 3650
    error_message = "Eligibility duration must be between 1 and 3650 days (10 years)"
  }
}

variable "pim_send_notifications" {
  description = "Whether to send email notifications to all eligible group members on activation requests and approvals"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - Miscellaneous
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Tags to apply to Azure resources (where supported)"
  type        = map(string)
  default     = {}
}

variable "prevent_duplicate_names" {
  description = "Whether to check for existing resources with the same name before creating. Recommended for production."
  type        = bool
  default     = true
}
