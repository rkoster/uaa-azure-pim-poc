# =============================================================================
# Example Variables
# =============================================================================

# -----------------------------------------------------------------------------
# REQUIRED VARIABLES
# -----------------------------------------------------------------------------

variable "uaa_entity_id" {
  description = "UAA SAML entity ID (audience)"
  type        = string
}

variable "uaa_acs_urls" {
  description = "UAA Assertion Consumer Service URLs"
  type        = list(string)
}

variable "eligible_member_ids" {
  description = "List of Azure AD user object IDs to make eligible for PIM activation"
  type        = list(string)
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - Azure AD Configuration
# -----------------------------------------------------------------------------

variable "group_name" {
  description = "Name of the Azure AD security group"
  type        = string
  default     = "AAD-CredHub-Admins"
}

variable "application_name" {
  description = "Name of the Azure AD SAML application"
  type        = string
  default     = "UAA-CredHub-SAML"
}

variable "uaa_logout_url" {
  description = "UAA single logout URL"
  type        = string
  default     = null
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - App Roles
# -----------------------------------------------------------------------------

variable "app_roles" {
  description = "App roles to create (map to UAA scopes)"
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
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - PIM Configuration
# -----------------------------------------------------------------------------

variable "pim_max_activation_hours" {
  description = "Maximum activation duration in hours"
  type        = number
  default     = 4
}

variable "pim_require_mfa" {
  description = "Require MFA on activation"
  type        = bool
  default     = true
}

variable "pim_require_justification" {
  description = "Require justification on activation"
  type        = bool
  default     = true
}

variable "pim_require_approval" {
  description = "Require peer approval (4-eyes)"
  type        = bool
  default     = true
}

variable "pim_send_notifications" {
  description = "Send email notifications to group members"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# OPTIONAL VARIABLES - Misc
# -----------------------------------------------------------------------------

variable "certificate_validity_years" {
  description = "SAML certificate validity in years"
  type        = number
  default     = 2
}

variable "tags" {
  description = "Tags for Azure resources"
  type        = map(string)
  default     = {}
}

variable "generate_uaa_config_file" {
  description = "Generate a local file with UAA configuration"
  type        = bool
  default     = true
}
