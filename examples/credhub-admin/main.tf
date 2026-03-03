# =============================================================================
# Example: CredHub Admin PIM Integration
# =============================================================================
#
# This example demonstrates how to use the azure-pim-uaa-idp module to create
# a just-in-time privileged access setup for CredHub administrators.
#
# Prerequisites:
#   - Azure AD tenant with Entra ID P2 license (for PIM for Groups)
#   - Service principal with required Graph API permissions
#   - UAA deployment with SAML provider support
#
# Usage:
#   1. Copy terraform.tfvars.example to terraform.tfvars
#   2. Fill in the required values
#   3. Run: terraform init && terraform apply
#   4. Use the output to configure UAA
# =============================================================================

# -----------------------------------------------------------------------------
# MODULE INSTANTIATION
# -----------------------------------------------------------------------------

module "credhub_admin_pim" {
  source = "../../modules/azure-pim-uaa-idp"

  # Required: UAA SAML configuration
  uaa_entity_id = var.uaa_entity_id
  uaa_acs_urls  = var.uaa_acs_urls
  uaa_logout_url = var.uaa_logout_url

  # Required: Users who can activate CredHub admin access
  eligible_member_ids = var.eligible_member_ids

  # Optional: Customize group and application names
  group_name       = var.group_name
  group_description = "Just-in-time privileged access group for CredHub administrators. Members must activate via Azure PIM with MFA and peer approval."
  application_name = var.application_name

  # Optional: App roles - add more scopes as needed
  app_roles = var.app_roles

  # Optional: PIM settings
  pim_max_activation_hours  = var.pim_max_activation_hours
  pim_require_mfa           = var.pim_require_mfa
  pim_require_justification = var.pim_require_justification
  pim_require_approval      = var.pim_require_approval
  pim_send_notifications    = var.pim_send_notifications

  # Optional: Certificate and misc settings
  certificate_validity_years = var.certificate_validity_years
  prevent_duplicate_names    = true
  tags                       = var.tags
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

output "saml_metadata_url" {
  description = "SAML metadata URL for UAA configuration"
  value       = module.credhub_admin_pim.saml_metadata_url
}

output "saml_sso_url" {
  description = "SAML SSO URL"
  value       = module.credhub_admin_pim.saml_sso_url
}

output "saml_entity_id" {
  description = "Azure AD SAML Entity ID (issuer)"
  value       = module.credhub_admin_pim.saml_entity_id
}

output "group_object_id" {
  description = "Azure AD group object ID"
  value       = module.credhub_admin_pim.group_object_id
}

output "application_id" {
  description = "Azure AD application (client) ID"
  value       = module.credhub_admin_pim.application_id
}

output "app_roles_to_scopes" {
  description = "Mapping of Azure AD app roles to UAA scopes"
  value       = module.credhub_admin_pim.quick_reference.app_roles_to_map
}

output "pim_activation_url" {
  description = "URL for users to activate their PIM membership"
  value       = module.credhub_admin_pim.quick_reference.pim_activation_url
}

output "uaa_saml_config" {
  description = "Complete UAA SAML provider configuration (YAML)"
  value       = module.credhub_admin_pim.uaa_saml_provider_config
  sensitive   = true
}

# Generate a local file with UAA configuration for convenience
resource "local_file" "uaa_config" {
  count    = var.generate_uaa_config_file ? 1 : 0
  filename = "${path.module}/generated-uaa-saml-config.yml"
  content  = module.credhub_admin_pim.uaa_saml_provider_config
  
  file_permission = "0600"
}

output "uaa_config_file_path" {
  description = "Path to the generated UAA configuration file (if enabled)"
  value       = var.generate_uaa_config_file ? local_file.uaa_config[0].filename : null
}
