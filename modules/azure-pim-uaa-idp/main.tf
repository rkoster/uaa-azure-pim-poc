# -----------------------------------------------------------------------------
# DATA SOURCES
# -----------------------------------------------------------------------------

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

# -----------------------------------------------------------------------------
# LOCALS
# -----------------------------------------------------------------------------

locals {
  tenant_id = data.azuread_client_config.current.tenant_id

  # SAML endpoints for Azure AD
  saml_metadata_url = "https://login.microsoftonline.com/${local.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${azuread_application.uaa_saml.client_id}"
  saml_entity_id    = "https://sts.windows.net/${local.tenant_id}/"
  saml_sso_url      = "https://login.microsoftonline.com/${local.tenant_id}/saml2"
  saml_logout_url   = "https://login.microsoftonline.com/${local.tenant_id}/saml2"

  # Build app roles map for easy lookup
  app_role_ids = { for role in azuread_application.uaa_saml.app_role : role.value => role.id }
}

# -----------------------------------------------------------------------------
# AZURE AD SECURITY GROUP
# -----------------------------------------------------------------------------

# Create the security group for privileged access
# This group will have no permanent members - all membership is via PIM
resource "azuread_group" "privileged_access" {
  display_name = var.group_name
  description  = var.group_description

  # Security group (not Microsoft 365 group)
  security_enabled = true
  mail_enabled     = false

  # REQUIRED for PIM for Groups - makes the group "role-assignable"
  assignable_to_role = true

  # Private visibility - membership not visible to non-members
  visibility = "Private"

  # The service principal running Terraform needs to be an owner
  owners = [data.azuread_client_config.current.object_id]

  # No permanent members - all membership managed via PIM
  members = []

  # Prevent accidental creation of duplicate groups
  prevent_duplicate_names = var.prevent_duplicate_names

  lifecycle {
    # Ignore changes to members since PIM manages them
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# AZURE AD SAML APPLICATION
# -----------------------------------------------------------------------------

# Generate UUIDs for each app role
resource "random_uuid" "app_role_ids" {
  for_each = { for role in var.app_roles : role.value => role }
}

# Create the Azure AD application for SAML federation with UAA
resource "azuread_application" "uaa_saml" {
  display_name = var.application_name

  # Single tenant only
  sign_in_audience = "AzureADMyOrg"

  # Unique identifier for the application
  identifier_uris = ["api://${replace(lower(var.application_name), " ", "-")}"]

  # Include application group assignments in tokens
  # This ensures the 'roles' claim contains the app roles the user is assigned to
  group_membership_claims = ["ApplicationGroup"]

  # Configure as enterprise application
  feature_tags {
    enterprise            = true
    custom_single_sign_on = true
    gallery               = false
    hide                  = false
  }

  # Create app roles - these map to UAA scopes
  dynamic "app_role" {
    for_each = var.app_roles
    content {
      id                   = random_uuid.app_role_ids[app_role.value.value].result
      allowed_member_types = ["User", "Application"]
      description          = app_role.value.description
      display_name         = app_role.value.display_name
      enabled              = true
      value                = app_role.value.value
    }
  }

  # Configure optional claims for SAML tokens
  optional_claims {
    # Include roles in SAML assertions
    saml2_token {
      name      = "groups"
      essential = false
    }
  }

  # Web app configuration (for SAML)
  web {
    # Redirect URIs are the ACS URLs
    redirect_uris = var.uaa_acs_urls

    # Logout URL
    logout_url = var.uaa_logout_url

    # SAML apps don't use implicit grant
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  # Require Microsoft Graph permissions for basic profile
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
      type = "Scope"
    }
  }

  # Prevent accidental creation of duplicate applications
  prevent_duplicate_names = var.prevent_duplicate_names

  # Owner
  owners = [data.azuread_client_config.current.object_id]

  lifecycle {
    # App role IDs should not change once created
    ignore_changes = [app_role]
  }
}

# -----------------------------------------------------------------------------
# SERVICE PRINCIPAL (Enterprise Application)
# -----------------------------------------------------------------------------

# Create the service principal for the application
# This is the "Enterprise Application" in Azure AD
resource "azuread_service_principal" "uaa_saml" {
  client_id = azuread_application.uaa_saml.client_id

  # Enable SAML SSO
  preferred_single_sign_on_mode = "saml"

  # Enable for users to sign in
  account_enabled               = true
  app_role_assignment_required  = false
  login_url                     = null
  notification_email_addresses  = []

  # SAML SSO settings
  saml_single_sign_on {
    relay_state = null
  }

  # Feature tags
  feature_tags {
    enterprise            = true
    custom_single_sign_on = true
    gallery               = false
    hide                  = false
  }

  owners = [data.azuread_client_config.current.object_id]

  # Enable all app roles from the application
  # This is needed for users/groups to be assigned to the roles
}

# -----------------------------------------------------------------------------
# SAML SIGNING CERTIFICATE
# -----------------------------------------------------------------------------

# Create a SAML signing certificate for the service principal
resource "azuread_service_principal_token_signing_certificate" "uaa_saml" {
  service_principal_id = azuread_service_principal.uaa_saml.id

  # Certificate validity
  end_date = timeadd(
    timestamp(),
    "${var.certificate_validity_years * 365 * 24}h"
  )

  lifecycle {
    # Don't recreate certificate on every apply due to timestamp()
    ignore_changes = [end_date]
  }
}

# -----------------------------------------------------------------------------
# APP ROLE ASSIGNMENT
# -----------------------------------------------------------------------------

# Assign the security group to each app role
# This means members of the group will receive these roles in their tokens
resource "azuread_app_role_assignment" "group_to_role" {
  for_each = { for role in var.app_roles : role.value => role }

  # The group being assigned
  principal_object_id = azuread_group.privileged_access.object_id

  # The service principal (enterprise app) the assignment is for
  resource_object_id = azuread_service_principal.uaa_saml.object_id

  # The app role being assigned
  app_role_id = local.app_role_ids[each.key]
}

# -----------------------------------------------------------------------------
# SAML CONFIGURATION VIA AZAPI
# -----------------------------------------------------------------------------

# Configure SAML URLs for the service principal
# This is necessary because azuread provider doesn't fully support SAML configuration
resource "azapi_update_resource" "saml_urls" {
  type        = "Microsoft.Graph/servicePrincipals@v1.0"
  resource_id = azuread_service_principal.uaa_saml.object_id

  body = jsonencode({
    # SAML SSO settings
    preferredSingleSignOnMode = "saml"

    # Configure SAML URLs
    samlSingleSignOnSettings = {
      relayState = null
    }
  })

  depends_on = [azuread_service_principal.uaa_saml]
}

# Configure custom claims for SAML assertions
resource "azapi_resource" "claims_mapping_policy" {
  type      = "Microsoft.Graph/claimsMappingPolicies@v1.0"
  name      = "${var.application_name}-claims-policy"
  parent_id = "/"

  body = jsonencode({
    displayName = "${var.application_name} Claims Mapping Policy"
    definition = [jsonencode({
      ClaimsMappingPolicy = {
        Version = 1
        IncludeBasicClaimSet = "true"
        ClaimsSchema = [
          {
            Source    = "user"
            ID        = "userprincipalname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
          },
          {
            Source    = "user"
            ID        = "mail"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
          },
          {
            Source    = "user"
            ID        = "givenname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
          },
          {
            Source    = "user"
            ID        = "surname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
          },
          {
            Source    = "user"
            ID        = "displayname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
          }
        ]
      }
    })]
    isOrganizationDefault = false
  })

  response_export_values = ["*"]
}

# Assign the claims mapping policy to the service principal
resource "azapi_resource" "claims_policy_assignment" {
  type      = "Microsoft.Graph/servicePrincipals@v1.0/claimsMappingPolicies/$ref"
  name      = "claimsMappingPolicyAssignment"
  parent_id = azuread_service_principal.uaa_saml.object_id

  body = jsonencode({
    "@odata.id" = "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/${jsondecode(azapi_resource.claims_mapping_policy.output).id}"
  })

  depends_on = [azapi_resource.claims_mapping_policy]
}
