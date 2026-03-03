terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 1.12"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

# -----------------------------------------------------------------------------
# PROVIDER CONFIGURATION
# -----------------------------------------------------------------------------

# Azure Resource Manager provider
# Used for subscription data and resource management
provider "azurerm" {
  features {}

  # Optionally specify subscription
  # subscription_id = var.subscription_id
}

# Azure Active Directory provider
# Used for creating groups, applications, and service principals
provider "azuread" {
  # Uses Azure CLI, service principal, or managed identity authentication
  # tenant_id = var.tenant_id
}

# Azure API provider
# Used for Microsoft Graph API calls (PIM for Groups)
provider "azapi" {
  # Uses the same authentication as azurerm/azuread
}

# Time provider
# Used for generating timestamps for PIM schedules
provider "time" {}

# Random provider
# Used for generating UUIDs for app role IDs
provider "random" {}

# Local provider
# Used for generating local files (optional)
provider "local" {}
