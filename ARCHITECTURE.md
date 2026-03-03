# Architecture: Azure PIM Integration with UAA for Just-In-Time CredHub Admin Access

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Solution Architecture](#solution-architecture)
4. [Component Details](#component-details)
5. [Security Model](#security-model)
6. [User Flows](#user-flows)
7. [Data Flow](#data-flow)
8. [Configuration Reference](#configuration-reference)
9. [Extensibility](#extensibility)
10. [Prerequisites](#prerequisites)

---

## Overview

This architecture implements **Just-In-Time (JIT) privileged access** for CredHub administrators using Azure AD Privileged Identity Management (PIM) integrated with Cloud Foundry's UAA via SAML federation.

### Key Principles

| Principle | Implementation |
|-----------|----------------|
| **Zero Standing Privileges** | No permanent CredHub admin access; all access is time-bound |
| **Just-In-Time Access** | Users activate privileges only when needed |
| **4-Eyes Security** | Peer approval required for activation |
| **Audit Trail** | All activations logged in Azure AD and UAA |
| **Least Privilege** | Access expires automatically after configured duration |

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Identity Provider | Microsoft Entra ID (Azure AD) | Identity management, PIM |
| Privileged Access | PIM for Groups | JIT membership activation |
| Federation | SAML 2.0 | SSO between Azure AD and UAA |
| Service Provider | Cloud Foundry UAA | OAuth2/OIDC token issuance |
| Target System | CredHub | Secrets management |
| Infrastructure as Code | Terraform | Automated provisioning |

---

## Problem Statement

### Current State (Without PIM)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY RISK: Standing Privileges                  │
│                                                                             │
│  ┌─────────────┐     Permanent      ┌─────────────┐     Always     ┌──────┐│
│  │   User A    │────membership─────▶│ Admin Group │────has────────▶│CredHub│
│  │   User B    │                    │             │   access       │ Admin ││
│  │   User C    │                    └─────────────┘                └──────┘│
│  └─────────────┘                                                            │
│                                                                             │
│  Problems:                                                                  │
│  • Compromised account = immediate admin access                             │
│  • No approval workflow for sensitive operations                            │
│  • No time-bound access                                                     │
│  • Difficult to audit "why" access was used                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Target State (With PIM)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURE: Just-In-Time Access                         │
│                                                                             │
│  ┌─────────────┐    Eligible     ┌─────────────┐                           │
│  │   User A    │───(not active)──│ Admin Group │                           │
│  │   User B    │                 │  (empty)    │                           │
│  │   User C    │                 └─────────────┘                           │
│  └─────────────┘                        │                                   │
│         │                               │                                   │
│         │ 1. Request activation         │                                   │
│         │ 2. Provide MFA + justification│                                   │
│         ▼                               │                                   │
│  ┌─────────────┐                        │                                   │
│  │    PIM      │◀───────────────────────┘                                   │
│  │  Workflow   │                                                            │
│  └─────────────┘                                                            │
│         │                                                                   │
│         │ 3. Peer approves (4-eyes)                                         │
│         ▼                                                                   │
│  ┌─────────────┐    Temporary    ┌─────────────┐   Time-bound  ┌──────────┐│
│  │   User A    │────membership──▶│ Admin Group │────access────▶│ CredHub  ││
│  │  (active)   │   (4 hours)     │             │               │  Admin   ││
│  └─────────────┘                 └─────────────┘               └──────────┘│
│                                                                             │
│  Benefits:                                                                  │
│  • Compromised account ≠ automatic admin access (needs activation)         │
│  • MFA required at activation time                                          │
│  • Peer approval creates accountability                                     │
│  • Justification logged for audit                                           │
│  • Access expires automatically                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Solution Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AZURE AD / ENTRA ID                            │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │                    PIM FOR GROUPS CONFIGURATION                        ││
│  │                                                                        ││
│  │  Policy Settings:                                                      ││
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐       ││
│  │  │ MFA Required     │ │ Justification    │ │ Peer Approval    │       ││
│  │  │ on Activation    │ │ Required         │ │ (4-Eyes)         │       ││
│  │  └──────────────────┘ └──────────────────┘ └──────────────────┘       ││
│  │                                                                        ││
│  │  ┌──────────────────┐ ┌──────────────────┐                            ││
│  │  │ Max Duration:    │ │ Notifications:   │                            ││
│  │  │ 4 hours          │ │ All members      │                            ││
│  │  └──────────────────┘ └──────────────────┘                            ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                      │                                      │
│                                      ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │              AAD-CREDHUB-ADMINS (Security Group)                       ││
│  │                                                                        ││
│  │  ┌─────────────────────────────────────────────────────────────────┐  ││
│  │  │                    ELIGIBLE MEMBERS                              │  ││
│  │  │                                                                  │  ││
│  │  │   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐     │  ││
│  │  │   │ User A  │    │ User B  │    │ User C  │    │ User D  │     │  ││
│  │  │   │(eligible│    │(eligible│    │(eligible│    │(eligible│     │  ││
│  │  │   │  only)  │    │  only)  │    │  only)  │    │  only)  │     │  ││
│  │  │   └─────────┘    └─────────┘    └─────────┘    └─────────┘     │  ││
│  │  │                                                                  │  ││
│  │  │   Note: No permanent members - all access via PIM activation    │  ││
│  │  └─────────────────────────────────────────────────────────────────┘  ││
│  │                                                                        ││
│  │  Properties:                                                           ││
│  │  • security_enabled: true                                              ││
│  │  • assignable_to_role: true (required for PIM)                         ││
│  │  • visibility: Private                                                 ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                      │                                      │
│                                      │ Assigned to App Role                 │
│                                      ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │              SAML APPLICATION (UAA-CredHub-SAML)                       ││
│  │                                                                        ││
│  │  Application Registration:                                             ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  Display Name: UAA-CredHub-SAML                                  │ ││
│  │  │  Sign-in Audience: Single tenant                                 │ ││
│  │  │  Identifier URI: api://uaa-credhub-saml                          │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  │                                                                        ││
│  │  App Roles (extensible for future scopes):                            ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │ ││
│  │  │  │ credhub-admin  │  │  bosh-admin    │  │ cf-admin       │     │ ││
│  │  │  │ (current)      │  │  (future)      │  │ (future)       │     │ ││
│  │  │  └────────────────┘  └────────────────┘  └────────────────┘     │ ││
│  │  │                                                                  │ ││
│  │  │  Group AAD-CredHub-Admins ──assigned──▶ credhub-admin role      │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  │                                                                        ││
│  │  SAML Configuration:                                                   ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  Entity ID (Issuer):     https://sts.windows.net/{tenant-id}/   │ ││
│  │  │  SSO URL:                https://login.microsoftonline.com/...  │ ││
│  │  │  Logout URL:             https://login.microsoftonline.com/...  │ ││
│  │  │  Certificate:            [Auto-generated, 2-year validity]       │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  │                                                                        ││
│  │  Claims Configuration:                                                 ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  SAML Assertion includes:                                        │ ││
│  │  │  • NameID: user.userprincipalname                                │ ││
│  │  │  • email: user.mail                                              │ ││
│  │  │  • roles: [app roles user is assigned to]                        │ ││
│  │  │           e.g., ["credhub-admin"] when PIM is activated          │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ SAML 2.0 Assertion
                                       │ (contains roles claim)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CLOUD FOUNDRY UAA                                 │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │              SAML IDENTITY PROVIDER CONFIGURATION                      ││
│  │                                                                        ││
│  │  Provider Alias: azure-credhub                                         ││
│  │  Metadata URL: https://login.microsoftonline.com/{tenant}/...         ││
│  │                                                                        ││
│  │  Attribute Mappings:                                                   ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  SAML Attribute          │  UAA Attribute                        │ ││
│  │  │  ─────────────────────────────────────────────────────────────── │ ││
│  │  │  NameID                  │  user_name                            │ ││
│  │  │  email                   │  email                                │ ││
│  │  │  roles                   │  external_groups                      │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │              EXTERNAL GROUP MAPPINGS                                   ││
│  │                                                                        ││
│  │  ┌──────────────────────────────────────────────────────────────────┐ ││
│  │  │  External Group (from Azure)  │  UAA Group (scope)               │ ││
│  │  │  ─────────────────────────────────────────────────────────────── │ ││
│  │  │  credhub-admin                │  credhub.admin                   │ ││
│  │  │  bosh-admin (future)          │  bosh.admin                      │ ││
│  │  │  cf-admin (future)            │  cloud_controller.admin          │ ││
│  │  └──────────────────────────────────────────────────────────────────┘ ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  Token Issuance:                                                            │
│  When user authenticates via SAML with "credhub-admin" role:               │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │  {                                                                     ││
│  │    "user_name": "user@example.com",                                    ││
│  │    "scope": ["openid", "credhub.admin", ...],                          ││
│  │    "authorities": ["credhub.admin", ...]                               ││
│  │  }                                                                     ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ OAuth2 Access Token
                                       │ (includes credhub.admin scope)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               CREDHUB                                       │
│                                                                             │
│  Authorization Check:                                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │  Token scope includes "credhub.admin"?                                 ││
│  │                                                                        ││
│  │  ✓ YES (PIM activated)  → Full admin access granted                   ││
│  │  ✗ NO  (PIM not active) → Access denied / limited access              ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  Admin Operations Available:                                                │
│  • Get/Set/Delete credentials                                               │
│  • Generate certificates                                                    │
│  • Manage permissions                                                       │
│  • Regenerate credentials                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Azure AD Security Group

**Resource:** `azuread_group`

| Property | Value | Purpose |
|----------|-------|---------|
| `display_name` | `AAD-CredHub-Admins` | Human-readable identifier |
| `security_enabled` | `true` | Required for access control |
| `assignable_to_role` | `true` | Required for PIM for Groups |
| `visibility` | `Private` | Membership not visible to non-members |
| `members` | `[]` (empty) | No permanent members |

**Why `assignable_to_role = true`?**
- This property enables the group for Privileged Identity Management
- Without it, PIM for Groups cannot manage membership eligibility
- Creates a "role-assignable group" in Azure AD

### 2. Azure AD SAML Application

**Resource:** `azuread_application` + `azuread_service_principal`

#### Application Registration

| Property | Value | Purpose |
|----------|-------|---------|
| `display_name` | `UAA-CredHub-SAML` | Identifies the app in Azure |
| `sign_in_audience` | `AzureADMyOrg` | Single-tenant only |
| `identifier_uris` | `["api://uaa-credhub-saml"]` | Unique identifier |
| `group_membership_claims` | `["ApplicationGroup"]` | Include assigned groups in tokens |

#### App Roles

App roles provide a clean abstraction layer between Azure AD groups and UAA scopes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           APP ROLES ARCHITECTURE                            │
│                                                                             │
│  Azure AD Group              App Role              UAA Scope                │
│  ──────────────────────────────────────────────────────────────────────────│
│                                                                             │
│  AAD-CredHub-Admins    ───▶  credhub-admin   ───▶  credhub.admin           │
│  AAD-BOSH-Admins       ───▶  bosh-admin      ───▶  bosh.admin              │
│  AAD-CF-Admins         ───▶  cf-admin        ───▶  cloud_controller.admin  │
│                                                                             │
│  Benefits:                                                                  │
│  • Decouples Azure AD group names from UAA configuration                   │
│  • Stable claim values (app role value doesn't change if group renamed)    │
│  • Multiple groups can map to same app role                                │
│  • Clear audit trail in Azure AD                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### SAML Configuration

| Setting | Value |
|---------|-------|
| Identifier (Entity ID) | Provided by UAA (`uaa_entity_id` variable) |
| Reply URL (ACS) | Provided by UAA (`uaa_acs_urls` variable) |
| Sign-on URL | Optional |
| Logout URL | Optional (`uaa_logout_url` variable) |
| Signing Certificate | Auto-generated, 2-year validity |
| Signing Algorithm | SHA-256 |

#### Claims in SAML Assertion

| Claim | Source | Example Value |
|-------|--------|---------------|
| `NameID` | `user.userprincipalname` | `alice@example.com` |
| `email` | `user.mail` | `alice@example.com` |
| `given_name` | `user.givenname` | `Alice` |
| `family_name` | `user.surname` | `Smith` |
| `roles` | Assigned app roles | `["credhub-admin"]` |

### 3. PIM for Groups Configuration

**Resource:** `azapi_resource` (Microsoft Graph API)

PIM for Groups is configured via the Microsoft Graph API since native Terraform provider support is not available.

#### Eligibility Schedule Request

Creates eligible (not active) membership assignments:

```
API: POST /identityGovernance/privilegedAccess/group/eligibilityScheduleRequests

{
  "accessId": "member",
  "principalId": "<user-object-id>",
  "groupId": "<group-object-id>",
  "action": "adminAssign",
  "justification": "Managed by Terraform",
  "scheduleInfo": {
    "startDateTime": "2024-01-01T00:00:00Z",
    "expiration": {
      "type": "noExpiration"  // Permanent eligibility
    }
  }
}
```

#### Policy Configuration

PIM policies control activation requirements:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PIM POLICY RULES                                    │
│                                                                             │
│  Rule Type                    │  Configuration                              │
│  ───────────────────────────────────────────────────────────────────────── │
│  Activation_EndUser_Assignment                                              │
│  ├─ enabledRules:             │  ["MultiFactorAuthentication",             │
│  │                            │   "Justification", "Approval"]              │
│  ├─ approvalStages:           │  [{                                         │
│  │                            │     "approverType": "groupMembers",         │
│  │                            │     "groupId": "<same-group-id>"            │
│  │                            │   }]                                        │
│  │                            │  (4-eyes: any other eligible member)        │
│  └─ isApprovalRequired:       │  true                                       │
│                                                                             │
│  Expiration_EndUser_Assignment                                              │
│  ├─ maximumDuration:          │  "PT4H" (4 hours)                           │
│  └─ isExpirationRequired:     │  true                                       │
│                                                                             │
│  Notification_Admin_EndUser_Assignment                                      │
│  ├─ notificationType:         │  "Email"                                    │
│  ├─ recipientType:            │  "Admin" (all eligible members)             │
│  └─ isDefaultRecipientEnabled:│  true                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Model

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY LAYERS                                   │
│                                                                             │
│  Layer 1: Identity                                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • Azure AD authentication required                                    │ │
│  │ • User must have valid Azure AD account                               │ │
│  │ • Conditional Access policies can be applied                          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│  Layer 2: Eligibility                                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • User must be eligible for group membership                          │ │
│  │ • Eligibility is explicitly granted by Terraform                      │ │
│  │ • Eligibility can be time-bound or permanent                          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│  Layer 3: Activation Requirements                                           │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • MFA required at activation time                                     │ │
│  │ • Justification must be provided                                      │ │
│  │ • Prevents casual/accidental activation                               │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│  Layer 4: Peer Approval (4-Eyes Principle)                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • Another eligible group member must approve                          │ │
│  │ • Approver sees justification before approving                        │ │
│  │ • Creates accountability and prevents lone-wolf actions               │ │
│  │ • Approver cannot approve their own request                           │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│  Layer 5: Time-Bound Access                                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • Maximum activation duration: 4 hours (configurable)                 │ │
│  │ • Access automatically revoked after expiration                       │ │
│  │ • User must re-activate for continued access                          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│  Layer 6: Audit Trail                                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ • All activations logged in Azure AD audit logs                       │ │
│  │ • Justification captured with each activation                         │ │
│  │ • Approver identity recorded                                          │ │
│  │ • UAA logs SAML authentication events                                 │ │
│  │ • CredHub logs all admin operations                                   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4-Eyes Approval Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         4-EYES APPROVAL WORKFLOW                            │
│                                                                             │
│  Eligible Members: [Alice, Bob, Carol, Dave]                                │
│                                                                             │
│  Scenario: Alice needs CredHub admin access                                 │
│                                                                             │
│  ┌──────────┐                                                               │
│  │  Alice   │                                                               │
│  │ (eligible│                                                               │
│  │  member) │                                                               │
│  └────┬─────┘                                                               │
│       │                                                                     │
│       │ 1. Request activation                                               │
│       │    └── MFA: ✓ Verified                                              │
│       │    └── Justification: "Rotating DB credentials for JIRA-1234"      │
│       ▼                                                                     │
│  ┌──────────┐                                                               │
│  │   PIM    │                                                               │
│  │ Service  │                                                               │
│  └────┬─────┘                                                               │
│       │                                                                     │
│       │ 2. Find eligible approvers (same group, excluding requestor)        │
│       │    └── Approvers: [Bob, Carol, Dave]                                │
│       │                                                                     │
│       │ 3. Send approval request email to all approvers                     │
│       ▼                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                                  │
│  │   Bob    │  │  Carol   │  │   Dave   │                                  │
│  │ (approver│  │(approver)│  │(approver)│                                  │
│  └────┬─────┘  └──────────┘  └──────────┘                                  │
│       │                                                                     │
│       │ 4. Bob reviews request:                                             │
│       │    └── Sees: "Alice requests CredHub Admin"                         │
│       │    └── Sees: "Justification: Rotating DB credentials..."            │
│       │    └── Action: [Approve] / [Deny]                                   │
│       │                                                                     │
│       │ 5. Bob clicks [Approve]                                             │
│       ▼                                                                     │
│  ┌──────────┐                                                               │
│  │   PIM    │                                                               │
│  │ Service  │                                                               │
│  └────┬─────┘                                                               │
│       │                                                                     │
│       │ 6. Activate Alice's group membership                                │
│       │    └── Duration: 4 hours                                            │
│       │    └── Log: "Approved by Bob at 2024-01-15T10:30:00Z"               │
│       ▼                                                                     │
│  ┌──────────┐                                                               │
│  │  Alice   │──── Now has active membership ────▶ AAD-CredHub-Admins       │
│  │ (active) │     (expires in 4 hours)                                      │
│  └──────────┘                                                               │
│                                                                             │
│  Audit Record:                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ Timestamp: 2024-01-15T10:30:00Z                                       │ │
│  │ Action: Membership Activated                                          │ │
│  │ Principal: alice@example.com                                          │ │
│  │ Group: AAD-CredHub-Admins                                             │ │
│  │ Approved By: bob@example.com                                          │ │
│  │ Justification: "Rotating DB credentials for JIRA-1234"                │ │
│  │ Expires: 2024-01-15T14:30:00Z                                         │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| Compromised user credentials | MFA required at activation; credential theft alone insufficient |
| Insider threat (single actor) | 4-eyes approval requires peer sign-off |
| Prolonged unauthorized access | Time-bound activation (max 4 hours) |
| Unauthorized activation | Only explicitly eligible users can request |
| Unaccountable actions | Justification + approver logged for audit |
| Social engineering approver | Approver sees full context including justification |

---

## User Flows

### Flow 1: Initial Setup (Administrator)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ADMINISTRATOR SETUP FLOW                            │
│                                                                             │
│  1. Deploy Terraform                                                        │
│     │                                                                       │
│     ├── terraform init                                                      │
│     ├── terraform plan                                                      │
│     └── terraform apply                                                     │
│            │                                                                │
│            ├── Creates: Azure AD Group (AAD-CredHub-Admins)                │
│            ├── Creates: SAML Application (UAA-CredHub-SAML)                │
│            ├── Creates: PIM Eligibility Assignments                        │
│            ├── Creates: PIM Policy (MFA, approval, notifications)          │
│            └── Outputs: SAML metadata, certificate, endpoints              │
│                                                                             │
│  2. Configure UAA                                                           │
│     │                                                                       │
│     ├── Add SAML provider configuration (from Terraform output)            │
│     ├── Configure external group mapping:                                   │
│     │      credhub-admin → credhub.admin                                   │
│     └── Deploy UAA changes                                                  │
│                                                                             │
│  3. Verify Setup                                                            │
│     │                                                                       │
│     ├── Test user activates PIM                                            │
│     ├── Test user logs into UAA via SAML                                   │
│     └── Verify credhub.admin scope in token                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Flow 2: User Activation (Day-to-Day Operation)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         USER ACTIVATION FLOW                                │
│                                                                             │
│  ┌────────────────┐                                                         │
│  │   User needs   │                                                         │
│  │  CredHub admin │                                                         │
│  │    access      │                                                         │
│  └───────┬────────┘                                                         │
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 1: Go to Azure PIM Portal                                         ││
│  │         https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/...   ││
│  │         Or: https://myaccess.microsoft.com                             ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 2: Find "AAD-CredHub-Admins" in eligible assignments             ││
│  │         Click "Activate"                                               ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 3: Complete MFA challenge                                         ││
│  │         (Authenticator app / SMS / etc.)                               ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 4: Enter activation details                                       ││
│  │         • Duration: 1-4 hours                                          ││
│  │         • Justification: "Rotating credentials for JIRA-1234"          ││
│  │         Click "Activate"                                               ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 5: Wait for peer approval                                         ││
│  │         • Email sent to other eligible members                         ││
│  │         • Any one approver can approve/deny                            ││
│  │         • Status shows "Pending approval"                              ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼ (After approval)                                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 6: Access CredHub                                                 ││
│  │         • Login to CredHub UI or CLI                                   ││
│  │         • Select "Azure AD" / SAML login                               ││
│  │         • Azure AD issues SAML assertion with "credhub-admin" role     ││
│  │         • UAA maps to credhub.admin scope                              ││
│  │         • Full admin access granted                                    ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼ (After 4 hours or manual deactivation)                           │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Step 7: Access automatically revoked                                   ││
│  │         • Group membership removed                                     ││
│  │         • New logins will not include credhub-admin role               ││
│  │         • Existing sessions may continue until token expires           ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Flow 3: Approver Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         APPROVER WORKFLOW                                   │
│                                                                             │
│  ┌────────────────┐                                                         │
│  │  Approver      │                                                         │
│  │  receives      │                                                         │
│  │  email         │                                                         │
│  └───────┬────────┘                                                         │
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Email Content:                                                         ││
│  │ ──────────────────────────────────────────────────────────────────────││
│  │ Subject: Approval required: AAD-CredHub-Admins membership              ││
│  │                                                                        ││
│  │ Alice Smith (alice@example.com) has requested activation of            ││
│  │ AAD-CredHub-Admins group membership.                                   ││
│  │                                                                        ││
│  │ Duration: 4 hours                                                      ││
│  │ Justification: "Need to rotate database credentials for production    ││
│  │                 deployment. Reference: JIRA-1234"                      ││
│  │                                                                        ││
│  │ [Approve]  [Deny]  [View in Portal]                                    ││
│  └───────┬────────────────────────────────────────────────────────────────┘│
│          │                                                                  │
│          ▼                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │ Approver Decision:                                                     ││
│  │                                                                        ││
│  │ Option A: Click [Approve]                                              ││
│  │   • Can add approval comment                                           ││
│  │   • Requestor immediately gains access                                 ││
│  │   • Logged in audit trail                                              ││
│  │                                                                        ││
│  │ Option B: Click [Deny]                                                 ││
│  │   • Must provide denial reason                                         ││
│  │   • Requestor notified of denial                                       ││
│  │   • Logged in audit trail                                              ││
│  │                                                                        ││
│  │ Option C: Ignore                                                       ││
│  │   • Request remains pending                                            ││
│  │   • Other approvers can still approve/deny                             ││
│  │   • Request may timeout based on policy                                ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### SAML Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SAML AUTHENTICATION FLOW                            │
│                                                                             │
│  ┌──────┐       ┌──────┐       ┌──────────┐       ┌──────────┐             │
│  │ User │       │CredHub       │   UAA    │       │ Azure AD │             │
│  │      │       │  /App │       │          │       │          │             │
│  └──┬───┘       └──┬───┘       └────┬─────┘       └────┬─────┘             │
│     │              │                │                   │                   │
│     │ 1. Access    │                │                   │                   │
│     │    CredHub   │                │                   │                   │
│     │─────────────▶│                │                   │                   │
│     │              │                │                   │                   │
│     │              │ 2. Redirect to │                   │                   │
│     │              │    UAA login   │                   │                   │
│     │◀─────────────│                │                   │                   │
│     │              │                │                   │                   │
│     │ 3. Access UAA login page      │                   │                   │
│     │──────────────────────────────▶│                   │                   │
│     │              │                │                   │                   │
│     │ 4. Click "Login with Azure AD"│                   │                   │
│     │──────────────────────────────▶│                   │                   │
│     │              │                │                   │                   │
│     │              │                │ 5. SAML AuthnReq  │                   │
│     │◀─────────────────────────────────────────────────▶│                   │
│     │              │                │   (redirect)      │                   │
│     │              │                │                   │                   │
│     │ 6. Azure AD login page        │                   │                   │
│     │◀──────────────────────────────────────────────────│                   │
│     │              │                │                   │                   │
│     │ 7. Enter credentials + MFA    │                   │                   │
│     │──────────────────────────────────────────────────▶│                   │
│     │              │                │                   │                   │
│     │              │                │                   │ 8. Validate user  │
│     │              │                │                   │    Check group    │
│     │              │                │                   │    membership     │
│     │              │                │                   │    (PIM active?)  │
│     │              │                │                   │                   │
│     │              │                │ 9. SAML Response  │                   │
│     │              │                │◀──────────────────│                   │
│     │              │                │                   │                   │
│     │              │                │ Contains:         │                   │
│     │              │                │ • NameID          │                   │
│     │              │                │ • email           │                   │
│     │              │                │ • roles: [        │                   │
│     │              │                │     "credhub-admin"                   │
│     │              │                │   ] (if PIM active)                   │
│     │              │                │                   │                   │
│     │              │                │ 10. Validate      │                   │
│     │              │                │     signature     │                   │
│     │              │                │     Map roles to  │                   │
│     │              │                │     UAA scopes    │                   │
│     │              │                │                   │                   │
│     │              │ 11. Issue OAuth token              │                   │
│     │              │     with scopes:                   │                   │
│     │              │     [credhub.admin]                │                   │
│     │              │◀───────────────│                   │                   │
│     │              │                │                   │                   │
│     │ 12. Access granted            │                   │                   │
│     │◀─────────────│                │                   │                   │
│     │              │                │                   │                   │
└─────┴──────────────┴────────────────┴───────────────────┴───────────────────┘
```

### Token Contents

**SAML Assertion (from Azure AD):**
```xml
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>alice@example.com</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role">
      <saml:AttributeValue>credhub-admin</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
      <saml:AttributeValue>alice@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

**OAuth Token (from UAA):**
```json
{
  "jti": "abc123",
  "sub": "user-guid",
  "scope": [
    "openid",
    "credhub.admin"
  ],
  "client_id": "credhub_client",
  "user_name": "alice@example.com",
  "origin": "azure-credhub",
  "iat": 1705312200,
  "exp": 1705315800,
  "iss": "https://uaa.sys.example.com/oauth/token"
}
```

---

## Configuration Reference

### Terraform Variables

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `group_name` | `string` | No | `"AAD-CredHub-Admins"` | Azure AD security group name |
| `group_description` | `string` | No | *auto* | Group description |
| `application_name` | `string` | No | `"UAA-CredHub-SAML"` | SAML app display name |
| `uaa_entity_id` | `string` | **Yes** | - | UAA SAML entity ID (audience) |
| `uaa_acs_urls` | `list(string)` | **Yes** | - | UAA Assertion Consumer Service URLs |
| `uaa_logout_url` | `string` | No | `null` | UAA single logout URL |
| `app_roles` | `list(object)` | No | `[{value="credhub-admin"...}]` | App roles to create |
| `eligible_member_ids` | `list(string)` | **Yes** | - | User object IDs to make eligible |
| `pim_max_activation_hours` | `number` | No | `4` | Max activation duration |
| `pim_require_mfa` | `bool` | No | `true` | Require MFA on activation |
| `pim_require_justification` | `bool` | No | `true` | Require justification |
| `pim_require_approval` | `bool` | No | `true` | Require peer approval |
| `certificate_validity_years` | `number` | No | `2` | SAML certificate validity |
| `tags` | `map(string)` | No | `{}` | Tags for Azure resources |

### Terraform Outputs

| Output | Type | Sensitive | Description |
|--------|------|-----------|-------------|
| `group_object_id` | `string` | No | Azure AD group object ID |
| `group_name` | `string` | No | Azure AD group display name |
| `application_id` | `string` | No | Application (client) ID |
| `service_principal_id` | `string` | No | Enterprise app object ID |
| `saml_metadata_url` | `string` | No | SAML federation metadata URL |
| `saml_entity_id` | `string` | No | Azure AD SAML entity ID (issuer) |
| `saml_sso_url` | `string` | No | SAML single sign-on URL |
| `saml_logout_url` | `string` | No | SAML single logout URL |
| `saml_certificate_base64` | `string` | No | SAML signing certificate (base64) |
| `app_role_values` | `list(string)` | No | App role values for UAA mapping |
| `uaa_provider_config` | `string` | Yes | Complete UAA SAML provider YAML |

### UAA Configuration Example

```yaml
login:
  saml:
    providers:
      azure-credhub:
        idpMetadata: "${saml_metadata_url}"
        nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
        assertionConsumerIndex: 0
        metadataTrustCheck: true
        showSamlLoginLink: true
        linkText: "Login with Azure AD"
        iconUrl: "https://docs.microsoft.com/azure/media/index/azure-active-directory.svg"
        attributeMappings:
          given_name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
          family_name: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
          email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
          external_groups:
            - http://schemas.microsoft.com/ws/2008/06/identity/claims/role
        externalGroupsWhitelist:
          - credhub-admin
          - bosh-admin
          - cf-admin

uaa:
  scim:
    external_groups:
      azure-credhub:
        credhub-admin:
          - credhub.admin
        bosh-admin:
          - bosh.admin
        cf-admin:
          - cloud_controller.admin
```

---

## Extensibility

### Adding New Admin Scopes

The architecture supports multiple app roles for different administrative scopes:

```hcl
module "pim_uaa" {
  source = "./modules/azure-pim-uaa-idp"

  # ... other variables ...

  app_roles = [
    {
      value        = "credhub-admin"
      display_name = "CredHub Administrator"
      description  = "Full administrative access to CredHub"
    },
    {
      value        = "bosh-admin"
      display_name = "BOSH Administrator"
      description  = "Full administrative access to BOSH Director"
    },
    {
      value        = "cf-admin"
      display_name = "Cloud Foundry Administrator"
      description  = "Full administrative access to Cloud Foundry"
    }
  ]
}
```

### Multiple Groups with Different Policies

For different approval/MFA requirements per scope:

```hcl
module "credhub_admins" {
  source = "./modules/azure-pim-uaa-idp"
  
  group_name               = "AAD-CredHub-Admins"
  pim_max_activation_hours = 4
  pim_require_approval     = true   # Strict for CredHub
  # ...
}

module "cf_admins" {
  source = "./modules/azure-pim-uaa-idp"
  
  group_name               = "AAD-CF-Admins"
  pim_max_activation_hours = 8
  pim_require_approval     = false  # Less strict for CF
  # ...
}
```

---

## Prerequisites

### Azure AD Requirements

| Requirement | Details |
|-------------|---------|
| **License** | Microsoft Entra ID P2 (required for PIM for Groups) |
| **Permissions** | `Group.ReadWrite.All`, `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `PrivilegedAccess.ReadWrite.AzureADGroup` |
| **Terraform Auth** | Service Principal with above permissions, or User with Global Administrator role |

### UAA Requirements

| Requirement | Details |
|-------------|---------|
| **Version** | UAA 74.0.0+ (SAML 2.0 support) |
| **Configuration** | Ability to add SAML providers and external group mappings |
| **Network** | UAA must be able to fetch Azure AD SAML metadata (or use static metadata) |

### CredHub Requirements

| Requirement | Details |
|-------------|---------|
| **UAA Integration** | CredHub configured to use UAA for authentication |
| **Scopes** | `credhub.admin` scope defined in UAA |

---

## References

- [Microsoft Entra PIM for Groups](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups)
- [PIM for Groups API (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-for-groups-api-overview)
- [Azure AD SAML SSO](https://learn.microsoft.com/en-us/entra/identity/saas-apps/tutorial-saml-based-sso)
- [Cloud Foundry UAA SAML Identity Providers](https://docs.cloudfoundry.org/uaa/identity-providers.html)
- [CredHub Authentication](https://docs.cloudfoundry.org/credhub/authentication.html)
