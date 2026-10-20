// AegisArena — post-bootstrap application release (resource-group scope).
//
// PURPOSE: this is the template normal, day-to-day releases use — it
// creates/updates ONLY the Container App revision, referencing every
// supporting resource (Container Apps Environment, ACR, the runtime
// managed identity, Key Vault) as `existing`, never creating them.
//
// WHY THIS EXISTS SEPARATELY FROM main.bicep: main.bicep runs at
// `targetScope = 'subscription'` (it has to, since it creates the resource
// group itself for the initial bootstrap). id-aegisarena-github — the
// GitHub Actions deployment identity — is deliberately scoped to
// Contributor on rg-aegisarena-dev ONLY (see infra/azure/README.md's
// least-privilege table), and a resource-group-scoped role assignment
// cannot run a subscription-scope ARM deployment. Rather than widen that
// identity's privileges to subscription-wide Contributor/Owner just to let
// it run main.bicep, normal releases use THIS resource-group-scoped
// template instead, run via `az deployment group create`.
//
// This template must NEVER create: a resource group, the PostgreSQL
// server, the Log Analytics workspace, the GitHub identity, or a duplicate
// ACR/Key Vault/Container Apps Environment. It only ever touches the
// Container App.
targetScope = 'resourceGroup'

@description('Azure region for the Container App (must match the region the bootstrap resources were created in).')
param location string = 'centralindia'

@description('Name of the existing Container Apps Environment created by the bootstrap (main.bicep).')
param containerAppsEnvironmentName string = 'cae-aegisarena-dev'

@description('Name of the existing Azure Container App to update.')
param containerAppName string = 'ca-aegisarena-clean'

@description('Name of the existing Azure Container Registry created by the bootstrap. This has a generated suffix (e.g. acraegisarenadevab12) and has no safe default — pass it explicitly (the CD workflow already has this as the ACR_NAME repository variable).')
param acrName string

@description('Name of the existing runtime managed identity (id-aegisarena-app) created by the bootstrap.')
param appIdentityName string = 'id-aegisarena-app'

@description('Name of the existing Key Vault created by the bootstrap.')
param keyVaultName string = 'kv-aegis-${uniqueString(resourceGroup().id)}'

@description('Immutable image tag (e.g. a git SHA) applied to both containers. "latest" is a placeholder for local iteration only — real releases MUST override this with an immutable tag.')
param imageTag string = 'latest'

@description('Minimum Container App replicas for the working clean deployment.')
param minReplicas int = 1

@description('Maximum Container App replicas.')
param maxReplicas int = 1

@description('Entra/Easy-Auth principal IDs (object IDs) granted ADMIN role. Empty by default — see docs/security/AUTHENTICATION.md.')
param adminPrincipalIds array = []

@description('Approved Google principal IDs for read-only dashboard access.')
param googleDashboardPrincipalIds array = []

@description('''
Sets TRUST_EASYAUTH_HEADERS on the Container App. MUST default to false.
Normal post-bootstrap releases keep this false until an operator has
manually configured Azure Container Apps Easy Auth on the running
Container App and verified it actually works (see
docs/deployment/AZURE_DEPLOYMENT.md and docs/security/AUTHENTICATION.md).
Only pass true explicitly on a release run AFTER that verification —
never change this template's default.
''')
param trustEasyAuthHeaders bool = false

@description('Temporarily enables the operator-keyed Google identity enrollment diagnostic. Defaults to false.')
param authIdentityDiagnosticEnabled bool = false

resource containerAppsEnvironment 'Microsoft.App/managedEnvironments@2025-01-01' existing = {
  name: containerAppsEnvironmentName
}

resource acr 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: acrName
}

resource appIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: appIdentityName
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: keyVaultName
}

module containerApp 'modules/containerapp.bicep' = {
  name: 'aegisarena-containerapp-release'
  params: {
    location: location
    containerAppName: containerAppName
    containerAppsEnvironmentId: containerAppsEnvironment.id
    acrLoginServer: acr.properties.loginServer
    appIdentityId: appIdentity.id
    keyVaultUri: keyVault.properties.vaultUri
    imageTag: imageTag
    minReplicas: minReplicas
    maxReplicas: maxReplicas
    // The verified clean revision uses ephemeral model storage and has no
    // Azure Files volume or mount. Existing storage resources are untouched.
    modelArtifactStorageName: ''
    adminPrincipalIds: adminPrincipalIds
    googleDashboardPrincipalIds: googleDashboardPrincipalIds
    trustEasyAuthHeaders: trustEasyAuthHeaders
    authIdentityDiagnosticEnabled: authIdentityDiagnosticEnabled
    // The clean app's authConfigs/current resource already references this
    // Container App secret name. The value must first be imported manually
    // into the existing Key Vault; the release template never reads it.
    googleProviderAuthenticationSecretKeyVaultEnabled: true
  }
}

// Safe outputs only — never a password or connection string (this template
// never touches PostgreSQL/Key Vault secret values in the first place).
output containerAppName string = containerApp.outputs.containerAppName
output containerAppFqdn string = containerApp.outputs.containerAppFqdn
