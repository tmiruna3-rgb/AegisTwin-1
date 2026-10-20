// AegisArena — single Container App, two sidecar containers (frontend + backend)
// in one revision.
//
// Networking note: Container Apps multi-container revisions share a single
// network namespace across all containers in the replica, so the frontend
// nginx container's `proxy_pass http://localhost:8000` (see
// frontend/nginx.conf.template, BACKEND_UPSTREAM=localhost:8000) reaches the
// backend sidecar directly — no extra Container Apps networking/Dapr config
// is needed for that. External ingress only ever targets the frontend
// container's port (8080); the backend port (8000) is never exposed directly
// to ingress.
//
// transport: 'auto' lets the same ingress serve both plain HTTP (/api) and
// WebSocket-upgraded connections (/ws, proxied by nginx to the backend) since
// Container Apps auto-detects the protocol per request.

@description('Azure region for the Container App.')
param location string

@description('Container App name.')
param containerAppName string = 'ca-aegisarena-dev'

@description('Resource ID of the Container Apps Environment (Consumption).')
param containerAppsEnvironmentId string

@description('Login server of the ACR to pull images from, e.g. acraegisarenadevXXXX.azurecr.io.')
param acrLoginServer string

@description('Resource ID of id-aegisarena-app — used for both ACR pulls and the Key Vault secret reference. Assigned to the Container App as its only identity.')
param appIdentityId string

@description('Vault URI of kv-aegisarena-dev, e.g. https://kv-aegisarena-dev.vault.azure.net/. Used to build the database-url secret reference.')
param keyVaultUri string

@description('Immutable image tag for both containers. Real deployments MUST pass a git-sha (or similarly immutable) tag — "latest" is a placeholder for local iteration only, never a supported production value.')
param imageTag string = 'latest'

@description('Minimum replica count (0 = scale to zero when idle, keeping cost near-zero between demos).')
param minReplicas int = 0

@description('Maximum replica count.')
param maxReplicas int = 1

@description('Entra/Easy-Auth principal IDs (object IDs) granted ADMIN role. Empty by default — set explicitly per docs/security/AUTHENTICATION.md before relying on ADMIN-tier actions.')
param adminPrincipalIds array = []

@description('Google principal IDs approved for read-only dashboard access.')
param googleDashboardPrincipalIds array = []

@description('''
Sets the backend container's TRUST_EASYAUTH_HEADERS env var. MUST default
to false — Azure Container Apps Easy Auth is configured manually, after
this Container App already exists (see docs/security/AUTHENTICATION.md and
docs/deployment/AZURE_DEPLOYMENT.md). Only pass true on a deployment run
AFTER an operator has configured Easy Auth on this Container App and
verified it is genuinely fronting the backend — never as a default.
''')
param trustEasyAuthHeaders bool = false

@description('Container Apps Environment storage (Azure Files) mounted at /data for model artifacts. Empty = no mount: artifacts then live on the ephemeral container filesystem and are rebuilt deterministically on first use after a restart.')
param modelArtifactStorageName string = 'modelartifacts'

var frontendImage = '${acrLoginServer}/aegisarena/frontend:${imageTag}'
var backendImage = '${acrLoginServer}/aegisarena/backend:${imageTag}'
// Container Apps' native Key Vault secret reference wants the secret's full
// vault URL (not just the vault URI) — keyVaultUri already ends in '/'.
var databaseUrlSecretUri = '${keyVaultUri}secrets/database-url'

resource containerApp 'Microsoft.App/containerApps@2025-01-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${appIdentityId}': {}
    }
  }
  properties: {
    environmentId: containerAppsEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        allowInsecure: false
      }
      // Managed-identity pulls only — no admin username/password anywhere.
      registries: [
        {
          server: acrLoginServer
          identity: appIdentityId
        }
      ]
      // Native Key Vault secret reference: Container Apps fetches the
      // current secret value at revision start using appIdentityId (which
      // already holds Key Vault Secrets User on the vault). The raw
      // connection string never appears in this template or in params.
      secrets: [
        {
          name: 'database-url'
          keyVaultUrl: databaseUrlSecretUri
          identity: appIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'frontend'
          image: frontendImage
          env: [
            // Same-revision sidecars share a network namespace, so the
            // backend is reachable at localhost — see module header note.
            {
              name: 'BACKEND_UPSTREAM'
              value: 'localhost:8000'
            }
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 30
            }
          ]
        }
        {
          name: 'backend'
          image: backendImage
          env: [
            {
              name: 'DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'ENVIRONMENT'
              value: 'production'
            }
            {
              name: 'DEBUG'
              value: 'false'
            }
            {
              name: 'SIMULATION_ONLY'
              value: 'true'
            }
            {
              // Belt-and-suspenders: config.py already disables /docs,
              // /redoc, /openapi.json whenever ENVIRONMENT=production.
              name: 'DOCS_ENABLED'
              value: 'false'
            }
            {
              name: 'ADMIN_PRINCIPAL_IDS'
              value: join(adminPrincipalIds, ',')
            }
            {
              name: 'GOOGLE_DASHBOARD_PRINCIPAL_IDS'
              value: string(googleDashboardPrincipalIds)
            }
            {
              // Explicitly declared (not merely relying on the app's own
              // false default) so a later declarative deployment of this
              // module can never silently drop an operator's prior true
              // setting by omission — see param description above.
              name: 'TRUST_EASYAUTH_HEADERS'
              value: trustEasyAuthHeaders ? 'true' : 'false'
            }
            {
              // The backend is never reached directly by the browser (only
              // by the frontend nginx sidecar over localhost, and by Azure
              // health probes), so CORS_ORIGINS is effectively unused here;
              // kept explicit and non-wildcard to satisfy config.py's
              // validator rather than relying on its localhost dev default.
              name: 'CORS_ORIGINS'
              value: 'https://${containerAppName}.internal.invalid'
            }
            {
              name: 'MODEL_ARTIFACT_DIR'
              value: '/data/models'
            }
          ]
          volumeMounts: empty(modelArtifactStorageName)
            ? []
            : [
                {
                  volumeName: 'model-artifacts'
                  mountPath: '/data'
                }
              ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          // Mapped per docs/DEPLOYMENT_REQUIREMENTS.md's
          // startup/liveness/readiness split: startup gates on the same
          // cheap liveness check but tolerates the cold-start time for
          // `alembic upgrade head` to finish (see backend/Dockerfile's
          // CMD); liveness stays cheap/dependency-free thereafter;
          // readiness is the only probe that validates PostgreSQL
          // connectivity (via /api/health/ready's existing DB check),
          // matching "avoid expensive deep health checks on every probe".
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/api/health/live'
                port: 8000
              }
              periodSeconds: 5
              failureThreshold: 20
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/api/health/live'
                port: 8000
              }
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/api/health/ready'
                port: 8000
              }
              periodSeconds: 15
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
      volumes: empty(modelArtifactStorageName)
        ? []
        : [
            {
              name: 'model-artifacts'
              storageType: 'AzureFile'
              storageName: modelArtifactStorageName
              // The backend runs as a non-root user; SMB mounts default to
              // root ownership, so grant write access explicitly.
              mountOptions: 'dir_mode=0777,file_mode=0777'
            }
          ]
    }
  }
}

output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppName string = containerApp.name
