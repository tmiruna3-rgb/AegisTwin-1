# Azure Deployment

This document is the procedural guide for deploying AegisArena to Azure. See
`docs/deployment/AZURE_ARCHITECTURE.md` for what gets deployed and why. As of
writing, nothing described here has been deployed yet — this documents how
the deployment is intended to work.

## Prerequisites

- Azure subscription with permission to create resource groups, managed
  identities, and role assignments (owner/contributor at subscription scope,
  for the one-time bootstrap only — day-to-day deploys use the
  RG-scoped `id-aegisarena-github` identity instead).
- Azure CLI (`az`) installed locally for the manual bootstrap steps below.
- Repository admin access on GitHub, to set repository/environment
  variables and secrets and to create the `production` Environment.

## Why this is a two-pass, mostly-manual bootstrap

A brand-new environment cannot be created in a single automated pass:

- The Container App needs `aegisarena/frontend`/`aegisarena/backend` images
  that don't exist until the ACR this same template creates has something
  pushed to it.
- GitHub OIDC cannot authenticate the very first deployment either, because
  the identity it federates against (`id-aegisarena-github`) is itself
  created by this template — there is nothing to federate against until
  after PASS 1 below.

So the **first-ever** deployment to a fresh subscription is a manual,
human-run process (this section), using the subscription-scope
`infra/azure/main.bicep`. Only **after** that bootstrap exists does
`.github/workflows/deploy-azure.yml` become usable for subsequent,
manually-triggered deployments (see "Running a deployment" below) — and
those subsequent deployments use a **different**, resource-group-scoped
template, `infra/azure/app.bicep`, not `main.bicep` again. This distinction
matters for least privilege:

| | Template | Scope | Creates | Used by |
|---|---|---|---|---|
| **Initial bootstrap** (this section, manual, once) | `infra/azure/main.bicep` | `subscription` | Resource group, both identities, ACR, Key Vault, Log Analytics, Container Apps Environment, PostgreSQL, and (PASS 2) the Container App | A human operator with subscription-level permissions |
| **Normal release** (every deploy after) | `infra/azure/app.bicep` | `resourceGroup` (`rg-aegisarena-dev`) | Nothing new — updates only the existing Container App | `deploy-azure.yml`, authenticated as `id-aegisarena-github` |

`id-aegisarena-github` holds only RG-scoped `Contributor` on
`rg-aegisarena-dev` (see the least-privilege table in
`infra/azure/README.md`) — it is deliberately never granted
subscription-wide access, so it is incapable of running
`main.bicep`/`az deployment sub create` at all. This is why normal releases
use `app.bicep`/`az deployment group create` instead: that identity's
existing RG-scoped privileges are exactly sufficient for it.

## Ordered manual hosting sequence

1. **PASS 1 — bootstrap supporting infrastructure** (no Container App yet):
   ```bash
   PGADMIN_PASSWORD='<generate a strong password, do not reuse elsewhere>' \
   az deployment sub create \
     --name aegisarena-bootstrap \
     --location centralindia \
     --template-file infra/azure/main.bicep \
     --parameters infra/azure/parameters/dev.bicepparam \
     --parameters deployContainerApp=false
   ```
   This creates the resource group, both managed identities, the ACR, Key
   Vault, Log Analytics workspace, Container Apps Environment, and the
   PostgreSQL Flexible Server — but not the Container App itself (there are
   no images to run yet). Note the `acrLoginServer` output.

2. **ACR login**, using your own `az login` session (not OIDC — no CI
   identity exists to federate against yet):
   ```bash
   az acr login --name <acrLoginServer, without .azurecr.io>
   ```

3. **Build/push SHA-tagged images** to that registry:
   ```bash
   git_sha=$(git rev-parse HEAD)
   docker build -t <acrLoginServer>/aegisarena/backend:$git_sha backend
   docker build -t <acrLoginServer>/aegisarena/frontend:$git_sha frontend
   docker push <acrLoginServer>/aegisarena/backend:$git_sha
   docker push <acrLoginServer>/aegisarena/frontend:$git_sha
   ```

4. **PASS 2 — create the Container App**, now that images exist:
   ```bash
   PGADMIN_PASSWORD='<the SAME password used in PASS 1>' \
   az deployment sub create \
     --name aegisarena-pass2 \
     --location centralindia \
     --template-file infra/azure/main.bicep \
     --parameters infra/azure/parameters/dev.bicepparam \
     --parameters imageTag=$git_sha
   ```
   (`deployContainerApp` defaults to `true`, so it does not need to be
   passed explicitly here.) Note the `containerAppFqdn` output — this is the
   application's public HTTPS hostname. At this point `TRUST_EASYAUTH_HEADERS`
   is still `false` (Bicep never sets it otherwise), so the app is reachable
   with anonymous VIEWER-only access — this is expected and safe.

5. **Create/configure the Microsoft Entra application registration** for
   Container Apps user authentication (App registrations → New registration,
   redirect URI pointed at the Container App's `/.auth/login/aad/callback`
   per Azure's Easy Auth setup docs). No IDs/secrets from this step are
   recorded in this repository.

6. **Configure Azure Container Apps Easy Auth** on the now-existing
   Container App (Container App → Authentication → Add identity provider →
   Microsoft), pointed at the app registration from step 5.

7. **Keep unauthenticated access allowed** in the Easy Auth configuration
   ("Allow unauthenticated requests", not "Require authentication") — public
   VIEWER access must keep working for anonymous callers; Easy Auth here
   only needs to *attach* identity headers for callers who do sign in, not
   block everyone else.

8. **Verify the sign-in flow actually works**: visit
   `https://<containerAppFqdn>/.auth/login/google` and confirm a real Google
   sign-in completes successfully.

9. **Verify the authenticated identity headers** reach the backend as
   expected — use the temporary, operator-keyed diagnostic documented in
   `docs/security/AUTHENTICATION.md` to confirm the encoded
   `X-MS-CLIENT-PRINCIPAL` contains a stable Google subject. Also prove that
   externally forged `X-MS-CLIENT-PRINCIPAL*` headers do not reach the
   backend. Local tests are not evidence for this ingress property.

10. **Only then, enable `TRUST_EASYAUTH_HEADERS=true`** on the Container
    App's backend container (an app setting/env var update + new revision)
    and redeploy. See `docs/security/AUTHENTICATION.md` for exactly why this
    ordering matters and what stays unsafe before this step.

11. **Test authorization boundaries** against the live deployment: anonymous
    read access remains anonymous `VIEWER`; an approved Google principal in
    `GOOGLE_DASHBOARD_PRINCIPAL_IDS` becomes authenticated `VIEWER` but is
    denied `ANALYST` and `ADMIN` operations; an unapproved Google identity
    remains anonymous. Test `ADMIN` separately only if an explicitly approved
    principal has been added to `ADMIN_PRINCIPAL_IDS`.

12. **Create the GitHub `production` Environment** (see below) — a one-time
    manual GitHub Settings action.

13. **Configure the actual GitHub OIDC subject** (see below) — verify it,
    do not assume the classic format is correct.

14. **Enable GitHub CD** (`deploy-azure.yml`, `workflow_dispatch`) for all
    subsequent manual deployments — see "Running a deployment" below.

No real credentials, tenant IDs, or subscription IDs are recorded anywhere
in this document or the repository.

## GitHub setup (steps 12–13 above, in detail)

### Provision the federated credential — verify the subject first

`infra/azure/main.bicep` creates `id-aegisarena-github` (PASS 1 above), but
intentionally **does not** create the GitHub OIDC federated credential on it
— that binding must match the exact subject claim GitHub issues, which
depends on how this specific repository is configured and is not safe to
hardcode.

`.github/workflows/deploy-azure.yml`'s `deploy` job runs under
`environment: production` (a GitHub Environment, not a branch ref), so the
federated credential must use an **environment-context** subject, not a
branch-ref subject:

- The classic/legacy subject format for a GitHub Environment job
  conceptually resembles `repo:OWNER/REPO:environment:production`.
- **GitHub has introduced an immutable, ID-based OIDC subject format** on
  some repositories/organizations, which encodes owner/repository IDs
  rather than names and does **not** match the classic string above.
- **Verify this repository's actual emitted subject before creating
  anything in Azure** — e.g. by decoding a test OIDC token GitHub issues for
  a run of this workflow, or by consulting GitHub's current OIDC subject
  claim documentation for this repository/organization's configuration —
  rather than assuming either format.

Once verified, create the federated credential with the confirmed subject:

```bash
az identity federated-credential create \
  --name "github-oidc-deploy" \
  --identity-name "id-aegisarena-github" \
  --resource-group "rg-aegisarena-dev" \
  --issuer "https://token.actions.githubusercontent.com" \
  --subject "<VERIFIED-SUBJECT-FOR-THIS-REPO-AND-ENVIRONMENT>" \
  --audiences "api://AzureADTokenExchange"
```

No federated credential has been created as part of this phase — this is
documentation only, describing a manual step to run once the subject has
been verified.

### Validate the Bicep template with what-if before applying

Always preview changes before applying them, especially against a live
environment:

```bash
az deployment sub what-if \
  --location centralindia \
  --template-file infra/azure/main.bicep \
  --parameters infra/azure/parameters/dev.bicepparam
```

(`--location` here only names where the deployment *record* is stored, not
where resources land — that's controlled by the `location` param inside the
template, which already defaults to `centralindia`. Kept aligned to avoid
confusion when reading deployment history later.)

Review the plan output for unexpected deletions/replacements before running
an actual deployment.

### Set GitHub repository variables (non-secret identifiers)

Settings → Secrets and variables → Actions → Variables:

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | Client (application) ID of `id-aegisarena-github` |
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID |
| `ACR_NAME` | The **actual deployed** registry name — read it from PASS 1's `acrLoginServer` output (it is `acraegisarenadev` plus a short generated suffix, e.g. `acraegisarenadevab12`, stripped of the trailing `.azurecr.io`), not the bare `acraegisarenadev` base name |
| `TRUST_EASYAUTH_HEADERS` | `false` until Easy Auth is configured and verified; then `true` so later releases preserve the verified trust boundary |
| `AUTH_IDENTITY_DIAGNOSTIC_ENABLED` | `false` normally; temporarily `true` only while enrolling an approved Google identity using the existing Key Vault secret `auth-identity-diagnostic-key` |
| `ADMIN_PRINCIPAL_IDS_JSON` | JSON array of verified Entra principal object IDs granted ADMIN, for example `["00000000-0000-0000-0000-000000000000"]`; use `[]` before configuration |
| `GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON` | JSON array of verified Google stable principal IDs granted authenticated VIEWER dashboard access; use `[]` before enrollment |

These are identifiers, not credentials — there is no secret material in any
of them, which is why they are GitHub *variables* rather than *secrets*
(and why `deploy-azure.yml` reads them via `vars.*`).

### No GitHub secret is needed for normal releases

`PGADMIN_PASSWORD` is used **only** at manual bootstrap time (PASS 1/PASS 2
above, run directly with `az deployment sub create` on an operator's own
machine) — it seeds the Postgres admin account and the corresponding Key
Vault secret once. `infra/azure/app.bicep` (what `deploy-azure.yml` actually
runs) never touches PostgreSQL or writes Key Vault secrets, so it needs no
password at all. **`PGADMIN_PASSWORD` should never be added as a GitHub
Actions secret** — it has no use there, and not storing it in GitHub reduces
the number of places a sensitive value could ever leak from. Keep it only
wherever you generated/recorded it for the manual bootstrap (e.g. a local
password manager), not in this repository or its CI configuration.

### Create the GitHub `production` Environment (manual, one-time)

This cannot be done from a workflow file — it is a GitHub repository
settings action:

1. Settings → Environments → New environment → name it `production`.
2. Add a required reviewer (or other protection rule) if you want manual
   approval before `deploy-azure.yml`'s `deploy` job runs.
3. Environment-scoped variables/secrets can also be set here instead of at
   the repository level if you want the `production` Environment to be the
   only place these values live.

## Running a deployment (post-bootstrap only)

`deploy-azure.yml` is **manual-only** (`workflow_dispatch` — no push trigger
of any kind, per the user's explicit request to control Azure spending by
hand) and is for deployments **after** the manual bootstrap above has
already run. Trigger it via **Actions → Deploy Azure → Run workflow**,
optionally supplying an `image_tag` (defaults to the triggering commit SHA
if left blank). It will:

1. Authenticate to Azure via OIDC (no stored secret), as `id-aegisarena-github`
   (RG-scoped `Contributor` only — see the table above).
2. **Preflight-check** that `rg-aegisarena-dev` and the configured
   `ACR_NAME` registry already exist, failing immediately with a message
   pointing back to this document if they don't — it will not attempt to
   create first-time infrastructure.
3. `az acr login` and build+push the backend and frontend images, tagged
   both with the immutable SHA and `:latest` (SHA tag is what actually gets
   deployed).
4. Run `az deployment group create --resource-group rg-aegisarena-dev`
   against `infra/azure/app.bicep`, passing `acrName` (from the `ACR_NAME`
   variable) and `imageTag` — **not** `infra/azure/main.bicep`, and no
   `PGADMIN_PASSWORD`/Postgres involvement at all (see above). This only
   ever updates the Container App. It also passes the validated
   `TRUST_EASYAUTH_HEADERS` and `ADMIN_PRINCIPAL_IDS_JSON` Environment
   variables, whose secure fallbacks are `false` and `[]`.
5. Poll `/api/health/live` and `/api/health/ready` on the resulting
   Container App FQDN, retrying for cold starts, and fail the job if either
   check does not return 200 within the retry budget.

There is no automatic trigger on push to `develop` or any other branch —
every Azure deployment is an explicit, manual action.

### Enabling `trustEasyAuthHeaders=true` on a later release

Once Easy Auth has been configured and verified (steps 5–9 of the ordered
sequence above), subsequent releases can grant allowlisted Google VIEWER and
explicit ADMIN access, which requires `TRUST_EASYAUTH_HEADERS=true` on the Container App.
The workflow cannot determine whether Easy Auth has been verified, so its
secure fallback remains `false`. After verification, set these variables
on the protected GitHub `production` Environment:

- `TRUST_EASYAUTH_HEADERS=true`
- `GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON` to the JSON array of approved Google
  stable principal IDs
- `ADMIN_PRINCIPAL_IDS_JSON` to the JSON array of approved admin object IDs

Every subsequent manual workflow release then supplies both values to Bicep.
For a direct operator-run release, pass the same values explicitly:

```bash
az deployment group create \
  --resource-group rg-aegisarena-dev \
  --template-file infra/azure/app.bicep \
  --parameters acrName=<the deployed ACR name> \
  --parameters imageTag=<git-sha> \
  --parameters trustEasyAuthHeaders=true \
  --parameters googleDashboardPrincipalIds='["<verified-google-principal-id>"]' \
  --parameters adminPrincipalIds='["<verified-admin-object-id>"]'
```

Declarative infrastructure has no remembered parameter state: both values
must be supplied every time `app.bicep` is deployed. The protected Environment
variables make that persistence explicit while retaining safe defaults.

## Changes from the final hardening pass (2026-10-07)

None of these templates have been compiled or deployed from this workspace.
Run `az bicep build --file infra/azure/main.bicep` and the `what-if` step above
before the first bootstrap.

- **Key Vault name.** It is now `kv-aegis-<uniqueString(resourceGroup().id)>`,
  in both `modules/keyvault.bicep` and `app.bicep`. The previous fixed name
  `kv-aegisarena-dev` would collide globally, and also with its own soft-deleted
  copy after a teardown. `main.bicep` outputs the real name.
- **PostgreSQL connection string.** The login and password are now passed
  through `uriComponent()`, so a generated password containing `@`, `/` or `:`
  can no longer corrupt the `DATABASE_URL` stored in Key Vault.
- **Model artifact storage.** The new `modules/modelstorage.bicep` creates:
  - a Standard_LRS storage account, `staegis<uniqueString>`;
  - a 1 GiB `model-artifacts` file share;
  - a Container Apps environment storage named `modelartifacts`.

  The backend container mounts it at `/data` with
  `MODEL_ARTIFACT_DIR=/data/models`. Detection-model records live in
  PostgreSQL, while their joblib files live on this share. When a file is
  missing, the backend rebuilds it deterministically, so the share is for
  efficiency rather than correctness.
- **Same-origin frontend.** The frontend image is now built with empty
  `VITE_API_BASE_URL` and `VITE_WS_BASE_URL`, so the browser calls `/api/...` on
  the app's own origin. nginx then proxies to the backend sidecar, including
  the WebSocket upgrade for `/api/v1/ws/`. Previously the image baked in
  `http://localhost:8000`, which pointed every visitor's browser at their own
  machine.

The extra monthly cost of the storage account is negligible (a 1 GiB LRS share).
The other resources are unchanged; see `COST_CONTROL.md`.
