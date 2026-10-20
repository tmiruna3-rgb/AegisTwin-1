# Authentication and Authorization Model

This document describes the identity and role model implemented in
`backend/app/core/auth.py`. For the full inventory of which routes require
which role, see `docs/security/AUTHORIZATION_MATRIX.md` (maintained
separately, alongside `auth.py` itself) — this document covers the trust
model and role semantics, not the per-route enumeration.

## Trust model: `TRUST_EASYAUTH_HEADERS` gates Easy Auth headers, defaulting to false

`backend/app/core/auth.py`'s `resolve_principal` can derive the caller's
identity from `X-MS-CLIENT-PRINCIPAL-ID`, or from the stable subject claim in
the encoded `X-MS-CLIENT-PRINCIPAL` header when Azure omits that convenience
header. It uses `X-MS-CLIENT-PRINCIPAL-IDP` (with the encoded principal's
`auth_typ` as a fallback) to identify the provider. These values affect access
**only when
`Settings.trust_easyauth_headers` is explicitly `True`**
(`TRUST_EASYAUTH_HEADERS` env var). This defaults to `False` everywhere,
including production, and is a completely separate switch from
`ENVIRONMENT=production`.

This exists because the Bicep in this phase (`infra/azure/main.bicep`)
provisions the Container App **without** configuring Azure Container Apps
Easy Auth — the actual Microsoft Entra application registration is a manual
step performed during hosting (see "Manual hosting sequence" below), after
the Container App already exists. Between the Container App being created
and an operator manually finishing that Easy Auth setup, there is a window
where the backend would otherwise be reachable without any real
authentication proxy in front of it. Trusting `X-MS-CLIENT-PRINCIPAL*`
headers unconditionally during that window would let any caller who can
reach the backend forge those headers directly and grant themselves
ANALYST or ADMIN. `TRUST_EASYAUTH_HEADERS=false` closes that window: the
headers are ignored outright, so the caller falls through to, at most,
anonymous VIEWER (or `401` if `ALLOW_ANONYMOUS_VIEWER=false`) — see
`backend/tests/test_authorization.py`'s
`test_production_default_trust_false_spoofed_header_stays_viewer` and
`test_trust_false_and_anonymous_disabled_ignores_header_and_401s` for the
exact proof.

**`TRUST_EASYAUTH_HEADERS=true` is safe only once, and only after**, the
following deployment assumption is actually true — not assumed, verified:

> The backend container is never independently, publicly reachable. It is
> reachable exclusively through the frontend nginx sidecar inside the same
> Container App (see `frontend/nginx.conf.template`, `frontend/Dockerfile`),
> and, above that, through Azure Container Apps ingress with Easy Auth
> (Entra ID authentication) genuinely configured and enabled. Azure
> Container Apps' built-in authentication middleware is what actually
> authenticates the caller and sets these `X-MS-CLIENT-PRINCIPAL*` headers
> on the request before it ever reaches nginx or the FastAPI app — it
> strips/overwrites any such header an external caller tries to forge.

**Manual hosting sequence** (see `docs/deployment/AZURE_DEPLOYMENT.md` for
the full ordered command sequence, including bootstrap):

1. Deploy the Container App (with `TRUST_EASYAUTH_HEADERS` left at its
   default `false` — Bicep never sets it to `true`).
2. Create/configure the Microsoft Entra application registration and enable
   Container Apps Easy Auth on the running Container App, keeping
   unauthenticated access allowed (so public VIEWER behavior still works).
3. Verify authentication actually works end-to-end — e.g. hit
   `/.auth/login/aad`, confirm a real sign-in flow, and confirm the
   `X-MS-CLIENT-PRINCIPAL*` headers the backend receives are genuinely
   Easy-Auth-issued (not forgeable by a direct caller).
4. **Only then** set `TRUST_EASYAUTH_HEADERS=true` on the Container App and
   redeploy/update the revision.
5. Re-test VIEWER (anonymous), ANALYST (authenticated), and ADMIN
   (configured principal ID) behavior against the live deployment.

If this assumption is ever broken later — for example, by exposing the
backend container's port directly on a public ingress rule, or by disabling
Easy Auth on the Container App after having set `TRUST_EASYAUTH_HEADERS=true`
— the header-based trust model becomes forgeable again. Setting
`TRUST_EASYAUTH_HEADERS` back to `false` immediately restores the safe
fallback (anonymous VIEWER / 401) without any code change.
`docs/deployment/AZURE_ARCHITECTURE.md` documents the network topology this
relies on; any change to that topology must re-examine this assumption
explicitly, not incidentally.

## Roles

`Role` in `backend/app/core/auth.py` is an ordered `IntEnum`
(`VIEWER < ANALYST < ADMIN`); `require_role(minimum)` denies (403) any
caller whose role is below `minimum`.

| Role | How it is granted |
|---|---|
| `VIEWER` | Default for anonymous (unauthenticated) requests, when `ALLOW_ANONYMOUS_VIEWER=true` (the default). No principal header required, regardless of `TRUST_EASYAUTH_HEADERS`. |
| `ANALYST` | Not granted by the current Google dashboard flow. Authentication alone never grants operation privileges. |
| `ADMIN` | **Only when `TRUST_EASYAUTH_HEADERS=true`**: an authenticated principal whose stable ID appears in `ADMIN_PRINCIPAL_IDS`. Also ignored entirely when `TRUST_EASYAUTH_HEADERS=false`. |

An authenticated Google identity receives authenticated `VIEWER` access only
when its stable ID is explicitly present in `GOOGLE_DASHBOARD_PRINCIPAL_IDS`.
An unlisted Google identity stays anonymous, and an approved Google viewer
still cannot call `ANALYST` or `ADMIN` routes.

## Temporary Google identity enrollment diagnostic

`GET /api/v1/session/header-probe` is a temporary, disabled-by-default
diagnostic for the post-deployment verification phase. It is hidden with 404
unless both of these settings are supplied:

- `AUTH_IDENTITY_DIAGNOSTIC_ENABLED=true`
- `AUTH_IDENTITY_DIAGNOSTIC_KEY=<high-entropy one-time value>`

The caller must send the key in `X-Aegis-Identity-Diagnostic-Key`. The HTTP
response reports header presence, decoded-principal validity, whether the
provider is Google, whether a stable subject was found, and whether header
trust is currently enabled. Only a key-authorized request carrying a complete,
consistent Google identity receives `google_principal_id`; unauthorized callers
receive only 404. The response is marked `Cache-Control: no-store`. Claims,
email addresses, cookies, tokens, and diagnostic keys are never returned, and
the principal ID is never written to application logs.

Use the diagnostic in this order:

1. Leave `TRUST_EASYAUTH_HEADERS=false` and the Google allowlist empty.
2. Generate a one-time random key of at least 32 characters. Store it as
   `auth-identity-diagnostic-key` in the existing Key Vault, then set the
   protected GitHub `production` Environment variable
   `AUTH_IDENTITY_DIAGNOSTIC_ENABLED=true`. The Bicep release template exposes
   it to the backend only through a Key Vault-backed Container App secret
   reference; the value never enters GitHub Actions or a Bicep parameter.
3. From an unauthenticated client, send forged `X-MS-CLIENT-PRINCIPAL*`
   headers plus the diagnostic key. All identity presence flags must be false.
   This is the live ingress-sanitization check; local tests cannot prove it.
4. Sign in with the approved Google account. In that same browser session,
   call the endpoint with the one-time key in
   `X-Aegis-Identity-Diagnostic-Key`. Require
   `principal_header_valid=true`, `provider_is_google=true`, and
   `stable_principal_id_present=true`.
5. Copy the returned `google_principal_id` directly into the protected
   `GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON` GitHub Environment variable. Do not
   paste it into tickets, chat, ordinary logs, or command history.
6. Add only that ID to the allowlist. After the forged-header
   check has passed, set `TRUST_EASYAUTH_HEADERS=true` in the same controlled
   release. Do not put the ID in `ADMIN_PRINCIPAL_IDS` unless separate admin
   approval is intended.
7. Verify the account receives authenticated `VIEWER` access and receives 403
   from representative `ANALYST` and `ADMIN` operations.
8. Immediately set `AUTH_IDENTITY_DIAGNOSTIC_ENABLED=false`, deploy that
   disabled state, delete the one-time Key Vault secret, clear browser console
   history, and remove
   `temporary_header_probe`, `HeaderProbeView`, and the two diagnostic settings
   from the next code release.

If `ALLOW_ANONYMOUS_VIEWER=false` and no principal header resolves to a role
(either because none was sent, or because `TRUST_EASYAUTH_HEADERS=false`
caused it to be ignored), the request is rejected with `401 Unauthorized`
rather than being treated as `VIEWER`.

## Development bypass: `AUTH_DEV_BYPASS_ROLE`

For local development, `AUTH_DEV_BYPASS_ROLE` (one of `VIEWER`, `ANALYST`,
`ADMIN`) makes every request resolve to that role unconditionally, without
needing Easy Auth headers at all — see `resolve_principal`'s first branch.
This is strictly a development convenience.

It is hard-blocked in production by two independent checks so a
misconfiguration cannot silently ship:

1. A pydantic validator on `Settings` in `backend/app/core/config.py`
   (`model_post_init`) raises at settings-construction time if
   `environment == "production"` and `auth_dev_bypass_role` is set.
2. `backend/app/main.py`'s `ensure_production_auth_safe`, called during
   application startup (`lifespan`), performs the same check again and
   raises a `ConfigurationError` that prevents the app from starting.

Both checks exist so the failure mode is "the application refuses to start"
rather than "the bypass silently activates in production."

### Where the bypass is set (and where it is not)

- `backend/.env.example` documents `AUTH_DEV_BYPASS_ROLE=ADMIN` for a local
  `backend/.env`. Without it, a local backend serves anonymous `VIEWER` only and
  every Blue Agent action (approve, execute, verify, rollback, autonomy change)
  returns `403`.
- The one-click demo launcher (`scripts/demo/start_aegistwin_demo.ps1`),
  `backend/launch.env` and the Playwright test backend set `ADMIN` explicitly
  and run with `AEGISARENA_DISABLE_DOTENV=1`, so a developer's own `.env` can
  never leak into them.
- The bypass warning is logged once per role (not per request).
- `docker-compose.prod.yml` and the Azure Bicep never set it;
  `backend/tests/test_deployment_config.py` pins that for the production compose.

## Session endpoint: `GET /api/v1/session`

Returns the caller's resolved principal so the UI can show it and disable
controls the caller may not use:

```json
{ "role": "ADMIN", "authenticated": true, "auth_mode": "development_bypass",
  "environment": "development", "can_operate": true, "can_administer": true }
```

The header shows the role (with a "dev" marker in bypass mode). The UI only
hides or disables controls for convenience. Authorisation is still enforced
server-side on every route.
