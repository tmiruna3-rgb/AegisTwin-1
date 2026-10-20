import hmac
from typing import Literal

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from pydantic import BaseModel

from app.core.auth import CurrentPrincipal, Role, read_easyauth_identity

router = APIRouter(prefix="/v1/session", tags=["session"])


class SessionView(BaseModel):
    role: Literal["VIEWER", "ANALYST", "ADMIN"]
    authenticated: bool
    auth_mode: Literal["development_bypass", "easy_auth", "anonymous"]
    environment: str
    can_operate: bool
    can_administer: bool


class HeaderProbeView(BaseModel):
    identity_headers_present: bool
    principal_header_present: bool
    principal_header_valid: bool
    principal_id_header_present: bool
    provider_header_present: bool
    provider_is_google: bool
    stable_principal_id_present: bool
    trust_enabled: bool
    google_principal_id: str | None


@router.get("/header-probe", response_model=HeaderProbeView)
def temporary_header_probe(
    request: Request,
    response: Response,
    diagnostic_key: str | None = Header(default=None, alias="X-Aegis-Identity-Diagnostic-Key"),
) -> HeaderProbeView:
    """TEMPORARY: inspect and enroll a Google Easy Auth identity.

    Disabled by default and hidden without the configured high-entropy key.
    A key-authorized operator receives the stable subject only for a complete,
    internally consistent Google identity. Response bodies are never logged by
    this code and are marked non-cacheable. Remove this endpoint and its two
    settings after enrollment.
    """

    settings = request.app.state.settings
    configured_key = settings.auth_identity_diagnostic_key
    if not settings.auth_identity_diagnostic_enabled or configured_key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    if diagnostic_key is None or not hmac.compare_digest(
        diagnostic_key, configured_key.get_secret_value()
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")

    identity = read_easyauth_identity(request)
    google_principal_id = identity.subject if identity.provider == "google" else None
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return HeaderProbeView(
        identity_headers_present=(
            identity.principal_header_present
            or identity.principal_id_header_present
            or identity.provider_header_present
        ),
        principal_header_present=identity.principal_header_present,
        principal_header_valid=identity.principal_header_valid,
        principal_id_header_present=identity.principal_id_header_present,
        provider_header_present=identity.provider_header_present,
        provider_is_google=identity.provider == "google",
        stable_principal_id_present=identity.subject is not None,
        trust_enabled=settings.trust_easyauth_headers,
        google_principal_id=google_principal_id,
    )


@router.get("", response_model=SessionView)
def current_session(principal: CurrentPrincipal, request: Request) -> SessionView:
    """The caller's effective role, so the UI can label and gate actions
    honestly instead of letting writes fail with 403."""

    if principal.subject == "dev-bypass":
        mode: Literal["development_bypass", "easy_auth", "anonymous"] = "development_bypass"
    elif principal.authenticated:
        mode = "easy_auth"
    else:
        mode = "anonymous"
    return SessionView(
        role=principal.role.name,
        authenticated=principal.authenticated,
        auth_mode=mode,
        environment=request.app.state.settings.environment,
        can_operate=principal.role >= Role.ANALYST,
        can_administer=principal.role >= Role.ADMIN,
    )
