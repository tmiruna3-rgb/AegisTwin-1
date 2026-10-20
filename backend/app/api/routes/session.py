from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.core.auth import CurrentPrincipal, Role

router = APIRouter(prefix="/v1/session", tags=["session"])


class SessionView(BaseModel):
    role: Literal["VIEWER", "ANALYST", "ADMIN"]
    authenticated: bool
    auth_mode: Literal["development_bypass", "easy_auth", "anonymous"]
    environment: str
    can_operate: bool
    can_administer: bool


@router.get("/header-probe")
def temporary_header_probe(request: Request) -> dict[str, bool]:
    """TEMPORARY: Verify that Azure strips forged identity headers.

    Remove this endpoint immediately after the controlled deployment test.
    Never return real principal IDs, cookies, or tokens.
    """
    return {
        "forged_id_reached_backend": (
            request.headers.get("X-MS-CLIENT-PRINCIPAL-ID")
            == "fake-google-user"
        ),
        "forged_provider_reached_backend": (
            request.headers.get("X-MS-CLIENT-PRINCIPAL-IDP")
            == "google"
        ),
    }

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
