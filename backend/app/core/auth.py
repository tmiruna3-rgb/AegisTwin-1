"""Role-based access control for AegisArena.

Trust boundary: identity headers (``X-MS-CLIENT-PRINCIPAL*``) are only ever
consulted when ``Settings.trust_easyauth_headers`` is explicitly ``True`` —
which defaults to ``False`` everywhere, including production. That flag must
only be flipped on, manually, after an operator has configured Azure
Container Apps Easy Auth on the deployed Container App and verified it
genuinely strips/overwrites any externally-supplied X-MS-CLIENT-PRINCIPAL*
value before it reaches this backend. See docs/security/AUTHENTICATION.md
for the full manual hosting sequence this relies on. Until then, every
caller resolves to, at most, anonymous VIEWER — headers are never trusted as
a substitute for a verified proxy.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status

from app.core.config import Settings

logger = logging.getLogger(__name__)
_bypass_warned: set[str] = set()


class Role(IntEnum):
    """Ordered least-to-most privileged. Comparisons rely on ordering."""

    VIEWER = 0
    ANALYST = 1
    ADMIN = 2

    @classmethod
    def from_str(cls, value: str) -> Role:
        return cls[value.upper()]


@dataclass(frozen=True)
class Principal:
    role: Role
    subject: str | None
    authenticated: bool


def _decode_client_principal(header_value: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(header_value, validate=True)
        parsed = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        logger.warning("Failed to decode X-MS-CLIENT-PRINCIPAL header; ignoring claims")
        return {}
    return parsed if isinstance(parsed, dict) else {}


def resolve_principal(request: Request, settings: Settings) -> Principal:
    if settings.environment != "production" and settings.auth_dev_bypass_role:
        role = Role.from_str(settings.auth_dev_bypass_role)
        if role.name not in _bypass_warned:
            # Logged once per process and role rather than on every request.
            _bypass_warned.add(role.name)
            logger.warning(
                "AUTH_DEV_BYPASS_ROLE=%s is active - every request is treated as this role. "
                "This must never be set in production.",
                role.name,
            )
        return Principal(role=role, subject="dev-bypass", authenticated=True)

    # Identity headers are only meaningful once Easy Auth is genuinely
    # configured and verified to strip/overwrite any externally-supplied
    # X-MS-CLIENT-PRINCIPAL* value (see docs/security/AUTHENTICATION.md).
    # Until an operator has done that and explicitly flipped this setting,
    # these headers MUST be ignored entirely — a caller supplying them
    # directly (there is no Easy Auth in front yet) must not be able to
    # spoof ANALYST/ADMIN.
    if settings.trust_easyauth_headers:
        principal_id = request.headers.get("X-MS-CLIENT-PRINCIPAL-ID")
        principal_header = request.headers.get("X-MS-CLIENT-PRINCIPAL")
        principal_provider = request.headers.get("X-MS-CLIENT-PRINCIPAL-IDP", "").lower()

        if principal_id:
            # Header content is decoded for future claim-based use (e.g.
            # name/roles claims) but role is currently derived solely from
            # the verified principal id against the configured admin
            # allow-list.
            if principal_header:
                _decode_client_principal(principal_header)
            if principal_id in settings.admin_principal_ids:
                role = Role.ADMIN
            elif principal_provider == "google" and principal_id in settings.google_dashboard_principal_ids:
                role = Role.VIEWER
            else:
                role = None

            if role is not None:
                return Principal(role=role, subject=principal_id, authenticated=True)

    if settings.allow_anonymous_viewer:
        return Principal(role=Role.VIEWER, subject=None, authenticated=False)

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")


def get_current_principal(request: Request) -> Principal:
    # Reads request.app.state.settings (the instance the running app was
    # built with via create_app), matching the pattern used by
    # get_database_session, rather than the module-level get_settings()
    # cache — so tests/deployments that construct an app with explicit
    # Settings (see backend/tests/conftest.py) get consistent auth behavior.
    settings: Settings = request.app.state.settings
    return resolve_principal(request, settings)


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_role(minimum: Role) -> Any:
    """Dependency factory: 403s if the caller's role is below ``minimum``."""

    def _dependency(principal: CurrentPrincipal) -> Principal:
        if principal.role < minimum:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"This action requires {minimum.name} role or higher",
            )
        return principal

    return Depends(_dependency)


RequireViewer = require_role(Role.VIEWER)
RequireAnalyst = require_role(Role.ANALYST)
RequireAdmin = require_role(Role.ADMIN)
