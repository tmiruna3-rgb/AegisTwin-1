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


@dataclass(frozen=True)
class EasyAuthIdentity:
    """Identity material asserted by a verified Easy Auth boundary."""

    provider: str | None
    subject: str | None
    principal_header_present: bool
    principal_header_valid: bool
    principal_id_header_present: bool
    provider_header_present: bool


_SUBJECT_CLAIM_TYPES = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
    "sub",
)


def _decode_client_principal(header_value: str) -> dict[str, Any] | None:
    try:
        decoded = base64.b64decode(header_value, validate=True)
        parsed = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        logger.warning("Failed to decode X-MS-CLIENT-PRINCIPAL header; ignoring claims")
        return None
    if not isinstance(parsed, dict):
        logger.warning("X-MS-CLIENT-PRINCIPAL did not contain a JSON object; ignoring claims")
        return None
    return parsed


def _normalise_nonempty_string(value: object, *, lowercase: bool = False) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    return value.lower() if lowercase else value


def _subject_claim(principal: dict[str, Any]) -> tuple[str | None, bool]:
    claims = principal.get("claims")
    if not isinstance(claims, list):
        return None, False

    subjects: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            return None, False
        if claim.get("typ") not in _SUBJECT_CLAIM_TYPES:
            continue
        value = _normalise_nonempty_string(claim.get("val"))
        if value is None:
            return None, False
        subjects.add(value)

    if len(subjects) > 1:
        return None, False
    return (next(iter(subjects)) if subjects else None), True


def read_easyauth_identity(request: Request) -> EasyAuthIdentity:
    """Read identity headers without deciding whether the app trusts them.

    Container Apps documents the encoded ``X-MS-CLIENT-PRINCIPAL`` claims as
    the portable identity representation. Some provider/platform combinations
    omit the convenience ``X-MS-CLIENT-PRINCIPAL-ID`` header, so the stable
    subject claim is used as a fallback. Conflicting duplicate assertions fail
    closed instead of choosing one silently.
    """

    principal_id_header = request.headers.get("X-MS-CLIENT-PRINCIPAL-ID")
    principal_header = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    provider_header = request.headers.get("X-MS-CLIENT-PRINCIPAL-IDP")
    principal_id = _normalise_nonempty_string(principal_id_header)
    header_provider = _normalise_nonempty_string(provider_header, lowercase=True)

    decoded = _decode_client_principal(principal_header) if principal_header is not None else None
    decoded_provider: str | None = None
    claim_subject: str | None = None
    principal_header_valid = False
    if decoded is not None:
        decoded_provider = _normalise_nonempty_string(decoded.get("auth_typ"), lowercase=True)
        claim_subject, claims_valid = _subject_claim(decoded)
        principal_header_valid = decoded_provider is not None and claims_valid

    malformed_assertion = bool(
        (principal_header is not None and not principal_header_valid)
        or (principal_id_header is not None and principal_id is None)
        or (provider_header is not None and header_provider is None)
    )
    provider_conflict = bool(
        header_provider and decoded_provider and header_provider != decoded_provider
    )
    subject_conflict = bool(principal_id and claim_subject and principal_id != claim_subject)
    provider = header_provider or decoded_provider
    subject = principal_id or claim_subject
    identity_invalid = (
        malformed_assertion or provider_conflict or subject_conflict or provider is None
    )

    return EasyAuthIdentity(
        provider=None if identity_invalid else provider,
        subject=None if identity_invalid else subject,
        principal_header_present=principal_header is not None,
        principal_header_valid=principal_header_valid,
        principal_id_header_present=principal_id_header is not None,
        provider_header_present=provider_header is not None,
    )


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
        identity = read_easyauth_identity(request)

        if identity.subject:
            if identity.subject in settings.admin_principal_ids:
                resolved_role: Role | None = Role.ADMIN
            elif (
                identity.provider == "google"
                and identity.subject in settings.google_dashboard_principal_ids
            ):
                resolved_role = Role.VIEWER
            else:
                resolved_role = None

            if resolved_role is not None:
                return Principal(role=resolved_role, subject=identity.subject, authenticated=True)

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
