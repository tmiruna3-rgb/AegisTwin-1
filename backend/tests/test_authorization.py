"""Authorization (RBAC) tests for the routes wired up in app.core.auth.

These tests exercise the real dependency-injection wiring end to end
through the FastAPI TestClient, rather than unit-testing app.core.auth in
isolation, so a mistake in how a route wires ``RequireViewer`` /
``RequireAnalyst`` / ``RequireAdmin`` would actually be caught here.

Representative routes used below:
- VIEWER read-only: GET /api/v1/topology (no DB fixture required, public).
- ANALYST-tier mutation: POST /api/v1/simulation/runs (self-contained -
  scenarios are static/in-memory, so no other fixture data is needed).
- ADMIN-tier mutation: PUT /api/v1/autonomy with mode=autonomous (also
  self-contained - the autonomy config is a lazily-created singleton row).

``get_current_principal`` resolves its ``Settings`` via
``request.app.state.settings`` (the instance the app was constructed with),
matching ``get_database_session``'s pattern. Tests that need a non-default
auth configuration (admin allow-list, dev bypass, anonymous disabled,
``TRUST_EASYAUTH_HEADERS``, etc.) therefore build their own app instance
with the desired ``Settings`` via a local helper rather than overriding a
dependency.

``TRUST_EASYAUTH_HEADERS`` defaults to ``False`` everywhere (including the
default ``client``/``settings`` fixtures below) — X-MS-CLIENT-PRINCIPAL*
headers are only consulted when a test explicitly sets it ``True``, mirroring
production's fail-safe default before Easy Auth is manually configured and
verified (see docs/security/AUTHENTICATION.md).
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.database.base import Base
from app.main import create_app
from app.services.model_artifact_service import model_artifact_service

PRINCIPAL_ID_HEADER = "X-MS-CLIENT-PRINCIPAL-ID"
PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL"


@pytest.fixture(autouse=True)
def isolate_model_cache() -> Generator[None, None, None]:
    model_artifact_service.clear_cache()
    yield
    model_artifact_service.clear_cache()


def _base_settings_kwargs(tmp_path: Path) -> dict[str, Any]:
    return {
        "_env_file": None,
        "DATABASE_URL": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        "DEBUG": False,
        "MODEL_ARTIFACT_DIR": tmp_path / "artifacts",
    }


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(**_base_settings_kwargs(tmp_path))


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        application = cast(FastAPI, test_client.app)
        Base.metadata.create_all(application.state.database.engine)
        yield test_client


def _client_with_settings(overridden: Settings) -> Generator[TestClient, None, None]:
    application = create_app(overridden)
    with TestClient(application) as test_client:
        Base.metadata.create_all(application.state.database.engine)
        yield test_client


def _run_create_payload() -> dict[str, Any]:
    return {
        "scenario_id": "normal-operations",
        "seed": 1,
        "start_time": "2026-01-01T00:00:00+00:00",
        "playback_speed": 1.0,
    }


def _autonomy_autonomous_payload(updated_by: str) -> dict[str, Any]:
    return {"mode": "autonomous", "updated_by": updated_by, "confirm": True}


# ---------------------------------------------------------------------
# 1. VIEWER (anonymous) can read a representative read-only route
# ---------------------------------------------------------------------


def test_anonymous_viewer_can_read_topology(client: TestClient) -> None:
    response = client.get("/api/v1/topology")
    assert response.status_code == 200


# ---------------------------------------------------------------------
# 2. VIEWER (anonymous) is denied a representative ANALYST-tier route
# ---------------------------------------------------------------------


def test_anonymous_viewer_denied_analyst_route(client: TestClient) -> None:
    response = client.post("/api/v1/simulation/runs", json=_run_create_payload())
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------
# 3. TRUST_EASYAUTH_HEADERS: default-false spoofing protection, and the
#    trust=true behavior these headers are designed for once an operator
#    has actually verified Easy Auth is in front of the backend.
# ---------------------------------------------------------------------


def test_default_trust_false_spoofed_header_does_not_grant_analyst(client: TestClient) -> None:
    # The shared `client` fixture uses default Settings: trust_easyauth_headers
    # is False by default. A caller supplying the header directly (there is
    # no Easy Auth in front in this test) must NOT be granted ANALYST.
    response = client.post(
        "/api/v1/simulation/runs",
        json=_run_create_payload(),
        headers={PRINCIPAL_ID_HEADER: "attacker-spoofed-id"},
    )
    assert response.status_code in (401, 403)


def test_production_default_trust_false_spoofed_header_stays_viewer(tmp_path: Path) -> None:
    # Same as above, but explicitly in ENVIRONMENT=production with no
    # TRUST_EASYAUTH_HEADERS override — the exact pre-Easy-Auth production
    # posture. A spoofed admin-looking header must not grant ADMIN either.
    prod_settings = Settings(
        **_base_settings_kwargs(tmp_path),
        ENVIRONMENT="production",
        ADMIN_PRINCIPAL_IDS=["admin-1"],
    )
    for client in _client_with_settings(prod_settings):
        response = client.put(
            "/api/v1/autonomy",
            json=_autonomy_autonomous_payload("admin-1"),
            headers={PRINCIPAL_ID_HEADER: "admin-1"},
        )
        assert response.status_code == 403
        # The read-only VIEWER route still works — anonymous VIEWER access
        # is unaffected by the header being ignored.
        assert client.get("/api/v1/topology").status_code == 200


def test_trust_true_unapproved_principal_cannot_operate(tmp_path: Path) -> None:
    trusting_settings = Settings(**_base_settings_kwargs(tmp_path), TRUST_EASYAUTH_HEADERS=True)
    for client in _client_with_settings(trusting_settings):
        response = client.post(
            "/api/v1/simulation/runs",
            json=_run_create_payload(),
            headers={PRINCIPAL_ID_HEADER: "analyst-1"},
        )
        assert response.status_code == 403


def test_approved_google_user_is_authenticated_viewer(tmp_path: Path) -> None:
    settings = Settings(
        **_base_settings_kwargs(tmp_path),
        TRUST_EASYAUTH_HEADERS=True,
        GOOGLE_DASHBOARD_PRINCIPAL_IDS=["google-user-1"],
    )
    for client in _client_with_settings(settings):
        response = client.get(
            "/api/v1/session",
            headers={PRINCIPAL_ID_HEADER: "google-user-1", "X-MS-CLIENT-PRINCIPAL-IDP": "google"},
        )
        assert response.status_code == 200
        assert response.json()["authenticated"] is True
        assert response.json()["role"] == "VIEWER"
        assert response.json()["can_operate"] is False

        operation = client.post(
            "/api/v1/simulation/runs",
            json=_run_create_payload(),
            headers={PRINCIPAL_ID_HEADER: "google-user-1", "X-MS-CLIENT-PRINCIPAL-IDP": "google"},
        )
        assert operation.status_code == 403


def test_approved_id_with_wrong_provider_is_rejected(tmp_path: Path) -> None:
    settings = Settings(
        **_base_settings_kwargs(tmp_path),
        TRUST_EASYAUTH_HEADERS=True,
        GOOGLE_DASHBOARD_PRINCIPAL_IDS=["google-user-1"],
    )
    for client in _client_with_settings(settings):
        response = client.get(
            "/api/v1/session",
            headers={
                PRINCIPAL_ID_HEADER: "google-user-1",
                "X-MS-CLIENT-PRINCIPAL-IDP": "aad",
            },
        )
        assert response.status_code == 200
        assert response.json()["authenticated"] is False
        assert response.json()["can_operate"] is False

def test_unapproved_google_user_remains_anonymous(tmp_path: Path) -> None:
    settings = Settings(
        **_base_settings_kwargs(tmp_path),
        TRUST_EASYAUTH_HEADERS=True,
        GOOGLE_DASHBOARD_PRINCIPAL_IDS=["google-user-1"],
    )
    for client in _client_with_settings(settings):
        response = client.get(
            "/api/v1/session",
            headers={PRINCIPAL_ID_HEADER: "unknown-google-user", "X-MS-CLIENT-PRINCIPAL-IDP": "google"},
        )
        assert response.status_code == 200
        assert response.json()["authenticated"] is False
        assert response.json()["can_operate"] is False

def test_trust_true_analyst_denied_admin_route(tmp_path: Path) -> None:
    trusting_settings = Settings(**_base_settings_kwargs(tmp_path), TRUST_EASYAUTH_HEADERS=True)
    for client in _client_with_settings(trusting_settings):
        response = client.put(
            "/api/v1/autonomy",
            json=_autonomy_autonomous_payload("analyst-1"),
            headers={PRINCIPAL_ID_HEADER: "analyst-1"},
        )
        assert response.status_code == 403


def test_trust_true_configured_admin_principal_grants_admin(tmp_path: Path) -> None:
    admin_settings = Settings(
        **_base_settings_kwargs(tmp_path),
        TRUST_EASYAUTH_HEADERS=True,
        ADMIN_PRINCIPAL_IDS=["admin-1"],
    )
    for client in _client_with_settings(admin_settings):
        response = client.put(
            "/api/v1/autonomy",
            json=_autonomy_autonomous_payload("admin-1"),
            headers={PRINCIPAL_ID_HEADER: "admin-1"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "autonomous"


def test_trust_true_non_admin_principal_id_is_analyst_not_admin(tmp_path: Path) -> None:
    admin_settings = Settings(
        **_base_settings_kwargs(tmp_path),
        TRUST_EASYAUTH_HEADERS=True,
        ADMIN_PRINCIPAL_IDS=["admin-1"],
    )
    for client in _client_with_settings(admin_settings):
        response = client.put(
            "/api/v1/autonomy",
            json=_autonomy_autonomous_payload("analyst-2"),
            headers={PRINCIPAL_ID_HEADER: "analyst-2"},
        )
        assert response.status_code == 403


def test_trust_false_and_anonymous_disabled_ignores_header_and_401s(tmp_path: Path) -> None:
    # trust=false + ALLOW_ANONYMOUS_VIEWER=false: even a spoofed principal
    # header must not authenticate the caller — the result is 401, not a
    # silently-granted ANALYST/VIEWER.
    locked_down_settings = Settings(
        **_base_settings_kwargs(tmp_path),
        ALLOW_ANONYMOUS_VIEWER=False,
    )
    for client in _client_with_settings(locked_down_settings):
        response = client.get(
            "/api/v1/topology",
            headers={PRINCIPAL_ID_HEADER: "attacker-spoofed-id"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------
# 4. Missing/invalid principal header combinations behave safely
# ---------------------------------------------------------------------


def test_principal_header_without_id_falls_back_to_anonymous_viewer(client: TestClient) -> None:
    # X-MS-CLIENT-PRINCIPAL present but no X-MS-CLIENT-PRINCIPAL-ID: must not
    # crash, and must resolve to anonymous VIEWER (not authenticated).
    response = client.get(
        "/api/v1/topology",
        headers={PRINCIPAL_HEADER: "eyJub3QiOiJhIHJlYWwgcHJpbmNpcGFsIn0="},
    )
    assert response.status_code == 200


def test_malformed_principal_header_does_not_crash(tmp_path: Path) -> None:
    # X-MS-CLIENT-PRINCIPAL-ID present alongside an X-MS-CLIENT-PRINCIPAL
    # value that is not valid base64/JSON: decoding failure must be
    # swallowed (logged, ignored) rather than raising/500ing. Requires
    # TRUST_EASYAUTH_HEADERS=True to exercise the decode path at all — with
    # the default False, the header is ignored outright regardless of its
    # validity, which is covered separately above.
    trusting_settings = Settings(**_base_settings_kwargs(tmp_path), TRUST_EASYAUTH_HEADERS=True)
    for client in _client_with_settings(trusting_settings):
        response = client.post(
            "/api/v1/simulation/runs",
            json=_run_create_payload(),
            headers={
                PRINCIPAL_ID_HEADER: "analyst-3",
                PRINCIPAL_HEADER: "not-valid-base64!!!",
            },
        )
        assert response.status_code == 403


def test_no_headers_and_anonymous_disabled_requires_authentication(tmp_path: Path) -> None:
    no_anonymous_settings = Settings(
        **_base_settings_kwargs(tmp_path), ALLOW_ANONYMOUS_VIEWER=False
    )
    for client in _client_with_settings(no_anonymous_settings):
        response = client.get("/api/v1/topology")
        assert response.status_code == 401


# ---------------------------------------------------------------------
# 5. AUTH_DEV_BYPASS_ROLE
# ---------------------------------------------------------------------


def test_dev_bypass_role_admin_grants_admin_without_headers(tmp_path: Path) -> None:
    bypass_settings = Settings(
        **_base_settings_kwargs(tmp_path),
        ENVIRONMENT="development",
        AUTH_DEV_BYPASS_ROLE="ADMIN",
    )
    for client in _client_with_settings(bypass_settings):
        response = client.put("/api/v1/autonomy", json=_autonomy_autonomous_payload("dev-bypass"))
        assert response.status_code == 200


def test_dev_bypass_role_rejected_in_production_settings() -> None:
    with pytest.raises(ValidationError):  # wraps the ValueError from model_post_init
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            AUTH_DEV_BYPASS_ROLE="ADMIN",
        )
