from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.exceptions import ConfigurationError
from app.main import create_app, ensure_production_auth_safe

DIAGNOSTIC_KEY = "test-only-diagnostic-key-32-bytes"


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    values: dict[str, object] = {
        "DATABASE_URL": f"sqlite:///{(tmp_path / 's.db').as_posix()}",
        "MODEL_ARTIFACT_DIR": tmp_path / "artifacts",
    }
    values.update(overrides)
    return TestClient(create_app(Settings(_env_file=None, **values)))  # type: ignore[arg-type]


def test_session_reports_development_bypass_role(tmp_path: Path) -> None:
    with _client(tmp_path, AUTH_DEV_BYPASS_ROLE="ADMIN", ENVIRONMENT="demo") as client:
        body = client.get("/api/v1/session").json()
    assert body == {
        "role": "ADMIN",
        "authenticated": True,
        "auth_mode": "development_bypass",
        "environment": "demo",
        "can_operate": True,
        "can_administer": True,
    }


def test_session_reports_anonymous_viewer_without_bypass(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        body = client.get("/api/v1/session").json()
        write = client.post(
            "/api/v1/simulation/runs",
            json={
                "scenario_id": "normal-operations",
                "seed": 1,
                "start_time": "2026-01-01T00:00:00Z",
            },
        )
    assert body["role"] == "VIEWER"
    assert body["auth_mode"] == "anonymous"
    assert body["can_operate"] is False
    assert write.status_code == 403


def test_header_probe_is_hidden_by_default(tmp_path: Path) -> None:
    raw_id = "must-not-be-disclosed"
    with _client(tmp_path) as client:
        response = client.get(
            "/api/v1/session/header-probe",
            headers={
                "X-Aegis-Identity-Diagnostic-Key": DIAGNOSTIC_KEY,
                "X-MS-CLIENT-PRINCIPAL-ID": raw_id,
                "X-MS-CLIENT-PRINCIPAL-IDP": "google",
            },
        )
    assert response.status_code == 404
    assert raw_id not in response.text


def test_header_probe_requires_operator_key(tmp_path: Path) -> None:
    raw_id = "must-not-be-disclosed"
    with _client(
        tmp_path,
        AUTH_IDENTITY_DIAGNOSTIC_ENABLED=True,
        AUTH_IDENTITY_DIAGNOSTIC_KEY=DIAGNOSTIC_KEY,
    ) as client:
        response = client.get(
            "/api/v1/session/header-probe",
            headers={
                "X-Aegis-Identity-Diagnostic-Key": "wrong-key",
                "X-MS-CLIENT-PRINCIPAL-ID": raw_id,
                "X-MS-CLIENT-PRINCIPAL-IDP": "google",
            },
        )
    assert response.status_code == 404
    assert raw_id not in response.text


def test_header_probe_returns_google_identity_only_to_key_authorized_operator(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw_id = "private-google-subject"
    principal = base64.b64encode(
        json.dumps(
            {
                "auth_typ": "google",
                "claims": [{"typ": "sub", "val": raw_id}],
            }
        ).encode()
    ).decode()
    with _client(
        tmp_path,
        AUTH_IDENTITY_DIAGNOSTIC_ENABLED=True,
        AUTH_IDENTITY_DIAGNOSTIC_KEY=DIAGNOSTIC_KEY,
        ENVIRONMENT="production",
    ) as client:
        response = client.get(
            "/api/v1/session/header-probe",
            headers={
                "X-Aegis-Identity-Diagnostic-Key": DIAGNOSTIC_KEY,
                "X-MS-CLIENT-PRINCIPAL": principal,
                "X-MS-CLIENT-PRINCIPAL-IDP": "google",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "identity_headers_present": True,
        "principal_header_present": True,
        "principal_header_valid": True,
        "principal_id_header_present": False,
        "provider_header_present": True,
        "provider_is_google": True,
        "stable_principal_id_present": True,
        "trust_enabled": False,
        "google_principal_id": raw_id,
    }
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert raw_id not in caplog.text


def test_header_probe_does_not_log_incomplete_identity(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with _client(
        tmp_path,
        AUTH_IDENTITY_DIAGNOSTIC_ENABLED=True,
        AUTH_IDENTITY_DIAGNOSTIC_KEY=DIAGNOSTIC_KEY,
    ) as client:
        response = client.get(
            "/api/v1/session/header-probe",
            headers={
                "X-Aegis-Identity-Diagnostic-Key": DIAGNOSTIC_KEY,
                "X-MS-CLIENT-PRINCIPAL-IDP": "google",
            },
        )
    assert response.status_code == 200
    assert response.json()["google_principal_id"] is None
    assert "principal_id=" not in caplog.text


def test_header_probe_enabled_requires_key() -> None:
    with pytest.raises(ValidationError, match="AUTH_IDENTITY_DIAGNOSTIC_KEY"):
        Settings(_env_file=None, AUTH_IDENTITY_DIAGNOSTIC_ENABLED=True)


def test_header_probe_rejects_weak_key_even_when_disabled() -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(_env_file=None, AUTH_IDENTITY_DIAGNOSTIC_KEY="short-key")


def test_authentication_security_defaults_are_fail_closed() -> None:
    settings = Settings(_env_file=None)
    assert settings.trust_easyauth_headers is False
    assert settings.google_dashboard_principal_ids == []
    assert settings.auth_identity_diagnostic_enabled is False
    assert settings.auth_identity_diagnostic_key is None


def test_disable_dotenv_ignores_developer_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        "AUTH_DEV_BYPASS_ROLE=ADMIN\nLOG_LEVEL=DEBUG\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AUTH_DEV_BYPASS_ROLE", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    get_settings.cache_clear()
    try:
        monkeypatch.setenv("AEGISARENA_DISABLE_DOTENV", "1")
        assert get_settings().auth_dev_bypass_role is None
        get_settings.cache_clear()
        monkeypatch.delenv("AEGISARENA_DISABLE_DOTENV")
        assert get_settings().auth_dev_bypass_role == "ADMIN"
    finally:
        get_settings.cache_clear()


def test_production_still_refuses_the_bypass(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, ENVIRONMENT="production", AUTH_DEV_BYPASS_ROLE="ADMIN")


def test_production_startup_guard_independently_refuses_the_bypass() -> None:
    # Bypass normal settings validation to prove the application startup guard is
    # an independent, fail-closed layer rather than relying on one validator.
    unsafe = Settings(_env_file=None).model_copy(
        update={
            "environment": "production",
            "auth_dev_bypass_role": "ADMIN",
        }
    )
    with pytest.raises(ConfigurationError, match="AUTH_DEV_BYPASS_ROLE"):
        ensure_production_auth_safe(unsafe)
