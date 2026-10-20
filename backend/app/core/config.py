from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# backend/ - relative MODEL_ARTIFACT_DIR values are anchored here so the
# artifact location never depends on the directory the server was launched from.
BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="AegisArena API", validation_alias="APP_NAME")
    environment: Literal["development", "test", "demo", "production"] = Field(
        default="development", validation_alias="ENVIRONMENT"
    )
    debug: bool = Field(default=False, validation_alias="DEBUG")
    api_prefix: str = Field(default="/api", validation_alias="API_PREFIX")
    backend_host: str = Field(default="127.0.0.1", validation_alias="BACKEND_HOST")
    backend_port: int = Field(default=8000, ge=1, le=65535, validation_alias="BACKEND_PORT")
    database_url: str = Field(default="sqlite:///./aegistwin.db", validation_alias="DATABASE_URL")
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"],
        validation_alias="CORS_ORIGINS",
    )
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    simulation_only: bool = Field(default=True, validation_alias="SIMULATION_ONLY")
    demo_mode: bool = Field(default=False, validation_alias="DEMO_MODE")
    build_mode: str = Field(default="development", validation_alias="AEGISTWIN_BUILD_MODE")
    git_commit: str | None = Field(default=None, validation_alias="AEGISTWIN_GIT_COMMIT")
    benchmark_report_timestamp: str | None = Field(
        default=None, validation_alias="AEGISTWIN_BENCHMARK_TIMESTAMP"
    )
    model_artifact_dir: Path = Field(
        default=Path("artifacts/models"), validation_alias="MODEL_ARTIFACT_DIR"
    )
    admin_principal_ids: Annotated[list[str], NoDecode] = Field(
        default_factory=list, validation_alias="ADMIN_PRINCIPAL_IDS"
    )
    google_dashboard_principal_ids: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        validation_alias="GOOGLE_DASHBOARD_PRINCIPAL_IDS",
    )

    @field_validator("google_dashboard_principal_ids", mode="before")
    @classmethod
    def parse_google_dashboard_principal_ids(cls, value: Any) -> Any:
        if isinstance(value, str):
            parsed = json.loads(value)
            if not isinstance(parsed, list) or not all(
                isinstance(item, str) and item.strip() for item in parsed
            ):
                raise ValueError(
                    "GOOGLE_DASHBOARD_PRINCIPAL_IDS must be a JSON array of non-empty strings"
                )
            return parsed
        return value

    allow_anonymous_viewer: bool = Field(default=True, validation_alias="ALLOW_ANONYMOUS_VIEWER")
    auth_dev_bypass_role: str | None = Field(default=None, validation_alias="AUTH_DEV_BYPASS_ROLE")
    docs_enabled: bool = Field(default=True, validation_alias="DOCS_ENABLED")
    # Must default to false: Easy Auth is only configured manually, after the
    # Container App exists (see docs/deployment/AZURE_DEPLOYMENT.md). Until an
    # operator has verified Easy Auth is genuinely stripping/overwriting
    # externally-supplied X-MS-CLIENT-PRINCIPAL* headers and enabled this
    # explicitly, those headers must never be trusted — see
    # docs/security/AUTHENTICATION.md.
    trust_easyauth_headers: bool = Field(default=False, validation_alias="TRUST_EASYAUTH_HEADERS")
    # Temporary, operator-controlled enrollment diagnostic. The endpoint is
    # hidden unless explicitly enabled and requires this key on every request.
    # Keep both unset in ordinary deployments and remove after enrollment.
    auth_identity_diagnostic_enabled: bool = Field(
        default=False, validation_alias="AUTH_IDENTITY_DIAGNOSTIC_ENABLED"
    )
    auth_identity_diagnostic_key: SecretStr | None = Field(
        default=None, validation_alias="AUTH_IDENTITY_DIAGNOSTIC_KEY"
    )

    @field_validator("auth_identity_diagnostic_key")
    @classmethod
    def validate_auth_identity_diagnostic_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value()
        if len(secret) < 32 or secret != secret.strip():
            raise ValueError(
                "AUTH_IDENTITY_DIAGNOSTIC_KEY must be at least 32 characters with no "
                "leading or trailing whitespace"
            )
        return value

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        normalised = value.rstrip("/")
        if not normalised.startswith("/") or normalised == "":
            raise ValueError("API_PREFIX must be a non-root path beginning with '/'")
        return normalised

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        candidate = value.strip()
        if candidate.startswith("["):
            parsed = json.loads(candidate)
            if not isinstance(parsed, list):
                raise ValueError("CORS_ORIGINS JSON must be an array")
            return parsed
        return [origin.strip() for origin in candidate.split(",") if origin.strip()]

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, value: list[str]) -> list[str]:
        if any(origin == "*" for origin in value):
            raise ValueError("Wildcard CORS origins are not allowed")
        if any(not origin.startswith(("http://", "https://")) for origin in value):
            raise ValueError("Each CORS origin must use http:// or https://")
        return value

    @field_validator("admin_principal_ids", mode="before")
    @classmethod
    def parse_admin_principal_ids(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        candidate = value.strip()
        if candidate.startswith("["):
            parsed = json.loads(candidate)
            if not isinstance(parsed, list):
                raise ValueError("ADMIN_PRINCIPAL_IDS JSON must be an array")
            return parsed
        return [entry.strip() for entry in candidate.split(",") if entry.strip()]

    @field_validator("model_artifact_dir")
    @classmethod
    def anchor_model_artifact_dir(cls, value: Path) -> Path:
        return value if value.is_absolute() else BACKEND_ROOT / value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalised = value.upper()
        if normalised not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL is not supported")
        return normalised

    @field_validator("git_commit")
    @classmethod
    def validate_git_commit(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        if (
            not all(character in "0123456789abcdefABCDEF" for character in value)
            or not 7 <= len(value) <= 40
        ):
            raise ValueError("AEGISTWIN_GIT_COMMIT must be a 7-40 character hexadecimal revision")
        return value.lower()

    @field_validator("auth_dev_bypass_role")
    @classmethod
    def validate_auth_dev_bypass_role(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        normalised = value.upper()
        if normalised not in {"VIEWER", "ANALYST", "ADMIN"}:
            raise ValueError("AUTH_DEV_BYPASS_ROLE must be VIEWER, ANALYST, or ADMIN")
        return normalised

    def model_post_init(self, __context: Any) -> None:
        if self.environment == "production" and self.auth_dev_bypass_role:
            raise ValueError("AUTH_DEV_BYPASS_ROLE must not be set when ENVIRONMENT=production")
        if self.auth_identity_diagnostic_enabled and self.auth_identity_diagnostic_key is None:
            raise ValueError(
                "AUTH_IDENTITY_DIAGNOSTIC_KEY is required when "
                "AUTH_IDENTITY_DIAGNOSTIC_ENABLED=true"
            )
        if self.environment != "production":
            self.cors_origins = expand_loopback_origins(self.cors_origins)


_LOOPBACK_TWINS = {"localhost": "127.0.0.1", "127.0.0.1": "localhost"}


def expand_loopback_origins(origins: list[str]) -> list[str]:
    """Outside production, treat `localhost` and `127.0.0.1` as the same origin.

    Vite and the demo launcher bind 127.0.0.1 while documentation and older
    .env files use localhost; a browser on either spelling is the same local
    developer, but CORS compares origins textually. Only exact loopback hosts
    are mirrored - no wildcard, and never in production.
    """

    expanded = list(origins)
    for origin in origins:
        scheme, _, rest = origin.partition("://")
        host, colon, port = rest.partition(":")
        twin = _LOOPBACK_TWINS.get(host)
        if twin is not None:
            candidate = f"{scheme}://{twin}{colon}{port}"
            if candidate not in expanded:
                expanded.append(candidate)
    return expanded


@lru_cache
def get_settings() -> Settings:
    # Supported launchers (demo, E2E, IDE launch config) set every value they
    # need explicitly and export AEGISARENA_DISABLE_DOTENV=1, so their
    # behaviour - including the development RBAC role - never silently
    # depends on an untracked developer backend/.env file.
    if os.environ.get("AEGISARENA_DISABLE_DOTENV") == "1":
        return Settings(_env_file=None)
    return Settings()
