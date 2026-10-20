"""Static regression checks on the deployment configuration (no Docker needed).

Each assertion pins a previously real defect: the dev compose mapped the
frontend to a port nginx does not listen on, nginx dropped the WebSocket
upgrade for /api/v1/ws/, model artifacts were not persisted, and the non-root
backend could not write a freshly created /data volume.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_dev_compose_maps_host_port_to_the_nginx_listen_port() -> None:
    compose = _read("docker-compose.yml")
    nginx = _read("frontend/nginx.conf.template")
    listen = re.search(r"listen\s+(\d+);", nginx)
    assert listen is not None
    assert f'"5173:{listen.group(1)}"' in compose


def test_nginx_upgrades_the_playback_websocket_path() -> None:
    nginx = _read("frontend/nginx.conf.template")
    block = nginx.split("location /api/v1/ws/", 1)[1].split("\n    }", 1)[0]
    assert "proxy_set_header Upgrade $http_upgrade;" in block
    assert 'proxy_set_header Connection "upgrade";' in block
    # It must be declared before the generic /api/ prefix block.
    assert nginx.index("location /api/v1/ws/") < nginx.index("location /api/ {")


def test_nginx_upgrades_the_event_websocket_path() -> None:
    nginx = _read("frontend/nginx.conf.template")
    block = nginx.split("location /ws/", 1)[1].split("\n    }", 1)[0]
    assert "proxy_set_header Upgrade $http_upgrade;" in block
    assert 'proxy_set_header Connection "upgrade";' in block


def test_model_artifacts_are_persisted_with_the_database() -> None:
    for compose_file in ("docker-compose.yml", "docker-compose.prod.yml"):
        compose = _read(compose_file)
        assert "MODEL_ARTIFACT_DIR: /data/models" in compose, compose_file
        assert re.search(r"- [\w-]+:/data\b", compose), compose_file


def test_backend_image_prepares_a_writable_data_directory_for_the_non_root_user() -> None:
    dockerfile = _read("backend/Dockerfile")
    assert "mkdir -p /data/models" in dockerfile
    chown = dockerfile.index("chown -R aegis:aegis")
    assert "/data" in dockerfile[chown : dockerfile.index("\n", chown)]
    assert dockerfile.index("chown -R aegis:aegis") < dockerfile.index("USER aegis")


def test_production_compose_never_enables_the_development_bypass() -> None:
    compose = _read("docker-compose.prod.yml")
    assert "AUTH_DEV_BYPASS_ROLE" not in compose
    assert "ENVIRONMENT: production" in compose


def test_backend_image_migrates_before_starting_one_worker() -> None:
    dockerfile = _read("backend/Dockerfile")
    assert "python -m alembic upgrade head && python -m uvicorn" in dockerfile
    command = next(line for line in dockerfile.splitlines() if line.startswith("CMD "))
    assert "--workers" not in command


def test_azure_container_app_keeps_the_hardened_single_replica_boundary() -> None:
    module = _read("infra/azure/modules/containerapp.bicep")
    assert "param maxReplicas int = 1" in module
    assert "activeRevisionsMode: 'Single'" in module
    assert "maxReplicas: maxReplicas" in module
    assert "allowInsecure: false" in module
    assert "value: 'localhost:8000'" in module
    assert "secretRef: 'database-url'" in module
    assert "AUTH_DEV_BYPASS_ROLE" not in module


def test_azure_release_preserves_verified_authentication_configuration() -> None:
    workflow = _read(".github/workflows/deploy-azure.yml")
    app_template = _read("infra/azure/app.bicep")
    module = _read("infra/azure/modules/containerapp.bicep")
    assert "TRUST_EASYAUTH_HEADERS: ${{ vars.TRUST_EASYAUTH_HEADERS || 'false' }}" in workflow
    assert (
        "AUTH_IDENTITY_DIAGNOSTIC_ENABLED: "
        "${{ vars.AUTH_IDENTITY_DIAGNOSTIC_ENABLED || 'false' }}"
    ) in workflow
    assert "ADMIN_PRINCIPAL_IDS_JSON: ${{ vars.ADMIN_PRINCIPAL_IDS_JSON || '[]' }}" in workflow
    assert (
        "GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON: "
        "${{ vars.GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON || '[]' }}"
    ) in workflow
    assert (
        "GOOGLE_PROVIDER_SECRET_KEY_VAULT_READY: "
        "${{ vars.GOOGLE_PROVIDER_SECRET_KEY_VAULT_READY || 'false' }}"
    ) in workflow
    assert '--parameters trustEasyAuthHeaders="$TRUST_EASYAUTH_HEADERS"' in workflow
    assert (
        '--parameters authIdentityDiagnosticEnabled="$AUTH_IDENTITY_DIAGNOSTIC_ENABLED"'
        in workflow
    )
    assert '--parameters adminPrincipalIds="$ADMIN_PRINCIPAL_IDS_JSON"' in workflow
    assert (
        '--parameters googleDashboardPrincipalIds="$GOOGLE_DASHBOARD_PRINCIPAL_IDS_JSON"'
        in workflow
    )
    assert "TRUST_EASYAUTH_HEADERS must be exactly 'true' or 'false'" in workflow
    assert "AUTH_IDENTITY_DIAGNOSTIC_ENABLED must be exactly 'true' or 'false'" in workflow
    assert "GOOGLE_PROVIDER_SECRET_KEY_VAULT_READY is exactly 'true'" in workflow
    migration_guard = workflow.index(
        "GOOGLE_PROVIDER_SECRET_KEY_VAULT_READY is exactly 'true'"
    )
    assert migration_guard < workflow.index("uses: azure/login@v2")
    assert "ADMIN_PRINCIPAL_IDS_JSON must be a JSON array" in workflow
    assert "param containerAppName string = 'ca-aegisarena-clean'" in app_template
    assert "param authIdentityDiagnosticEnabled bool = false" in app_template
    assert "param authIdentityDiagnosticEnabled bool = false" in module
    assert "param trustEasyAuthHeaders bool = false" in app_template
    assert "param googleDashboardPrincipalIds array = []" in app_template
    assert "secretRef: authIdentityDiagnosticSecretName" in module
    assert "googleProviderAuthenticationSecretKeyVaultEnabled: true" in app_template
    assert (
        "param googleProviderAuthenticationSecretKeyVaultEnabled bool = false"
        in module
    )
    assert (
        "var googleProviderAuthenticationSecretName = "
        "'google-provider-authentication-secret'"
    ) in module
    assert (
        "var googleProviderAuthenticationSecretUri = "
        "'${keyVaultUri}secrets/${googleProviderAuthenticationSecretName}'"
    ) in module
    assert (
        "name: googleProviderAuthenticationSecretName\n"
        "                keyVaultUrl: googleProviderAuthenticationSecretUri\n"
        "                identity: appIdentityId"
    ) in module
    assert "listSecrets" not in app_template
    assert "listSecrets" not in module
    assert "Microsoft.App/containerApps/authConfigs" not in app_template
    assert "Microsoft.App/containerApps/authConfigs" not in module
