from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


class TestHealthRoute:
    def test_health_returns_200(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert data["version"] == "1.0.0"

    def test_health_fields_present(self, client: TestClient):
        response = client.get("/health")
        data = response.json()
        assert "wpscan_token_configured" in data
        assert "discord_configured" in data


class TestAuditRoute:
    def test_audit_requires_webhook(self, client: TestClient):
        unconfigured = Settings(discord_webhook_url="", _env_file=None)
        with patch("app.routes.audit.get_settings", return_value=unconfigured):
            response = client.post(
                "/audit",
                json={"url": "https://example.com"},
            )
        assert response.status_code == 400
        assert "webhook" in response.json()["detail"].lower()

    def test_audit_rejects_invalid_url(self, client: TestClient):
        response = client.post(
            "/audit",
            json={
                "url": "not-a-valid-url!!!",
                "webhook_url": "https://discord.com/api/webhooks/123/abc",
            },
        )
        assert response.status_code == 422

    def test_audit_accepts_valid_request(self, client: TestClient):
        response = client.post(
            "/audit",
            json={
                "url": "https://example.com",
                "webhook_url": "https://discord.com/api/webhooks/123/abc",
            },
        )
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert "https://example.com" in data["url"]

    def test_audit_adds_https_scheme(self, client: TestClient):
        response = client.post(
            "/audit",
            json={
                "url": "example.com",
                "webhook_url": "https://discord.com/api/webhooks/123/abc",
            },
        )
        assert response.status_code == 202
        data = response.json()
        assert data["url"].startswith("https://")

    def test_audit_accepts_ip_address(self, client: TestClient):
        response = client.post(
            "/audit",
            json={
                "url": "http://192.168.1.1",
                "webhook_url": "https://discord.com/api/webhooks/123/abc",
            },
        )
        assert response.status_code == 202


class TestOpenAPIDoc:
    def test_docs_accessible(self, client: TestClient):
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_schema(self, client: TestClient):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "WP Audit Tool"
        assert "/audit" in schema["paths"]
        assert "/health" in schema["paths"]
