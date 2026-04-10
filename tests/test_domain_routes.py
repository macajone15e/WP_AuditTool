"""Tests for the /domain-audit route."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.constants import DomainCheckStatus
from app.main import app
from app.models.domain import (
    ChecksSummary,
    DnsInfo,
    DnssecInfo,
    DomainSecurityReport,
    HstsInfo,
    SslInfo,
    WhoisInfo,
)


@pytest.fixture()
def mock_domain_report() -> DomainSecurityReport:
    return DomainSecurityReport(
        domain="example.com",
        scan_time="2024-01-01T00:00:00+00:00",
        whois=WhoisInfo(
            status=DomainCheckStatus.PASS,
            registrar="Test Registrar",
            transfer_locked=True,
            privacy_enabled=True,
            days_until_expiry=365,
        ),
        dns=DnsInfo(
            status=DomainCheckStatus.PASS,
            has_a_record=True,
            has_mx_record=True,
            has_ns_record=True,
            www_resolves=True,
        ),
        ssl=SslInfo(
            status=DomainCheckStatus.PASS,
            issuer="Let's Encrypt",
            is_valid=True,
            days_until_expiry=90,
        ),
        hsts=HstsInfo(
            status=DomainCheckStatus.PASS,
            enabled=True,
            max_age=31536000,
        ),
        dnssec=DnssecInfo(
            status=DomainCheckStatus.PASS,
            enabled=True,
            ds_records_found=True,
        ),
        checks_summary=ChecksSummary(
            total=5, passed=5, warnings=0, failed=0, errors=0,
        ),
    )


class TestDomainAuditRoute:
    @pytest.mark.asyncio
    async def test_domain_audit_success(self, mock_domain_report: DomainSecurityReport):
        with patch(
            "app.routes.domain.DomainSecurityService.check_all",
            new_callable=AsyncMock,
            return_value=mock_domain_report,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/domain-audit",
                    json={"domain": "example.com"},
                )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["domain"] == "example.com"
        assert data["report"]["whois"]["transfer_locked"] is True
        assert data["report"]["checks_summary"]["passed"] == 5

    @pytest.mark.asyncio
    async def test_domain_audit_with_url_input(self, mock_domain_report: DomainSecurityReport):
        """Domain validator should strip protocol and www."""
        with patch(
            "app.routes.domain.DomainSecurityService.check_all",
            new_callable=AsyncMock,
            return_value=mock_domain_report,
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/domain-audit",
                    json={"domain": "https://www.example.com/page"},
                )

        assert response.status_code == 200
        assert response.json()["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_domain_audit_invalid_domain(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/domain-audit",
                json={"domain": "notadomain"},
            )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_domain_audit_empty_domain(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/domain-audit",
                json={"domain": ""},
            )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_domain_audit_service_error(self):
        with patch(
            "app.routes.domain.DomainSecurityService.check_all",
            new_callable=AsyncMock,
            side_effect=Exception("Service boom"),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/domain-audit",
                    json={"domain": "example.com"},
                )

        assert response.status_code == 500
        assert "Service boom" in response.json()["detail"]
