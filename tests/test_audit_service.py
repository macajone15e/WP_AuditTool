from unittest.mock import AsyncMock

import pytest

from app.config import Settings
from app.exceptions.scanner import WPScanError
from app.models.audit import AuditReport
from app.services.audit import AuditService


class TestAuditService:
    def setup_method(self):
        self.settings = Settings(
            discord_webhook_url="https://discord.com/api/webhooks/123/abc",
            wpscan_api_token="test-token",
            _env_file=None,
        )
        self.service = AuditService(self.settings)

    @pytest.mark.asyncio()
    async def test_run_success(self, sample_wpscan_output: dict):
        self.service._scanner.scan = AsyncMock(return_value=sample_wpscan_output)
        self.service._discord.send = AsyncMock(
            return_value=[{"status": "success", "code": 204}],
        )

        await self.service.run(
            url="https://example.com",
            webhook_url="https://discord.com/api/webhooks/123/abc",
        )

        self.service._scanner.scan.assert_awaited_once()
        self.service._discord.send.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_run_sends_error_report_on_wpscan_failure(self):
        self.service._scanner.scan = AsyncMock(
            side_effect=WPScanError("scan failed", stderr="error output"),
        )
        self.service._discord.send = AsyncMock(
            return_value=[{"status": "success", "code": 204}],
        )

        await self.service.run(
            url="https://example.com",
            webhook_url="https://discord.com/api/webhooks/123/abc",
        )

        # Should still send a report (error report)
        self.service._discord.send.assert_awaited_once()
        call_args = self.service._discord.send.call_args
        report = call_args[0][1]
        assert isinstance(report, AuditReport)
        assert report.scan_stats.aborted is True

    @pytest.mark.asyncio()
    async def test_run_handles_unexpected_error(self):
        self.service._scanner.scan = AsyncMock(
            side_effect=RuntimeError("unexpected"),
        )
        self.service._discord.send = AsyncMock()

        # Should not raise
        await self.service.run(
            url="https://example.com",
            webhook_url="https://discord.com/api/webhooks/123/abc",
        )

        # Discord should not be called for unexpected errors
        self.service._discord.send.assert_not_awaited()

    def test_build_error_report(self):
        report = AuditService._build_error_report(
            "https://example.com",
            "Something went wrong",
        )
        assert isinstance(report, AuditReport)
        assert report.target_url == "https://example.com"
        assert report.scan_stats.aborted is True
        assert report.scan_stats.abort_reason == "Something went wrong"
