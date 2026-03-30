import logging

from app.config import Settings
from app.exceptions.scanner import WPScanError
from app.models.audit import AuditReport, ScanStats
from app.services.discord import DiscordService
from app.services.parser import ParserService
from app.services.scanner import ScannerService

logger = logging.getLogger(__name__)


class AuditService:
    """Orchestrate scan → parse → notify for a WordPress audit.

    Args:
        settings: Application settings instance.

    """

    def __init__(self, settings: Settings) -> None:
        """Initialise with application *settings* and create sub-services."""
        self._settings = settings
        self._scanner = ScannerService(settings)
        self._parser = ParserService()
        self._discord = DiscordService()

    async def run(
        self,
        url: str,
        webhook_url: str,
        *,
        api_token: str | None = None,
    ) -> None:
        """Execute a full audit: scan, parse, and send results to Discord.

        Args:
            url: Target WordPress URL.
            webhook_url: Discord webhook URL.
            api_token: Optional WPScan API token override.

        """
        logger.info("Starting audit for %s", url)

        try:
            report = await self._scan_and_parse(url, api_token=api_token)
        except WPScanError as exc:
            logger.error("WPScan error for %s: %s", url, exc)
            logger.error("Stderr: %s", exc.stderr[:300] if exc.stderr else "N/A")
            report = self._build_error_report(url, str(exc))
        except Exception:
            logger.exception("Unexpected error for %s", url)
            return

        await self._notify(webhook_url, report, url)

    # Private helpers

    async def _scan_and_parse(
        self,
        url: str,
        *,
        api_token: str | None = None,
    ) -> AuditReport:
        """Run WPScan and parse the results."""
        logger.info("Running WPScan for %s…", url)
        raw_results = await self._scanner.scan(url, api_token=api_token)

        logger.info("Parsing results…")
        return self._parser.parse(raw_results)

    async def _notify(
        self,
        webhook_url: str,
        report: AuditReport,
        url: str,
    ) -> None:
        """Send the report to Discord."""
        logger.info("Sending results to Discord…")
        try:
            responses = await self._discord.send(webhook_url, report)
            success_count = sum(1 for r in responses if r.get("status") == "success")
            logger.info(
                "Audit complete for %s — %d/%d Discord messages sent",
                url,
                success_count,
                len(responses),
            )
        except Exception:
            logger.exception("Failed to send results to Discord for %s", url)

    @staticmethod
    def _build_error_report(url: str, error_message: str) -> AuditReport:
        """Build a minimal report indicating a scan failure."""
        return AuditReport(
            target_url=url,
            scan_stats=ScanStats(aborted=True, abort_reason=error_message),
        )
