import logging

from app.config import Settings
from app.exceptions.scanner import WPScanError
from app.models.audit import AuditReport, ScanStats
from app.services.discord import DiscordService
from app.services.domain import DomainSecurityService
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
        self._domain = DomainSecurityService()

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

        # Send "audit started" notification to Discord
        await self._send_start_notification(webhook_url, url)

        try:
            report = await self._scan_and_parse(url, api_token=api_token)
        except WPScanError as exc:
            logger.error("WPScan error for %s: %s", url, exc)
            logger.error("Stderr: %s", exc.stderr[:300] if exc.stderr else "N/A")
            report = self._build_error_report(url, str(exc))
        except Exception:
            logger.exception("Unexpected error for %s", url)
            return

        # Run domain security checks
        report = await self._enrich_with_domain_security(report, url)

        await self._notify(webhook_url, report, url)

    # Private helpers

    async def _send_start_notification(
        self,
        webhook_url: str,
        url: str,
    ) -> None:
        """Send an "audit started" message to Discord."""
        try:
            await self._discord.send_start_message(webhook_url, url)
            logger.info("Sent audit start notification for %s", url)
        except Exception:
            logger.warning("Failed to send start notification for %s", url, exc_info=True)

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

    async def _enrich_with_domain_security(
        self,
        report: AuditReport,
        url: str,
    ) -> AuditReport:
        """Run domain security checks and attach to the report."""
        try:
            domain = self._domain.extract_domain(url)
            logger.info("Running domain security checks for %s…", domain)
            domain_report = await self._domain.check_all(domain)
            report.domain_security = domain_report
            logger.info("Domain security checks complete for %s", domain)
        except Exception:
            logger.warning(
                "Domain security checks failed for %s",
                url,
                exc_info=True,
            )
        return report

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
