import logging
from datetime import UTC, datetime
from typing import Any

from app.constants import Severity
from app.models.audit import (
    AuditReport,
    InterestingFinding,
    PluginInfo,
    ScanStats,
    SensitiveFile,
    ServerInfo,
    ThemeInfo,
    TimThumb,
    UserInfo,
    VersionInfo,
    Vulnerability,
    VulnerabilitySummary,
    WordPressInfo,
)

logger = logging.getLogger(__name__)


class ParserService:
    """Transform raw WPScan JSON output into a typed ``AuditReport``."""

    def parse(self, data: dict[str, Any]) -> AuditReport:
        """Parse raw WPScan JSON *data* into an ``AuditReport``.

        Args:
            data: Dictionary loaded from WPScan's ``--format json`` output.

        Returns:
            Fully populated ``AuditReport`` instance.

        """
        report = AuditReport(
            scan_time=datetime.now(tz=UTC).isoformat(),
            target_url=data.get("target_url", ""),
            effective_url=data.get("effective_url", ""),
            wordpress=self._parse_wordpress(data),
            server=self._parse_server(data),
            interesting_findings=self._parse_interesting_findings(data),
            plugins=self._parse_plugins(data),
            themes=self._parse_themes(data),
            users=self._parse_users(data),
            config_backups=self._parse_config_backups(data),
            db_exports=self._parse_db_exports(data),
            timthumbs=self._parse_timthumbs(data),
            scan_stats=self._parse_scan_stats(data),
        )

        report.vulnerabilities_summary = self._compute_vulnerability_summary(report)
        return report

    # WordPress core

    def _parse_wordpress(self, data: dict[str, Any]) -> WordPressInfo:
        """Extract WordPress version information."""
        wp = data.get("version")
        if not wp:
            return WordPressInfo(detected=False)

        return WordPressInfo(
            detected=True,
            number=wp.get("number", "Unknown"),
            status=wp.get("status", ""),
            release_date=wp.get("release_date", ""),
            found_by=wp.get("found_by", ""),
            confidence=wp.get("confidence", 0),
            interesting_entries=wp.get("interesting_entries", []),
            vulnerabilities=[
                self._parse_vulnerability(v)
                for v in wp.get("vulnerabilities", [])
            ],
        )

    @staticmethod
    def _parse_server(data: dict[str, Any]) -> ServerInfo:
        """Extract HTTP server information from interesting findings."""
        server_header = ""
        powered_by = ""

        for finding in data.get("interesting_findings", []):
            if finding.get("type") != "headers":
                continue
            for entry in finding.get("interesting_entries", []):
                lower = entry.lower()
                if lower.startswith("server:"):
                    server_header = entry.split(":", 1)[1].strip()
                elif lower.startswith("x-powered-by:"):
                    powered_by = entry.split(":", 1)[1].strip()

        return ServerInfo(server=server_header, powered_by=powered_by)

    # Components

    def _parse_plugins(self, data: dict[str, Any]) -> list[PluginInfo]:
        """Extract detected plugins."""
        return [
            PluginInfo(
                slug=slug,
                location=info.get("location", ""),
                version=self._parse_version(info.get("version")),
                found_by=info.get("found_by", ""),
                latest_version=info.get("latest_version", ""),
                outdated=info.get("outdated", False),
                vulnerabilities=[
                    self._parse_vulnerability(v)
                    for v in info.get("vulnerabilities", [])
                ],
            )
            for slug, info in data.get("plugins", {}).items()
        ]

    def _parse_themes(self, data: dict[str, Any]) -> list[ThemeInfo]:
        """Extract detected themes, with the main theme listed first."""
        themes: list[ThemeInfo] = []
        main_theme = data.get("main_theme", {})
        main_slug = main_theme.get("slug", "") if main_theme else ""

        if main_theme and main_slug:
            themes.append(ThemeInfo(
                slug=main_slug,
                is_main=True,
                location=main_theme.get("location", ""),
                version=self._parse_version(main_theme.get("version")),
                found_by=main_theme.get("found_by", ""),
                latest_version=main_theme.get("latest_version", ""),
                outdated=main_theme.get("outdated", False),
                style_name=main_theme.get("style_name", ""),
                author=main_theme.get("author", ""),
                vulnerabilities=[
                    self._parse_vulnerability(v)
                    for v in main_theme.get("vulnerabilities", [])
                ],
            ))

        for slug, info in data.get("themes", {}).items():
            if slug == main_slug:
                continue
            themes.append(ThemeInfo(
                slug=slug,
                is_main=False,
                location=info.get("location", ""),
                version=self._parse_version(info.get("version")),
                found_by=info.get("found_by", ""),
                latest_version=info.get("latest_version", ""),
                outdated=info.get("outdated", False),
                vulnerabilities=[
                    self._parse_vulnerability(v)
                    for v in info.get("vulnerabilities", [])
                ],
            ))

        return themes

    @staticmethod
    def _parse_users(data: dict[str, Any]) -> list[UserInfo]:
        """Extract enumerated WordPress users."""
        return [
            UserInfo(
                username=username,
                id=info.get("id", ""),
                found_by=info.get("found_by", ""),
                confidence=info.get("confidence", 0),
            )
            for username, info in data.get("users", {}).items()
        ]

    # Sensitive files

    @staticmethod
    def _parse_config_backups(data: dict[str, Any]) -> list[SensitiveFile]:
        """Extract configuration backup files."""
        return [
            SensitiveFile(
                url=url,
                found_by=info.get("found_by", ""),
                confidence=info.get("confidence", 0),
            )
            for url, info in data.get("config_backups", {}).items()
        ]

    @staticmethod
    def _parse_db_exports(data: dict[str, Any]) -> list[SensitiveFile]:
        """Extract database export files."""
        return [
            SensitiveFile(
                url=url,
                found_by=info.get("found_by", ""),
                confidence=info.get("confidence", 0),
            )
            for url, info in data.get("db_exports", {}).items()
        ]

    def _parse_timthumbs(self, data: dict[str, Any]) -> list[TimThumb]:
        """Extract TimThumb instances."""
        return [
            TimThumb(
                url=url,
                found_by=info.get("found_by", ""),
                vulnerabilities=[
                    self._parse_vulnerability(v)
                    for v in info.get("vulnerabilities", [])
                ],
            )
            for url, info in data.get("timthumbs", {}).items()
        ]

    # Interesting findings

    def _parse_interesting_findings(
        self,
        data: dict[str, Any],
    ) -> list[InterestingFinding]:
        """Extract interesting findings from the scan."""
        return [
            InterestingFinding(
                url=finding.get("url", ""),
                to_s=finding.get("to_s", ""),
                type=finding.get("type", ""),
                found_by=finding.get("found_by", ""),
                confidence=finding.get("confidence", 0),
                interesting_entries=finding.get("interesting_entries", []),
                references=finding.get("references", {}),
                vulnerabilities=[
                    self._parse_vulnerability(v)
                    for v in finding.get("vulnerabilities", [])
                ],
            )
            for finding in data.get("interesting_findings", [])
        ]

    # Scan statistics

    @staticmethod
    def _parse_scan_stats(data: dict[str, Any]) -> ScanStats:
        """Extract scan execution statistics."""
        abort_info = data.get("scan_aborted")
        return ScanStats(
            aborted=abort_info is not None,
            abort_reason=abort_info or "",
            elapsed_seconds=data.get("elapsed", 0),
            requests_done=data.get("requests_done", 0),
            data_sent_bytes=data.get("data_sent", 0),
            data_received_bytes=data.get("data_received", 0),
            used_memory_bytes=data.get("used_memory", 0),
        )

    # Vulnerability helpers

    @staticmethod
    def _parse_vulnerability(raw: dict[str, Any]) -> Vulnerability:
        """Parse a single vulnerability entry."""
        refs = raw.get("references", {})
        return Vulnerability(
            title=raw.get("title", "Untitled"),
            fixed_in=raw.get("fixed_in", ""),
            severity=raw.get("severity", Severity.UNKNOWN),
            cve=refs.get("cve", []),
            urls=refs.get("url", []),
            wpvulndb=refs.get("wpvulndb", []),
        )

    @staticmethod
    def _parse_version(version_data: Any) -> VersionInfo:
        """Parse version metadata from various formats."""
        if not version_data:
            return VersionInfo()
        if isinstance(version_data, dict):
            return VersionInfo(
                number=version_data.get("number", "Unknown"),
                confidence=version_data.get("confidence", 0),
                found_by=version_data.get("found_by", ""),
            )
        return VersionInfo(number=str(version_data))

    @staticmethod
    def _compute_vulnerability_summary(report: AuditReport) -> VulnerabilitySummary:
        """Aggregate all vulnerabilities from the report into a summary."""
        all_vulns: list[Vulnerability] = []

        if report.wordpress.detected:
            all_vulns.extend(report.wordpress.vulnerabilities)

        for plugin in report.plugins:
            all_vulns.extend(plugin.vulnerabilities)

        for theme in report.themes:
            all_vulns.extend(theme.vulnerabilities)

        for finding in report.interesting_findings:
            all_vulns.extend(finding.vulnerabilities)

        for tt in report.timthumbs:
            all_vulns.extend(tt.vulnerabilities)

        severity_counts: dict[str, int] = {s: 0 for s in Severity}
        for vuln in all_vulns:
            sev = vuln.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[Severity.UNKNOWN] += 1

        return VulnerabilitySummary(
            total=len(all_vulns),
            by_severity=severity_counts,
            details=all_vulns,
        )
