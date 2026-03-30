import logging
from datetime import UTC, datetime

import httpx

from app.constants import (
    DISCORD_BOT_AVATAR_URL,
    DISCORD_BOT_USERNAME,
    DISCORD_COLOR_BLUE,
    DISCORD_COLOR_DARK,
    DISCORD_COLOR_GREEN,
    DISCORD_COLOR_ORANGE,
    DISCORD_COLOR_PURPLE,
    DISCORD_COLOR_RED,
    DISCORD_COLOR_YELLOW,
    DISCORD_MAX_EMBED_DESCRIPTION,
    DISCORD_MAX_EMBEDS_PER_MESSAGE,
    DISCORD_MAX_TOTAL_CHARS,
    SEVERITY_EMOJI,
    Severity,
)
from app.models.audit import AuditReport, VulnerabilitySummary

logger = logging.getLogger(__name__)


class DiscordService:
    """Build rich Discord embeds from an ``AuditReport`` and send them."""

    # Public API

    async def send(self, webhook_url: str, report: AuditReport) -> list[dict]:
        """Send the *report* as formatted embeds to *webhook_url*.

        Returns:
            List of response dicts with ``status`` and optional ``code`` keys.

        """
        payloads = self._build_payloads(report)
        return await self._post_payloads(webhook_url, payloads)

    # Payload construction

    def _build_payloads(self, report: AuditReport) -> list[dict]:
        """Split embeds into Discord-compliant payloads."""
        builders = [
            self._build_header_embed,
            self._build_vulnerabilities_embed,
            self._build_plugins_embed,
            self._build_themes_embed,
            self._build_users_embed,
            self._build_sensitive_files_embed,
            self._build_interesting_findings_embed,
            self._build_stats_embed,
        ]

        all_embeds = [e for b in builders if (e := b(report)) is not None]

        payloads: list[dict] = []
        current_embeds: list[dict] = []
        current_chars = 0

        for embed in all_embeds:
            embed_chars = self._estimate_embed_chars(embed)

            if (
                len(current_embeds) >= DISCORD_MAX_EMBEDS_PER_MESSAGE
                or current_chars + embed_chars > DISCORD_MAX_TOTAL_CHARS
            ):
                payloads.append(self._wrap_payload(current_embeds))
                current_embeds = []
                current_chars = 0

            current_embeds.append(embed)
            current_chars += embed_chars

        if current_embeds:
            payloads.append(self._wrap_payload(current_embeds))

        return payloads

    # Individual embed builders

    def _build_header_embed(self, report: AuditReport) -> dict:
        """Build the main overview embed with target info and quick stats."""
        summary = report.vulnerabilities_summary
        score = self._format_score(summary)
        color = self._severity_color(summary)

        wp_version = "Not detected"
        wp_status = ""
        if report.wordpress.detected:
            wp_version = report.wordpress.number
            status = report.wordpress.status
            if status == "insecure":
                wp_status = " ⚠️ (insecure)"
            elif status == "latest":
                wp_status = " ✅ (up to date)"
            elif status:
                wp_status = f" ({status})"

        lines = [
            score,
            "",
            f"🌐 **Target URL**: {report.target_url}",
        ]
        if report.effective_url and report.effective_url != report.target_url:
            lines.append(f"↪️ **Effective URL**: {report.effective_url}")

        lines.extend(["", f"📦 **WordPress**: `{wp_version}`{wp_status}"])

        if report.server.server:
            lines.append(f"🖥️ **Server**: `{report.server.server}`")
        if report.server.powered_by:
            lines.append(f"⚙️ **X-Powered-By**: `{report.server.powered_by}`")

        main_theme = next((t for t in report.themes if t.is_main), None)
        if main_theme:
            name = main_theme.style_name or main_theme.slug
            lines.append(f"🎨 **Active theme**: `{name}` v{main_theme.version.number}")

        lines.extend([
            "",
            f"🔌 **Plugins detected**: {len(report.plugins)}",
            f"👤 **Users found**: {len(report.users)}",
        ])

        return {
            "title": "🔍 WP Audit — Security Report",
            "description": self._truncate("\n".join(lines)),
            "color": color,
            "timestamp": report.scan_time or datetime.now(tz=UTC).isoformat(),
        }

    def _build_vulnerabilities_embed(self, report: AuditReport) -> dict | None:
        """Vulnerability details embed."""
        summary = report.vulnerabilities_summary
        if summary.total == 0:
            return None

        severity_parts = []
        for sev in Severity:
            count = summary.by_severity.get(sev, 0)
            if count > 0:
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                severity_parts.append(f"{emoji} **{sev.upper()}**: {count}")

        lines = [" • ".join(severity_parts), ""]

        max_to_show = 15
        for shown, vuln in enumerate(summary.details):
            if shown >= max_to_show:
                remaining = summary.total - shown
                lines.append(f"\n*…and {remaining} more vulnerability(ies)*")
                break

            emoji = SEVERITY_EMOJI.get(vuln.severity, "⚪")
            lines.append(f"{emoji} **{vuln.title}**")

            meta: list[str] = []
            if vuln.fixed_in:
                meta.append(f"Fixed in `{vuln.fixed_in}`")
            if vuln.cve:
                cve_links = [
                    f"[CVE-{c}](https://nvd.nist.gov/vuln/detail/CVE-{c})"
                    for c in vuln.cve[:3]
                ]
                meta.append(" ".join(cve_links))
            if meta:
                lines.append(f"  ↳ {' | '.join(meta)}")

        return {
            "title": f"⚠️ Vulnerabilities ({summary.total})",
            "description": self._truncate("\n".join(lines)),
            "color": self._severity_color(summary),
        }

    def _build_plugins_embed(self, report: AuditReport) -> dict | None:
        """Plugins list embed."""
        if not report.plugins:
            return None

        lines: list[str] = []
        for plugin in report.plugins[:20]:
            vuln_count = len(plugin.vulnerabilities)
            if vuln_count > 0:
                status = f" 🔴 {vuln_count} vuln(s)"
            elif plugin.outdated:
                status = " 🟡 outdated"
            else:
                status = " ✅"
            lines.append(f"• `{plugin.slug}` v{plugin.version.number}{status}")

        if len(report.plugins) > 20:
            lines.append(f"\n*…and {len(report.plugins) - 20} more plugin(s)*")

        return {
            "title": f"🔌 Plugins ({len(report.plugins)})",
            "description": self._truncate("\n".join(lines)),
            "color": DISCORD_COLOR_PURPLE,
        }

    def _build_themes_embed(self, report: AuditReport) -> dict | None:
        """Themes list embed."""
        if not report.themes:
            return None

        lines: list[str] = []
        for theme in report.themes[:10]:
            prefix = "⭐" if theme.is_main else "•"
            vuln_count = len(theme.vulnerabilities)
            if vuln_count > 0:
                status = f" 🔴 {vuln_count} vuln(s)"
            elif theme.outdated:
                status = " 🟡 outdated"
            else:
                status = " ✅"
            name = theme.style_name or theme.slug
            lines.append(f"{prefix} `{name}` v{theme.version.number}{status}")

        return {
            "title": f"🎨 Themes ({len(report.themes)})",
            "description": self._truncate("\n".join(lines)),
            "color": DISCORD_COLOR_PURPLE,
        }

    def _build_users_embed(self, report: AuditReport) -> dict | None:
        """Build the enumerated users embed."""
        if not report.users:
            return None

        lines: list[str] = []
        for user in report.users[:20]:
            line = f"• `{user.username}` (ID: {user.id})"
            if user.found_by:
                line += f" — _{user.found_by}_"
            lines.append(line)

        if len(report.users) > 20:
            lines.append(f"\n*…and {len(report.users) - 20} more user(s)*")

        return {
            "title": f"👤 Users ({len(report.users)})",
            "description": self._truncate("\n".join(lines)),
            "color": DISCORD_COLOR_BLUE,
        }

    def _build_sensitive_files_embed(self, report: AuditReport) -> dict | None:
        """Config backups, DB exports, and TimThumbs embed."""
        if not report.config_backups and not report.db_exports and not report.timthumbs:
            return None

        lines: list[str] = []

        if report.config_backups:
            lines.append("**📋 Config Backups:**")
            for backup in report.config_backups[:5]:
                lines.append(f"  🔴 `{backup.url}`")

        if report.db_exports:
            lines.append("\n**🗃️ DB Exports:**")
            for export in report.db_exports[:5]:
                lines.append(f"  🔴 `{export.url}`")

        if report.timthumbs:
            lines.append("\n**📸 TimThumbs:**")
            for tt in report.timthumbs[:5]:
                vuln_count = len(tt.vulnerabilities)
                suffix = f" ({vuln_count} vuln(s))" if vuln_count > 0 else ""
                lines.append(f"  ⚠️ `{tt.url}`{suffix}")

        total = len(report.config_backups) + len(report.db_exports) + len(report.timthumbs)
        return {
            "title": f"📁 Sensitive Files ({total})",
            "description": self._truncate("\n".join(lines)),
            "color": DISCORD_COLOR_RED,
        }

    def _build_interesting_findings_embed(self, report: AuditReport) -> dict | None:
        """Interesting findings embed."""
        if not report.interesting_findings:
            return None

        lines: list[str] = []
        for finding in report.interesting_findings[:10]:
            if finding.to_s:
                lines.append(f"• **{finding.to_s}**")
            elif finding.url:
                lines.append(f"• `{finding.url}`")
            for entry in finding.interesting_entries[:3]:
                lines.append(f"  ↳ `{self._truncate(entry, max_len=100)}`")

        return {
            "title": f"🔎 Findings ({len(report.interesting_findings)})",
            "description": self._truncate("\n".join(lines)),
            "color": DISCORD_COLOR_BLUE,
        }

    def _build_stats_embed(self, report: AuditReport) -> dict:
        """Scan statistics embed."""
        stats = report.scan_stats
        elapsed_str = self._format_duration(stats.elapsed_seconds)

        lines = [
            f"⏱️ **Duration**: {elapsed_str}",
            f"📡 **Requests**: {stats.requests_done}",
            f"📤 **Data sent**: {self._format_bytes(stats.data_sent_bytes)}",
            f"📥 **Data received**: {self._format_bytes(stats.data_received_bytes)}",
        ]

        if stats.aborted:
            lines.append(
                f"\n⚠️ **Scan aborted**: {stats.abort_reason or 'Unknown reason'}",
            )

        return {
            "title": "📊 Scan Statistics",
            "description": "\n".join(lines),
            "color": DISCORD_COLOR_DARK,
            "footer": {"text": "WP Audit Tool • Powered by WPScan"},
        }

    # HTTP delivery

    @staticmethod
    async def _post_payloads(webhook_url: str, payloads: list[dict]) -> list[dict]:
        """Send all payloads to the Discord webhook."""
        responses: list[dict] = []

        async with httpx.AsyncClient(timeout=30) as client:
            for idx, payload in enumerate(payloads):
                logger.info(
                    "Sending Discord message %d/%d (%d embeds)",
                    idx + 1,
                    len(payloads),
                    len(payload["embeds"]),
                )
                try:
                    resp = await client.post(
                        webhook_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 204:
                        logger.info("Message %d sent successfully", idx + 1)
                        responses.append({"status": "success", "code": 204})
                    elif resp.status_code == 429:
                        logger.warning("Rate-limited by Discord")
                        responses.append({
                            "status": "rate_limited",
                            "code": 429,
                            "retry_after": resp.json().get("retry_after", 0),
                        })
                    else:
                        body = resp.text
                        logger.error("Discord error (HTTP %d): %s", resp.status_code, body[:500])
                        responses.append({
                            "status": "error",
                            "code": resp.status_code,
                            "body": body[:500],
                        })
                except httpx.HTTPError as exc:
                    logger.error("HTTP error while sending: %s", exc)
                    responses.append({"status": "error", "error": str(exc)})

        return responses

    # Formatting helpers

    @staticmethod
    def _wrap_payload(embeds: list[dict]) -> dict:
        """Wrap a list of embeds into a Discord webhook payload."""
        return {
            "username": DISCORD_BOT_USERNAME,
            "avatar_url": DISCORD_BOT_AVATAR_URL,
            "embeds": embeds,
        }

    @staticmethod
    def _estimate_embed_chars(embed: dict) -> int:
        """Estimate the character count of an embed for limit checking."""
        chars = len(embed.get("title", "")) + len(embed.get("description", ""))
        for field in embed.get("fields", []):
            chars += len(field.get("name", "")) + len(field.get("value", ""))
        chars += len(embed.get("footer", {}).get("text", ""))
        return chars

    @staticmethod
    def _truncate(text: str, *, max_len: int = DISCORD_MAX_EMBED_DESCRIPTION) -> str:
        """Truncate *text* to *max_len* characters."""
        if len(text) <= max_len:
            return text
        return text[: max_len - 1] + "…"

    @staticmethod
    def _format_score(summary: VulnerabilitySummary) -> str:
        """Format the vulnerability score headline."""
        total = summary.total
        by_sev = summary.by_severity
        critical = by_sev.get(Severity.CRITICAL, 0)
        high = by_sev.get(Severity.HIGH, 0)

        if total == 0:
            return "🟢 **NO VULNERABILITIES DETECTED**"
        if critical > 0:
            return f"🔴 **{total} VULNERABILITY(IES) — {critical} CRITICAL**"
        if high > 0:
            return f"🟠 **{total} VULNERABILITY(IES) — {high} HIGH**"
        return f"🟡 **{total} VULNERABILITY(IES) DETECTED**"

    @staticmethod
    def _severity_color(summary: VulnerabilitySummary) -> int:
        """Return a Discord embed color based on the highest severity."""
        by_sev = summary.by_severity
        if by_sev.get(Severity.CRITICAL, 0) > 0 or by_sev.get(Severity.HIGH, 0) > 0:
            return DISCORD_COLOR_RED
        if by_sev.get(Severity.MEDIUM, 0) > 0:
            return DISCORD_COLOR_ORANGE
        if by_sev.get(Severity.LOW, 0) > 0:
            return DISCORD_COLOR_YELLOW
        return DISCORD_COLOR_GREEN

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format a duration in seconds to a human-readable string."""
        if not seconds:
            return "N/A"
        if seconds >= 60:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        return f"{seconds:.1f}s"

    @staticmethod
    def _format_bytes(byte_count: int) -> str:
        """Format a byte count to a human-readable string."""
        if not byte_count:
            return "N/A"
        if byte_count > 1_000_000:
            return f"{byte_count / 1_000_000:.1f} MB"
        if byte_count > 1_000:
            return f"{byte_count / 1_000:.1f} KB"
        return f"{byte_count} B"
