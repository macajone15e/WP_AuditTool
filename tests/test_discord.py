from app.models.audit import (
    AuditReport,
    VulnerabilitySummary,
)
from app.services.discord import DiscordService


class TestDiscordService:
    def setup_method(self):
        self.service = DiscordService()

    def test_build_payloads_returns_list(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        assert isinstance(payloads, list)
        assert len(payloads) >= 1

    def test_payload_has_required_fields(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        payload = payloads[0]
        assert "username" in payload
        assert "avatar_url" in payload
        assert "embeds" in payload
        assert payload["username"] == "WP Audit Bot"

    def test_header_embed_present(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert any("Security Report" in t for t in titles)

    def test_vulnerability_embed_present_when_vulns_exist(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert any("Vulnerabilities" in t for t in titles)

    def test_no_vulnerability_embed_when_none(self):
        report = AuditReport(
            target_url="https://example.com",
            vulnerabilities_summary=VulnerabilitySummary(total=0),
        )
        payloads = self.service._build_payloads(report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert not any("Vulnerabilities" in t for t in titles)

    def test_plugins_embed_present(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert any("Plugins" in t for t in titles)

    def test_no_plugins_embed_when_empty(self):
        report = AuditReport(target_url="https://example.com", plugins=[])
        payloads = self.service._build_payloads(report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert not any("Plugins" in t for t in titles)

    def test_score_display_no_vulns(self):
        summary = VulnerabilitySummary(total=0)
        score = self.service._format_score(summary)
        assert "NO VULNERABILITIES" in score

    def test_score_display_critical(self):
        summary = VulnerabilitySummary(
            total=1,
            by_severity={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0},
        )
        score = self.service._format_score(summary)
        assert "CRITICAL" in score

    def test_score_display_high(self):
        summary = VulnerabilitySummary(
            total=2,
            by_severity={"critical": 0, "high": 2, "medium": 0, "low": 0, "unknown": 0},
        )
        score = self.service._format_score(summary)
        assert "HIGH" in score

    def test_truncate_short_text(self):
        assert self.service._truncate("hello", max_len=10) == "hello"

    def test_truncate_long_text(self):
        result = self.service._truncate("a" * 100, max_len=10)
        assert len(result) == 10
        assert result.endswith("…")

    def test_format_duration_seconds(self):
        assert self.service._format_duration(30.5) == "30.5s"

    def test_format_duration_minutes(self):
        assert self.service._format_duration(125) == "2m 5s"

    def test_format_duration_zero(self):
        assert self.service._format_duration(0) == "N/A"

    def test_format_bytes_kb(self):
        assert self.service._format_bytes(2500) == "2.5 KB"

    def test_format_bytes_mb(self):
        assert self.service._format_bytes(3_500_000) == "3.5 MB"

    def test_format_bytes_zero(self):
        assert self.service._format_bytes(0) == "N/A"

    def test_embed_description_within_limit(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        for payload in payloads:
            for embed in payload["embeds"]:
                desc = embed.get("description", "")
                assert len(desc) <= 4096

    def test_users_embed_present(self, parsed_report: AuditReport):
        payloads = self.service._build_payloads(parsed_report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert any("Users" in t for t in titles)

    def test_stats_embed_always_present(self):
        report = AuditReport(target_url="https://example.com")
        payloads = self.service._build_payloads(report)
        all_embeds = []
        for p in payloads:
            all_embeds.extend(p["embeds"])
        titles = [e.get("title", "") for e in all_embeds]
        assert any("Statistics" in t for t in titles)
