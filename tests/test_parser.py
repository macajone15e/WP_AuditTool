from app.models.audit import AuditReport
from app.services.parser import ParserService


class TestParserService:
    def setup_method(self):
        self.parser = ParserService()

    def test_parse_returns_audit_report(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert isinstance(report, AuditReport)

    def test_parse_target_url(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert report.target_url == "https://example.com/"
        assert report.effective_url == "https://www.example.com/"

    def test_parse_wordpress_version(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert report.wordpress.detected is True
        assert report.wordpress.number == "6.4.2"
        assert report.wordpress.status == "insecure"

    def test_parse_wordpress_vulnerabilities(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert len(report.wordpress.vulnerabilities) == 1
        vuln = report.wordpress.vulnerabilities[0]
        assert vuln.title == "WordPress 6.4.2 - Unauthenticated XSS"
        assert vuln.severity == "medium"
        assert vuln.fixed_in == "6.4.3"
        assert "2024-12345" in vuln.cve

    def test_parse_wordpress_not_detected(self):
        report = self.parser.parse({"version": None})
        assert report.wordpress.detected is False

    def test_parse_server_info(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert report.server.server == "Apache/2.4.52"
        assert report.server.powered_by == "PHP/8.1.2"

    def test_parse_plugins(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert len(report.plugins) == 2

        cf7 = next(p for p in report.plugins if p.slug == "contact-form-7")
        assert cf7.version.number == "5.8"
        assert cf7.outdated is True
        assert len(cf7.vulnerabilities) == 1

        akismet = next(p for p in report.plugins if p.slug == "akismet")
        assert akismet.outdated is False
        assert len(akismet.vulnerabilities) == 0

    def test_parse_themes(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert len(report.themes) == 1

        main_theme = report.themes[0]
        assert main_theme.is_main is True
        assert main_theme.slug == "twentytwentyfour"
        assert main_theme.style_name == "Twenty Twenty-Four"
        assert main_theme.outdated is True

    def test_parse_users(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert len(report.users) == 2

        usernames = {u.username for u in report.users}
        assert usernames == {"admin", "editor"}

    def test_parse_scan_stats(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert report.scan_stats.elapsed_seconds == 45.2
        assert report.scan_stats.requests_done == 1234
        assert report.scan_stats.aborted is False

    def test_vulnerability_summary(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        summary = report.vulnerabilities_summary
        assert summary.total == 2
        assert summary.by_severity["medium"] == 1
        assert summary.by_severity["low"] == 1

    def test_parse_empty_data(self):
        report = self.parser.parse({})
        assert report.wordpress.detected is False
        assert report.plugins == []
        assert report.themes == []
        assert report.users == []
        assert report.vulnerabilities_summary.total == 0

    def test_parse_interesting_findings(self, sample_wpscan_output: dict):
        report = self.parser.parse(sample_wpscan_output)
        assert len(report.interesting_findings) == 2
        headers_finding = report.interesting_findings[0]
        assert headers_finding.type == "headers"
        assert headers_finding.confidence == 100

    def test_scan_aborted(self):
        data = {"scan_aborted": "Target is not a WordPress site"}
        report = self.parser.parse(data)
        assert report.scan_stats.aborted is True
        assert report.scan_stats.abort_reason == "Target is not a WordPress site"
