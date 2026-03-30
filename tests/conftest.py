"""Shared test fixtures and sample data."""

import pytest

from app.config import Settings
from app.models.audit import AuditReport
from app.services.parser import ParserService


@pytest.fixture()
def settings() -> Settings:
    """Create a test Settings instance with safe defaults."""
    return Settings(
        discord_webhook_url="https://discord.com/api/webhooks/123/abc",
        wpscan_api_token="test-token",
        wpscan_path="/usr/bin/wpscan",
        api_host="127.0.0.1",
        api_port=8000,
        scan_timeout=60,
    )


@pytest.fixture()
def sample_wpscan_output() -> dict:
    """Return a realistic sample WPScan JSON output."""
    return {
        "target_url": "https://example.com/",
        "effective_url": "https://www.example.com/",
        "interesting_findings": [
            {
                "url": "https://example.com/",
                "to_s": "Headers",
                "type": "headers",
                "found_by": "Headers (Passive Detection)",
                "confidence": 100,
                "interesting_entries": [
                    "Server: Apache/2.4.52",
                    "X-Powered-By: PHP/8.1.2",
                ],
                "references": {},
                "vulnerabilities": [],
            },
            {
                "url": "https://example.com/xmlrpc.php",
                "to_s": "XML-RPC seems to be enabled: https://example.com/xmlrpc.php",
                "type": "xmlrpc",
                "found_by": "Direct Access (Aggressive Detection)",
                "confidence": 100,
                "interesting_entries": [
                    "https://example.com/xmlrpc.php",
                ],
                "references": {
                    "url": ["https://www.rapid7.com/db/modules/auxiliary/scanner/http/"]
                },
                "vulnerabilities": [],
            },
        ],
        "version": {
            "number": "6.4.2",
            "status": "insecure",
            "release_date": "2024-01-30",
            "found_by": "Meta Generator (Passive Detection)",
            "confidence": 80,
            "interesting_entries": [],
            "vulnerabilities": [
                {
                    "title": "WordPress 6.4.2 - Unauthenticated XSS",
                    "fixed_in": "6.4.3",
                    "severity": "medium",
                    "references": {
                        "cve": ["2024-12345"],
                        "url": ["https://wordpress.org/news/"],
                        "wpvulndb": ["wp-vuln-001"],
                    },
                },
            ],
        },
        "main_theme": {
            "slug": "twentytwentyfour",
            "location": "https://example.com/wp-content/themes/twentytwentyfour/",
            "style_name": "Twenty Twenty-Four",
            "author": "the WordPress team",
            "found_by": "CSS Style In Homepage (Passive Detection)",
            "version": {"number": "1.0", "confidence": 80, "found_by": "Style"},
            "latest_version": "1.1",
            "outdated": True,
            "vulnerabilities": [],
        },
        "plugins": {
            "contact-form-7": {
                "slug": "contact-form-7",
                "location": "https://example.com/wp-content/plugins/contact-form-7/",
                "found_by": "Urls In Homepage (Passive Detection)",
                "version": {"number": "5.8", "confidence": 100, "found_by": "Readme"},
                "latest_version": "5.9",
                "outdated": True,
                "vulnerabilities": [
                    {
                        "title": "Contact Form 7 < 5.9 - Open Redirect",
                        "fixed_in": "5.9",
                        "severity": "low",
                        "references": {
                            "cve": ["2024-67890"],
                            "url": [],
                            "wpvulndb": [],
                        },
                    },
                ],
            },
            "akismet": {
                "slug": "akismet",
                "location": "https://example.com/wp-content/plugins/akismet/",
                "found_by": "Known Locations (Aggressive Detection)",
                "version": {"number": "5.3", "confidence": 90, "found_by": "Readme"},
                "latest_version": "5.3",
                "outdated": False,
                "vulnerabilities": [],
            },
        },
        "themes": {},
        "users": {
            "admin": {
                "id": 1,
                "found_by": "Author Id Brute Forcing (Aggressive Detection)",
                "confidence": 100,
            },
            "editor": {
                "id": 2,
                "found_by": "Author Id Brute Forcing (Aggressive Detection)",
                "confidence": 100,
            },
        },
        "config_backups": {},
        "db_exports": {},
        "timthumbs": {},
        "elapsed": 45.2,
        "requests_done": 1234,
        "data_sent": 256000,
        "data_received": 4500000,
        "used_memory": 125000000,
    }


@pytest.fixture()
def parsed_report(sample_wpscan_output: dict) -> AuditReport:
    """Return a parsed AuditReport from the sample data."""
    return ParserService().parse(sample_wpscan_output)
