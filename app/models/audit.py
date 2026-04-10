from __future__ import annotations

from pydantic import BaseModel, Field

from app.constants import Severity
from app.models.domain import DomainSecurityReport


# Shared / atomic models
class Vulnerability(BaseModel):
    """A single known vulnerability.

    Attributes:
        title: Short description of the vulnerability.
        fixed_in: Version in which the vulnerability was patched.
        severity: One of critical / high / medium / low / unknown.
        cve: List of associated CVE identifiers.
        urls: Reference URLs.
        wpvulndb: WPVulnDB identifiers.

    """

    title: str = "Untitled"
    fixed_in: str = ""
    severity: str = Severity.UNKNOWN
    cve: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    wpvulndb: list[str] = Field(default_factory=list)


class VersionInfo(BaseModel):
    """Version metadata for a WordPress component.

    Attributes:
        number: Detected version string (``"Unknown"`` if not found).
        confidence: Detection confidence percentage.
        found_by: Detection method.

    """

    number: str = "Unknown"
    confidence: int = 0
    found_by: str = ""

# WordPress core
class WordPressInfo(BaseModel):
    """Information about the detected WordPress installation.

    Attributes:
        detected: Whether a WordPress installation was identified.
        number: Version number.
        status: Version status (e.g. ``"latest"``, ``"insecure"``).
        release_date: Official release date of this version.
        found_by: Detection method.
        confidence: Detection confidence.
        interesting_entries: Notable entries found during detection.
        vulnerabilities: Known vulnerabilities for this version.

    """

    detected: bool = False
    number: str = "Unknown"
    status: str = ""
    release_date: str = ""
    found_by: str = ""
    confidence: int = 0
    interesting_entries: list[str] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ServerInfo(BaseModel):
    """HTTP server information extracted from response headers.

    Attributes:
        server: Value of the ``Server`` header.
        powered_by: Value of the ``X-Powered-By`` header.

    """

    server: str = ""
    powered_by: str = ""


# Components

class PluginInfo(BaseModel):
    """A detected WordPress plugin.

    Attributes:
        slug: Plugin slug identifier.
        location: File-system location.
        version: Detected version info.
        found_by: Detection method.
        latest_version: Newest available version.
        outdated: Whether the plugin is outdated.
        vulnerabilities: Known vulnerabilities.

    """

    slug: str
    location: str = ""
    version: VersionInfo = Field(default_factory=VersionInfo)
    found_by: str = ""
    latest_version: str = ""
    outdated: bool = False
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ThemeInfo(BaseModel):
    """A detected WordPress theme.

    Attributes:
        slug: Theme slug identifier.
        is_main: Whether this is the active theme.
        location: File-system location.
        version: Detected version info.
        found_by: Detection method.
        latest_version: Newest available version.
        outdated: Whether the theme is outdated.
        style_name: Theme display name from ``style.css``.
        author: Theme author.
        vulnerabilities: Known vulnerabilities.

    """

    slug: str
    is_main: bool = False
    location: str = ""
    version: VersionInfo = Field(default_factory=VersionInfo)
    found_by: str = ""
    latest_version: str = ""
    outdated: bool = False
    style_name: str = ""
    author: str = ""
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class UserInfo(BaseModel):
    """A WordPress user discovered during enumeration.

    Attributes:
        username: Login name.
        id: WordPress user ID.
        found_by: Detection method.
        confidence: Detection confidence.

    """

    username: str
    id: int | str = ""
    found_by: str = ""
    confidence: int = 0


# Sensitive files

class SensitiveFile(BaseModel):
    """A sensitive file discovered on the target.

    Attributes:
        url: Full URL of the file.
        found_by: Detection method.
        confidence: Detection confidence.

    """

    url: str
    found_by: str = ""
    confidence: int = 0


class TimThumb(BaseModel):
    """A TimThumb instance discovered on the target.

    Attributes:
        url: Full URL.
        found_by: Detection method.
        vulnerabilities: Known vulnerabilities.

    """

    url: str
    found_by: str = ""
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


# Interesting findings

class InterestingFinding(BaseModel):
    """A noteworthy finding from the scan.

    Attributes:
        url: URL of the finding.
        to_s: Human-readable summary.
        type: Finding category.
        found_by: Detection method.
        confidence: Detection confidence.
        interesting_entries: Notable entries.
        references: Reference links.
        vulnerabilities: Associated vulnerabilities.

    """

    url: str = ""
    to_s: str = ""
    type: str = ""
    found_by: str = ""
    confidence: int = 0
    interesting_entries: list[str] = Field(default_factory=list)
    references: dict[str, list[str]] = Field(default_factory=dict)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


# Scan statistics

class ScanStats(BaseModel):
    """Scan execution statistics.

    Attributes:
        aborted: Whether the scan was aborted.
        abort_reason: Reason for abortion (if applicable).
        elapsed_seconds: Total scan duration.
        requests_done: Number of HTTP requests made.
        data_sent_bytes: Bytes sent.
        data_received_bytes: Bytes received.
        used_memory_bytes: Peak memory usage.

    """

    aborted: bool = False
    abort_reason: str = ""
    elapsed_seconds: float = 0.0
    requests_done: int = 0
    data_sent_bytes: int = 0
    data_received_bytes: int = 0
    used_memory_bytes: int = 0


# Vulnerability summary

class VulnerabilitySummary(BaseModel):
    """Aggregated vulnerability statistics.

    Attributes:
        total: Total number of vulnerabilities found.
        by_severity: Count per severity level.
        details: Flat list of all vulnerabilities.

    """

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.UNKNOWN: 0,
    })
    details: list[Vulnerability] = Field(default_factory=list)


# Top-level report

class AuditReport(BaseModel):
    """Complete audit report produced after parsing WPScan output.

    This is the single source of truth passed between services.
    """

    scan_time: str = ""
    target_url: str = ""
    effective_url: str = ""
    wordpress: WordPressInfo = Field(default_factory=WordPressInfo)
    server: ServerInfo = Field(default_factory=ServerInfo)
    interesting_findings: list[InterestingFinding] = Field(default_factory=list)
    plugins: list[PluginInfo] = Field(default_factory=list)
    themes: list[ThemeInfo] = Field(default_factory=list)
    users: list[UserInfo] = Field(default_factory=list)
    config_backups: list[SensitiveFile] = Field(default_factory=list)
    db_exports: list[SensitiveFile] = Field(default_factory=list)
    timthumbs: list[TimThumb] = Field(default_factory=list)
    vulnerabilities_summary: VulnerabilitySummary = Field(
        default_factory=VulnerabilitySummary,
    )
    domain_security: DomainSecurityReport | None = None
    scan_stats: ScanStats = Field(default_factory=ScanStats)
