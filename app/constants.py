from enum import StrEnum


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ScanExitCode:
    """WPScan CLI exit codes.

    References:
        https://github.com/wpscanteam/wpscan/wiki/Exit-Codes

    """

    SUCCESS = 0
    VULNERABILITIES_FOUND = 5


# Discord embed color palette (decimal format).
DISCORD_COLOR_GREEN = 0x2ECC71
DISCORD_COLOR_YELLOW = 0xF1C40F
DISCORD_COLOR_ORANGE = 0xE67E22
DISCORD_COLOR_RED = 0xE74C3C
DISCORD_COLOR_BLUE = 0x3498DB
DISCORD_COLOR_PURPLE = 0x9B59B6
DISCORD_COLOR_DARK = 0x2C3E50

# Discord API limits.
DISCORD_MAX_EMBED_DESCRIPTION = 4096
DISCORD_MAX_FIELD_VALUE = 1024
DISCORD_MAX_FIELD_NAME = 256
DISCORD_MAX_EMBEDS_PER_MESSAGE = 10
DISCORD_MAX_TOTAL_CHARS = 6000

# Discord bot identity.
DISCORD_BOT_USERNAME = "WP Audit Bot"
DISCORD_BOT_AVATAR_URL = (
    "https://s.w.org/style/images/about/WordPress-logotype-wmark.png"
)

# WPScan default enumeration flags.
WPSCAN_DEFAULT_ENUMERATE = "vp,vt,tt,cb,dbe,u"
WPSCAN_DEFAULT_PLUGINS_DETECTION = "mixed"

# Severity display mapping.
SEVERITY_EMOJI: dict[str, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.UNKNOWN: "⚪",
}


class DomainCheckStatus(StrEnum):
    """Status of a domain security check."""

    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


DOMAIN_CHECK_EMOJI: dict[str, str] = {
    DomainCheckStatus.PASS: "✅",
    DomainCheckStatus.WARNING: "⚠️",
    DomainCheckStatus.FAIL: "❌",
    DomainCheckStatus.ERROR: "💥",
    DomainCheckStatus.SKIPPED: "⏭️",
}

DOMAIN_CHECK_COLOR: dict[str, int] = {
    DomainCheckStatus.PASS: DISCORD_COLOR_GREEN,
    DomainCheckStatus.WARNING: DISCORD_COLOR_YELLOW,
    DomainCheckStatus.FAIL: DISCORD_COLOR_RED,
    DomainCheckStatus.ERROR: DISCORD_COLOR_ORANGE,
    DomainCheckStatus.SKIPPED: DISCORD_COLOR_DARK,
}

# WHOIS privacy proxy patterns (case-insensitive match in registrant fields).
WHOIS_PRIVACY_PATTERNS: list[str] = [
    "privacy",
    "redacted",
    "whoisguard",
    "domains by proxy",
    "contact privacy",
    "withheld",
    "data protected",
    "not disclosed",
    "identity protect",
    "privacyprotect",
    "whoisprivacy",
    "domain protection",
]

