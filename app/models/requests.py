import re

from pydantic import BaseModel, field_validator

_URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,63}|[A-Z0-9-]{2,}\.?)"
    r"|localhost"
    r"|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d+)?"
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


class AuditRequest(BaseModel):
    """Incoming request to launch a WordPress security audit.

    Attributes:
        url: Target WordPress site URL.
        webhook_url: Optional Discord webhook URL override.
        api_token: Optional WPScan API token override.

    """

    url: str
    webhook_url: str | None = None
    api_token: str | None = None

    @field_validator("url")
    @classmethod
    def validate_and_normalise_url(cls, value: str) -> str:
        """Ensure the URL has a valid scheme and structure."""
        value = value.strip()
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        if not _URL_PATTERN.match(value):
            msg = f"Invalid URL: {value}"
            raise ValueError(msg)
        return value


class DomainAuditRequest(BaseModel):
    """Incoming request to audit a domain's security posture.

    Attributes:
        domain: Target domain name (e.g. ``"example.com"``).
        webhook_url: Optional Discord webhook URL to send results.

    """

    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        """Strip protocol and path, keep only the domain name."""
        value = value.strip().lower()
        # Remove protocol if present
        for prefix in ("https://", "http://"):
            if value.startswith(prefix):
                value = value[len(prefix):]
                break
        # Remove path, query, fragment
        value = value.split("/")[0].split("?")[0].split("#")[0]
        # Remove port
        value = value.split(":")[0]
        # Remove www prefix for canonical form
        if value.startswith("www."):
            value = value[4:]
        if not value or "." not in value:
            msg = f"Invalid domain: {value}"
            raise ValueError(msg)
        return value

