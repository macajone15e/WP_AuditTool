from pydantic import BaseModel
from app.models.domain import DomainSecurityReport


class AuditResponse(BaseModel):
    """Response returned after an audit request is accepted.

    Attributes:
        status: Always ``"accepted"`` for a 202 response.
        message: Human-readable confirmation message.
        url: The normalised target URL.

    """

    status: str
    message: str
    url: str


class HealthResponse(BaseModel):
    """Response returned by the health-check endpoint.

    Attributes:
        status: ``"ok"`` or ``"degraded"``.
        wpscan_token_configured: Whether a WPScan API token is set.
        discord_configured: Whether a Discord webhook URL is set.
        version: Application version string.

    """

    status: str
    wpscan_token_configured: bool
    discord_configured: bool
    version: str


class DomainAuditResponse(BaseModel):
    """Response returned by the domain-audit endpoint.

    Attributes:
        status: ``"completed"`` on success.
        domain: Audited domain.
        report: Full domain security report.

    """

    status: str
    domain: str
    report: DomainSecurityReport

