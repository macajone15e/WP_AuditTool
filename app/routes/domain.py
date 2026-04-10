import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.config import get_settings
from app.models.requests import DomainAuditRequest
from app.models.responses import DomainAuditResponse
from app.services.discord import DiscordService
from app.services.domain import DomainSecurityService

router = APIRouter(tags=["Domain Security"])

logger = logging.getLogger(__name__)


@router.post("/domain-audit", response_model=DomainAuditResponse)
async def domain_audit(
    request: DomainAuditRequest,
    background_tasks: BackgroundTasks,
) -> DomainAuditResponse:
    """Run domain-level security checks (WHOIS, DNS, SSL, HSTS, DNSSEC).

    Returns the full report synchronously.

    - **domain**: Target domain name (required).
    - **webhook_url**: Discord webhook URL override (optional).
    """
    service = DomainSecurityService()

    try:
        report = await service.check_all(request.domain)
    except Exception as exc:
        logger.exception("Domain audit failed for %s", request.domain)
        raise HTTPException(
            status_code=500,
            detail=f"Domain audit failed: {exc}",
        ) from exc

    settings = get_settings()
    webhook_url = request.webhook_url or settings.discord_webhook_url

    if webhook_url and "YOUR_WEBHOOK" not in webhook_url:
        discord_service = DiscordService()
        background_tasks.add_task(
            discord_service.send_domain_report,
            webhook_url,
            report,
        )

    return DomainAuditResponse(
        status="completed",
        domain=request.domain,
        report=report,
    )
