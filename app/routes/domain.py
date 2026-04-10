import logging

from fastapi import APIRouter, HTTPException

from app.models.requests import DomainAuditRequest
from app.models.responses import DomainAuditResponse
from app.services.domain import DomainSecurityService

router = APIRouter(tags=["Domain Security"])

logger = logging.getLogger(__name__)


@router.post("/domain-audit", response_model=DomainAuditResponse)
async def domain_audit(request: DomainAuditRequest) -> DomainAuditResponse:
    """Run domain-level security checks (WHOIS, DNS, SSL, HSTS, DNSSEC).

    Returns the full report synchronously.

    - **domain**: Target domain name (required).
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

    return DomainAuditResponse(
        status="completed",
        domain=request.domain,
        report=report,
    )
