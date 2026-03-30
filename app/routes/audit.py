from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.config import Settings, get_settings
from app.models.requests import AuditRequest
from app.models.responses import AuditResponse
from app.services.audit import AuditService

router = APIRouter(tags=["Audit"])


@router.post("/audit", response_model=AuditResponse, status_code=202)
async def launch_audit(
    request: AuditRequest,
    background_tasks: BackgroundTasks,
) -> AuditResponse:
    """Launch a WordPress security audit.

    The scan runs in the background. Results are delivered to the
    configured Discord webhook.

    - **url**: Target WordPress site URL (required).
    - **webhook_url**: Discord webhook URL override (optional).
    - **api_token**: WPScan API token override (optional).
    """
    settings: Settings = get_settings()

    webhook_url = request.webhook_url or settings.discord_webhook_url
    if not webhook_url or "YOUR_WEBHOOK" in webhook_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "Discord webhook not configured. "
                "Provide 'webhook_url' in the request body or set "
                "DISCORD_WEBHOOK_URL in the .env file."
            ),
        )

    audit_service = AuditService(settings)
    background_tasks.add_task(
        audit_service.run,
        url=request.url,
        webhook_url=webhook_url,
        api_token=request.api_token,
    )

    return AuditResponse(
        status="accepted",
        message=(
            f"Audit started for {request.url}. "
            "Results will be sent to Discord."
        ),
        url=request.url,
    )
