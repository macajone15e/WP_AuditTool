"""Health-check route."""

from fastapi import APIRouter

from app.config import Settings, get_settings
from app.models.responses import HealthResponse

router = APIRouter(tags=["System"])

APP_VERSION = "1.0.0"


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return the current health status of the API and its dependencies."""
    settings: Settings = get_settings()
    return HealthResponse(
        status="ok" if settings.is_discord_configured else "degraded",
        wpscan_token_configured=settings.is_wpscan_token_configured,
        discord_configured=settings.is_discord_configured,
        version=APP_VERSION,
    )
