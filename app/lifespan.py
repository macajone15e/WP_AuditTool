import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings

logger = logging.getLogger("wp_audit")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Log key configuration information on startup and shutdown."""
    settings = get_settings()

    logger.info("WP Audit Tool started")
    logger.info("  API: http://%s:%d", settings.api_host, settings.api_port)
    logger.info("  Docs: http://%s:%d/docs", settings.api_host, settings.api_port)

    if settings.is_discord_configured:
        logger.info("  Discord webhook: configured")
    else:
        logger.warning("  Discord webhook: NOT configured")

    if settings.is_wpscan_token_configured:
        logger.info("  WPScan API token: configured")
    else:
        logger.info("  WPScan API token: not set (limited results)")

    yield

    logger.info("WP Audit Tool stopped")
