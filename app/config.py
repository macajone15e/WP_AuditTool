"""Application settings loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration.

    All values can be overridden via environment variables or a ``.env`` file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Discord
    discord_webhook_url: str = ""

    # WPScan
    wpscan_api_token: str = ""
    wpscan_path: str = "wpscan"

    # API server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Scan behaviour
    scan_timeout: int = 300

    @property
    def is_discord_configured(self) -> bool:
        """Return ``True`` if a valid Discord webhook URL is set."""
        return bool(self.discord_webhook_url) and "YOUR_WEBHOOK" not in self.discord_webhook_url

    @property
    def is_wpscan_token_configured(self) -> bool:
        """Return ``True`` if a WPScan API token is set."""
        return bool(self.wpscan_api_token)


def get_settings() -> Settings:
    """Create and return a fresh ``Settings`` instance."""
    return Settings()
