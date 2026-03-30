from app.config import Settings


class TestSettings:
    def test_default_values(self):
        settings = Settings(
            discord_webhook_url="",
            wpscan_api_token="",
            _env_file=None,
        )
        assert settings.wpscan_path == "wpscan"
        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 8000
        assert settings.scan_timeout == 300

    def test_is_discord_configured_with_valid_url(self):
        settings = Settings(
            discord_webhook_url="https://discord.com/api/webhooks/123/abc",
            _env_file=None,
        )
        assert settings.is_discord_configured is True

    def test_is_discord_configured_with_placeholder(self):
        settings = Settings(
            discord_webhook_url="https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN",
            _env_file=None,
        )
        assert settings.is_discord_configured is False

    def test_is_discord_configured_when_empty(self):
        settings = Settings(discord_webhook_url="", _env_file=None)
        assert settings.is_discord_configured is False

    def test_is_wpscan_token_configured(self):
        settings = Settings(wpscan_api_token="my-token", _env_file=None)
        assert settings.is_wpscan_token_configured is True

    def test_is_wpscan_token_not_configured(self):
        settings = Settings(wpscan_api_token="", _env_file=None)
        assert settings.is_wpscan_token_configured is False

    def test_custom_port_and_host(self):
        settings = Settings(
            api_host="127.0.0.1",
            api_port=9000,
            _env_file=None,
        )
        assert settings.api_host == "127.0.0.1"
        assert settings.api_port == 9000
