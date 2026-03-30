import json
from unittest.mock import MagicMock, patch

import pytest

from app.config import Settings
from app.exceptions.scanner import WPScanError, WPScanTimeoutError
from app.services.scanner import ScannerService


class TestScannerService:
    def setup_method(self):
        self.settings = Settings(
            wpscan_path="/usr/bin/wpscan",
            wpscan_api_token="test-token",
            scan_timeout=60,
            _env_file=None,
        )
        self.scanner = ScannerService(self.settings)

    def test_build_command_basic(self):
        cmd = self.scanner._build_command(
            url="https://example.com",
            output_file="/tmp/out.json",
            token="",
            extra_args=None,
        )
        assert "/usr/bin/wpscan" in cmd
        assert "--url" in cmd
        assert "https://example.com" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    def test_build_command_with_token(self):
        cmd = self.scanner._build_command(
            url="https://example.com",
            output_file="/tmp/out.json",
            token="my-token",
            extra_args=None,
        )
        assert "--api-token" in cmd
        assert "my-token" in cmd

    def test_build_command_without_token(self):
        cmd = self.scanner._build_command(
            url="https://example.com",
            output_file="/tmp/out.json",
            token="",
            extra_args=None,
        )
        assert "--api-token" not in cmd

    def test_build_command_with_extra_args(self):
        cmd = self.scanner._build_command(
            url="https://example.com",
            output_file="/tmp/out.json",
            token="",
            extra_args=["--max-threads", "10"],
        )
        assert "--max-threads" in cmd
        assert "10" in cmd

    def test_parse_json_valid(self):
        data = {"version": {"number": "6.4.2"}}
        result = self.scanner._parse_json(json.dumps(data))
        assert result == data

    def test_parse_json_invalid(self):
        with pytest.raises(WPScanError, match="Failed to parse"):
            self.scanner._parse_json("not valid json")

    def test_cleanup_nonexistent_file(self):
        # Should not raise
        self.scanner._cleanup("/tmp/nonexistent_file_wpscan.json")

    @pytest.mark.asyncio()
    async def test_scan_timeout(self):
        mock_process = MagicMock()
        mock_process.kill = MagicMock()

        async def fake_post_kill_communicate():
            return b"", b""

        mock_process.communicate = fake_post_kill_communicate

        with (
            patch("app.services.scanner.asyncio.create_subprocess_exec") as mock_exec,
            patch("app.services.scanner.asyncio.wait_for") as mock_wait,
        ):
            mock_exec.return_value = mock_process
            mock_wait.side_effect = TimeoutError()

            with pytest.raises(WPScanTimeoutError):
                await self.scanner.scan("https://example.com")


class TestWPScanError:
    def test_error_message(self):
        err = WPScanError("test error", stderr="some output", return_code=4)
        assert str(err) == "test error"
        assert err.stderr == "some output"
        assert err.return_code == 4

    def test_default_values(self):
        err = WPScanError("test")
        assert err.stderr == ""
        assert err.return_code == -1


class TestWPScanTimeoutError:
    def test_inherits_from_wpscan_error(self):
        err = WPScanTimeoutError(300)
        assert isinstance(err, WPScanError)
        assert err.timeout_seconds == 300
        assert "300s" in str(err)
