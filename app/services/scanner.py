import asyncio
import contextlib
import json
import logging
import tempfile
from pathlib import Path

from app.config import Settings
from app.constants import (
    WPSCAN_DEFAULT_ENUMERATE,
    WPSCAN_DEFAULT_PLUGINS_DETECTION,
    ScanExitCode,
)
from app.exceptions.scanner import WPScanError, WPScanTimeoutError

logger = logging.getLogger(__name__)


class ScannerService:
    """Execute WPScan against a target URL and return raw JSON results.

    Args:
        settings: Application settings instance.

    """

    def __init__(self, settings: Settings) -> None:
        """Initialise with application *settings*."""
        self._settings = settings

    async def scan(
        self,
        url: str,
        *,
        api_token: str | None = None,
        extra_args: list[str] | None = None,
    ) -> dict:
        """Run WPScan on *url* and return the parsed JSON output.

        Args:
            url: Target WordPress URL.
            api_token: Optional WPScan API token override.
            extra_args: Additional CLI arguments forwarded to WPScan.

        Returns:
            Parsed JSON output as a dictionary.

        Raises:
            WPScanError: If WPScan exits with an unexpected code or produces
                invalid output.
            WPScanTimeoutError: If the scan exceeds the configured timeout.

        """
        token = api_token or self._settings.wpscan_api_token
        output_file = self._create_temp_output_path()

        try:
            cmd = self._build_command(url, output_file, token, extra_args)
            logger.info("Starting WPScan for %s", url)
            logger.debug("Command: %s", " ".join(cmd))

            raw_json = await self._execute(cmd, output_file)
            results = self._parse_json(raw_json)

            logger.info("Scan completed for %s", url)
            return results
        finally:
            self._cleanup(output_file)

    # Private helpers

    @staticmethod
    def _create_temp_output_path() -> str:
        """Create a temporary file path for WPScan JSON output."""
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            prefix="wpscan_",
            delete=False,
            mode="w",
        ) as tmp:
            return tmp.name

    def _build_command(
        self,
        url: str,
        output_file: str,
        token: str,
        extra_args: list[str] | None,
    ) -> list[str]:
        """Assemble the WPScan CLI command."""
        cmd = [
            self._settings.wpscan_path,
            "--url", url,
            "--format", "json",
            "--output", output_file,
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",
            "--enumerate", WPSCAN_DEFAULT_ENUMERATE,
            "--plugins-detection", WPSCAN_DEFAULT_PLUGINS_DETECTION,
        ]
        if token:
            cmd.extend(["--api-token", token])
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    async def _execute(self, cmd: list[str], output_file: str) -> str:
        """Execute the WPScan process and return the raw JSON string."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            _stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self._settings.scan_timeout,
            )
        except TimeoutError as exc:
            process.kill()
            await process.communicate()
            raise WPScanTimeoutError(self._settings.scan_timeout) from exc

        stderr_text = stderr.decode("utf-8", errors="replace")
        return_code = process.returncode or 0

        acceptable_codes = {ScanExitCode.SUCCESS, ScanExitCode.VULNERABILITIES_FOUND}
        if return_code not in acceptable_codes:
            output_path = Path(output_file)
            if not output_path.exists() or output_path.stat().st_size == 0:
                logger.error(
                    "WPScan failed (exit code %d): %s",
                    return_code,
                    stderr_text[:500],
                )
                raise WPScanError(
                    f"WPScan exited with code {return_code}",
                    stderr=stderr_text,
                    return_code=return_code,
                )

        return self._read_output_file(output_file, stderr_text, return_code)

    @staticmethod
    def _read_output_file(output_file: str, stderr_text: str, return_code: int) -> str:
        """Read and validate the WPScan output file."""
        output_path = Path(output_file)

        if not output_path.exists():
            raise WPScanError(
                "WPScan output file was not created",
                stderr=stderr_text,
                return_code=return_code,
            )

        raw_json = output_path.read_text(encoding="utf-8")
        if not raw_json.strip():
            raise WPScanError(
                "WPScan output file is empty",
                stderr=stderr_text,
                return_code=return_code,
            )

        return raw_json

    @staticmethod
    def _parse_json(raw_json: str) -> dict:
        """Parse raw JSON string into a dictionary."""
        try:
            return json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise WPScanError(
                f"Failed to parse WPScan JSON output: {exc}",
                stderr=raw_json[:500],
            ) from exc

    @staticmethod
    def _cleanup(output_file: str) -> None:
        """Remove the temporary output file."""
        with contextlib.suppress(OSError):
            Path(output_file).unlink(missing_ok=True)
