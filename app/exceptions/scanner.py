class WPScanError(Exception):
    """Base error for WPScan execution failures.

    Attributes:
        stderr: Captured standard error output from the WPScan process.
        return_code: Process exit code (``-1`` if unavailable).

    """

    def __init__(
        self,
        message: str,
        *,
        stderr: str = "",
        return_code: int = -1,
    ) -> None:
        """Initialise with a *message*, optional *stderr* output and *return_code*."""
        super().__init__(message)
        self.stderr = stderr
        self.return_code = return_code


class WPScanTimeoutError(WPScanError):
    """Raised when a WPScan process exceeds the configured timeout."""

    def __init__(self, timeout_seconds: int) -> None:
        """Initialise with the *timeout_seconds* that was exceeded."""
        super().__init__(
            f"WPScan process exceeded the {timeout_seconds}s timeout",
            return_code=-1,
        )
        self.timeout_seconds = timeout_seconds
