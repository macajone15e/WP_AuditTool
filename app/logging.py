import logging


def setup_logging() -> None:
    """Configure the root logger with a structured format."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(name)-28s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )
