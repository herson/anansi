"""Log setup for the entry points (the CLI and the web dashboard), never run on import."""
import logging
from logging.handlers import RotatingFileHandler
from os import PathLike
from pathlib import Path

DEFAULT_LOG_DIR = "logs"


def configure_logging(log_dir: str | PathLike[str] = DEFAULT_LOG_DIR) -> None:
    """Send INFO and above to a rotating `anansi.log` in log_dir, creating the directory."""
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        handlers=[RotatingFileHandler(directory / "anansi.log", maxBytes=5 * 1024 * 1024, backupCount=3)],
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
