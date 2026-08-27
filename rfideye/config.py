"""Runtime configuration: filesystem layout, logging and user preferences.

Everything RFIDeye persists lives under a single, per-user directory so the
tool never litters the working directory:

``$XDG_DATA_HOME/rfideye`` (Linux, default ``~/.local/share/rfideye``)

Layout::

    <data_dir>/
    |-- rfideye.db        # SQLite scan history
    |-- logs/rfideye.log  # rotating structured log
    |-- dumps/            # JSON/CSV exports
    `-- reports/          # Markdown/HTML session reports
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

LOG_LEVELS: Final[tuple[str, ...]] = ("debug", "info", "warning", "error")

#: Environment variable that overrides the auto-detected ``pm3`` binary.
ENV_PM3_BIN: Final[str] = "RFIDEYE_PM3_BIN"
#: Environment variable that overrides the data directory.
ENV_DATA_DIR: Final[str] = "RFIDEYE_DATA_DIR"


def _default_data_dir() -> Path:
    """Return the platform-appropriate data directory (never creates it)."""
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override).expanduser()

    if os.name == "nt":  # pragma: no cover - Windows convenience only
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "rfideye"

    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "rfideye"


@dataclass(frozen=True, slots=True)
class Paths:
    """Resolved filesystem locations used across the application."""

    data_dir: Path

    @classmethod
    def default(cls) -> Paths:
        return cls(data_dir=_default_data_dir())

    @property
    def database(self) -> Path:
        return self.data_dir / "rfideye.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "rfideye.log"

    @property
    def dump_dir(self) -> Path:
        return self.data_dir / "dumps"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure(self) -> Paths:
        """Create every directory RFIDeye needs.  Idempotent."""
        for directory in (self.data_dir, self.log_dir, self.dump_dir, self.report_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self


def setup_logging(paths: Paths, level: str = "info", *, console: bool = False) -> logging.Logger:
    """Configure the ``rfideye`` logger hierarchy.

    Logs always go to a rotating file (5 x 1 MiB).  The TUI owns stdout, so the
    console handler is opt-in and only used by ``--verbose`` / ``doctor``.

    Args:
        paths: Resolved application paths (directories are created here).
        level: One of :data:`LOG_LEVELS`.
        console: Also mirror records to stderr.

    Returns:
        The configured root logger for the ``rfideye`` namespace.
    """
    if level.lower() not in LOG_LEVELS:
        raise ValueError(f"invalid log level {level!r}; expected one of {LOG_LEVELS}")

    paths.ensure()
    logger = logging.getLogger("rfideye")
    logger.setLevel(getattr(logging, level.upper()))
    logger.propagate = False

    # Re-entrant safe: drop previously installed handlers before re-adding.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        paths.log_file, maxBytes=1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        logger.addHandler(stream)

    return logger
