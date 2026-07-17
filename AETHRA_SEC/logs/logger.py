"""Central logging engine for AETHRA-SEC.

Two destinations are supported and used together:

* **Rotating log files** on disk - always available, even before the database
  is reachable.  This guarantees we never lose an error report.
* **MySQL tables** (``system_logs`` / ``activity_logs``) - attached lazily once
  the database layer exists so the GUI Logs page can query structured history.

The engine is intentionally decoupled from the database module to avoid an
import cycle: the database layer registers itself via :func:`attach_database`.
"""

from __future__ import annotations

import logging
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from config import BASE_DIR
from utils.constants import LogLevel
from utils.helpers import now

_LOG_DIR = BASE_DIR / "logs" / "files"
_LOG_DIR.mkdir(parents=True, exist_ok=True)


def _build_file_logger() -> logging.Logger:
    logger = logging.getLogger("aethra")
    if logger.handlers:  # already configured
        return logger
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # General application log.
    app_handler = RotatingFileHandler(
        _LOG_DIR / "aethra.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    app_handler.setFormatter(formatter)
    app_handler.setLevel(logging.INFO)
    logger.addHandler(app_handler)

    # Dedicated error log (WARNING and above).
    err_handler = RotatingFileHandler(
        _LOG_DIR / "errors.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    err_handler.setFormatter(formatter)
    err_handler.setLevel(logging.WARNING)
    logger.addHandler(err_handler)

    # Console handler for laboratory debugging.
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)
    logger.addHandler(console)
    return logger


class LoggingEngine:
    """Thread-safe facade over file + database logging."""

    def __init__(self) -> None:
        self._file_logger = _build_file_logger()
        self._db = None  # set by attach_database
        self._lock = threading.Lock()
        # Re-entrancy guard: the database layer logs its own errors through this
        # engine, and this engine writes logs to the database.  Without a guard,
        # a failing DB write would recurse forever (log -> db.execute fails ->
        # log -> ...).  This thread-local flag breaks that cycle: while we are
        # persisting a log to the DB, any nested log call is file-only.
        self._reentry = threading.local()

    # -- database wiring -----------------------------------------------------
    def attach_database(self, database: Any) -> None:
        """Register the database layer so structured logs are persisted."""
        with self._lock:
            self._db = database

    # -- core system logging -------------------------------------------------
    def log(self, module: str, action: str, description: str = "",
            level: LogLevel | str = LogLevel.INFO, user: str = "system") -> None:
        """Write a structured system-log entry to file and (if available) MySQL."""
        level_str = level.value if isinstance(level, LogLevel) else str(level)
        message = f"[{module}] {action}: {description}" if description else f"[{module}] {action}"
        self._file_logger.log(self._py_level(level_str), message)

        db = self._db
        if db is None:
            return
        # If we are already inside a DB persist (e.g. the DB layer is logging a
        # failed query), stay file-only to avoid infinite recursion.
        if getattr(self._reentry, "active", False):
            return
        self._reentry.active = True
        try:
            db.execute(
                """INSERT INTO system_logs (timestamp, module, action, description, user, severity)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                (now(), module, action, description, user, level_str),
                commit=True,
            )
        except Exception as exc:  # noqa: BLE001 - logging must never raise
            self._file_logger.error("Failed to persist system log to DB: %s", exc)
        finally:
            self._reentry.active = False

    # -- convenience wrappers ------------------------------------------------
    def info(self, module: str, action: str, description: str = "", user: str = "system") -> None:
        self.log(module, action, description, LogLevel.INFO, user)

    def warning(self, module: str, action: str, description: str = "", user: str = "system") -> None:
        self.log(module, action, description, LogLevel.WARNING, user)

    def error(self, module: str, action: str, description: str = "", user: str = "system") -> None:
        self.log(module, action, description, LogLevel.ERROR, user)

    def critical(self, module: str, action: str, description: str = "", user: str = "system") -> None:
        self.log(module, action, description, LogLevel.CRITICAL, user)

    def exception(self, module: str, description: str, exc: BaseException, user: str = "system") -> None:
        """Log an exception with its traceback to the error file + DB."""
        self._file_logger.exception("[%s] %s", module, description)
        self.log(module, "Exception", f"{description}: {exc}", LogLevel.ERROR, user)

    @staticmethod
    def _py_level(level_str: str) -> int:
        return {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }.get(level_str, logging.INFO)


# Global singleton used everywhere.
LOG = LoggingEngine()
