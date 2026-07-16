"""Centralised configuration for AETHRA-SEC.

All tunable values live here so the rest of the codebase never hard-codes
credentials, file paths, or magic numbers.  Sensitive values (database
credentials, tool paths) are read from environment variables / a local ``.env``
file, while non-sensitive defaults are provided inline.

The configuration is exposed both as a module-level singleton (``CONFIG``) and
through helper accessors.  A subset of settings can also be overridden at
runtime from the ``settings`` MySQL table; :meth:`AppConfig.apply_overrides`
merges those in once the database layer is available.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Optional .env support.  We degrade gracefully if python-dotenv is missing so
# the module can always be imported (e.g. during unit tests).
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:  # pragma: no cover - dotenv is optional at import time
    pass


# Base directory of the project (used to resolve relative resource paths).
BASE_DIR: Path = Path(__file__).resolve().parent

# Application metadata.
APP_NAME: str = "AETHRA-SEC"
APP_FULL_NAME: str = (
    "A Unified System for Automated Penetration Testing with Real-Time "
    "Network Traffic Analysis and Immediate Threat Mitigation Recommender"
)
APP_VERSION: str = "1.0.0"
APP_ORGANIZATION: str = "Educational Cybersecurity Laboratory"


def _env(key: str, default: str = "") -> str:
    """Return an environment variable, falling back to ``default``."""
    value = os.environ.get(key)
    return value if value is not None and value != "" else default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


@dataclass
class DatabaseConfig:
    """MySQL connection parameters."""

    host: str = field(default_factory=lambda: _env("AETHRA_DB_HOST", "localhost"))
    port: int = field(default_factory=lambda: _env_int("AETHRA_DB_PORT", 3306))
    database: str = field(default_factory=lambda: _env("AETHRA_DB_NAME", "aethra_sec"))
    user: str = field(default_factory=lambda: _env("AETHRA_DB_USER", "root"))
    password: str = field(default_factory=lambda: _env("AETHRA_DB_PASSWORD", ""))
    pool_name: str = "aethra_pool"
    pool_size: int = 8
    connect_timeout: int = 8

    def connection_kwargs(self, include_db: bool = True) -> Dict[str, Any]:
        """Build kwargs for ``mysql.connector.connect``.

        When ``include_db`` is False the database name is omitted so callers can
        create the schema on a fresh server.
        """
        kwargs: Dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "connection_timeout": self.connect_timeout,
            "autocommit": False,
        }
        if include_db:
            kwargs["database"] = self.database
        return kwargs


@dataclass
class NmapConfig:
    """Nmap / python-nmap integration settings."""

    executable: str = field(default_factory=lambda: _env("AETHRA_NMAP_PATH", "nmap"))
    default_scan_type: str = "quick"
    max_threads: int = 4
    scan_timeout: int = 600  # seconds
    service_detection: bool = True
    version_detection: bool = True
    os_detection: bool = True
    host_discovery: bool = True


@dataclass
class SnortConfig:
    """Snort IDS integration settings.

    AETHRA-SEC listens for alerts over an Alert Socket (IPC).  On Windows the
    socket is exposed as a TCP loopback endpoint.
    """

    snort_dir: str = field(default_factory=lambda: _env("AETHRA_SNORT_DIR", r"C:\\Snort"))
    executable: str = field(
        default_factory=lambda: _env("AETHRA_SNORT_EXE", r"C:\\Snort\\bin\\snort.exe")
    )
    config_file: str = field(
        default_factory=lambda: _env("AETHRA_SNORT_CONF", r"C:\\Snort\\etc\\snort.conf")
    )
    rules_dir: str = field(
        default_factory=lambda: _env("AETHRA_SNORT_RULES", r"C:\\Snort\\rules")
    )
    alert_host: str = field(
        default_factory=lambda: _env("AETHRA_SNORT_ALERT_HOST", "127.0.0.1")
    )
    alert_port: int = field(
        default_factory=lambda: _env_int("AETHRA_SNORT_ALERT_PORT", 9000)
    )
    auto_restart: bool = True
    enable_notifications: bool = True
    reconnect_delay: int = 5  # seconds between reconnect attempts


@dataclass
class MonitoringConfig:
    """PyShark capture / traffic analysis settings."""

    interface: str = field(default_factory=lambda: _env("AETHRA_CAPTURE_INTERFACE", ""))
    packet_buffer_size: int = 5000
    capture_filter: str = ""  # BPF filter, empty = capture everything
    max_packet_rate: int = 0  # 0 = unlimited
    connection_timeout: int = 120  # seconds before an idle conversation is dropped
    persist_batch_size: int = 50  # packets buffered before a DB flush
    device_offline_after: int = 90  # seconds without traffic => device offline


@dataclass
class ReportConfig:
    """Report generation defaults."""

    output_dir: str = field(default_factory=lambda: _env("AETHRA_REPORT_DIR", "reports_output"))
    default_format: str = "pdf"
    auto_naming: bool = True
    organization_name: str = APP_ORGANIZATION
    laboratory_name: str = "Cybersecurity Laboratory"


@dataclass
class SecurityConfig:
    """Authentication / session hardening parameters."""

    max_login_attempts: int = 5
    lockout_minutes: int = 15
    session_timeout_minutes: int = 30
    auto_logout: bool = True
    audit_logging: bool = True
    # Password complexity policy.
    password_min_length: int = 8
    password_require_upper: bool = True
    password_require_lower: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = False


@dataclass
class UIConfig:
    """Presentation-layer defaults."""

    theme: str = field(default_factory=lambda: _env("AETHRA_THEME", "darkly"))
    refresh_interval_ms: int = field(
        default_factory=lambda: _env_int("AETHRA_REFRESH_INTERVAL_MS", 1000)
    )
    auto_start_monitoring: bool = True
    language: str = "en"
    window_min_width: int = 1200
    window_min_height: int = 760


@dataclass
class AppConfig:
    """Aggregate configuration object shared across the application."""

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    nmap: NmapConfig = field(default_factory=NmapConfig)
    snort: SnortConfig = field(default_factory=SnortConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    reports: ReportConfig = field(default_factory=ReportConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ui: UIConfig = field(default_factory=UIConfig)

    def report_path(self) -> Path:
        """Return the absolute report output directory, creating it if needed."""
        path = Path(self.reports.output_dir)
        if not path.is_absolute():
            path = BASE_DIR / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    # A mapping of ``settings`` table keys to (section, attribute) so runtime
    # overrides from the database can be merged into this object.
    _OVERRIDE_MAP = {
        "theme": ("ui", "theme"),
        "refresh_interval_ms": ("ui", "refresh_interval_ms"),
        "auto_start_monitoring": ("ui", "auto_start_monitoring"),
        "capture_interface": ("monitoring", "interface"),
        "connection_timeout": ("monitoring", "connection_timeout"),
        "default_scan_type": ("nmap", "default_scan_type"),
        "scan_timeout": ("nmap", "scan_timeout"),
        "session_timeout_minutes": ("security", "session_timeout_minutes"),
        "max_login_attempts": ("security", "max_login_attempts"),
        "report_default_format": ("reports", "default_format"),
        "organization_name": ("reports", "organization_name"),
        "laboratory_name": ("reports", "laboratory_name"),
    }

    def apply_overrides(self, settings: Dict[str, str]) -> None:
        """Merge string values from the ``settings`` table into this config.

        Types are coerced based on the current attribute value so a stored
        ``"1500"`` becomes an ``int`` when the target field is numeric.
        """
        for key, raw in settings.items():
            target = self._OVERRIDE_MAP.get(key)
            if not target:
                continue
            section_name, attr = target
            section = getattr(self, section_name)
            current = getattr(section, attr)
            try:
                if isinstance(current, bool):
                    coerced: Any = str(raw).strip().lower() in {"1", "true", "yes", "on"}
                elif isinstance(current, int):
                    coerced = int(raw)
                elif isinstance(current, float):
                    coerced = float(raw)
                else:
                    coerced = raw
                setattr(section, attr, coerced)
            except (TypeError, ValueError):
                # Ignore malformed override; keep the safe default.
                continue

    def as_dict(self) -> Dict[str, Any]:
        """Return a serialisable snapshot (passwords redacted)."""
        data = asdict(self)
        data["database"]["password"] = "***" if self.database.password else ""
        return data


# Module-level singleton used throughout the codebase.
CONFIG = AppConfig()
