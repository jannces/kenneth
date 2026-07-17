"""MySQL database access layer.

Responsibilities:

* Own a connection pool to MySQL (``mysql-connector-python``).
* Provide safe, **parameterised** query helpers (no string interpolation) to
  prevent SQL injection.
* Automatically reconnect when the connection drops, satisfying the
  Availability requirement of the CIA triad.
* Create the schema and seed initial data on first run.

The layer exposes a small, deliberate API (``query``, ``query_one``,
``execute``, ``executemany``) rather than leaking raw cursors, keeping the
business layer decoupled from the driver.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from config import CONFIG, BASE_DIR
from logs.logger import LOG

try:
    import mysql.connector
    from mysql.connector import errorcode
    from mysql.connector.pooling import MySQLConnectionPool
    _MYSQL_AVAILABLE = True
except Exception:  # pragma: no cover - driver optional at import time
    mysql = None  # type: ignore
    errorcode = None  # type: ignore
    MySQLConnectionPool = None  # type: ignore
    _MYSQL_AVAILABLE = False


class DatabaseError(Exception):
    """Raised when a database operation cannot be completed."""


class Database:
    """Thread-safe MySQL facade with pooling and auto-reconnect."""

    def __init__(self) -> None:
        self._pool: Optional["MySQLConnectionPool"] = None
        self._lock = threading.Lock()
        self._connected = False
        self._db_config = CONFIG.database

    # -- lifecycle -----------------------------------------------------------
    @property
    def available(self) -> bool:
        """Whether the MySQL driver is importable in this environment."""
        return _MYSQL_AVAILABLE

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, ensure_schema: bool = True) -> bool:
        """Establish the pool.  Returns True on success.

        On the very first connection this will create the database/schema and
        seed default data when ``ensure_schema`` is True.
        """
        if not _MYSQL_AVAILABLE:
            LOG.error("database", "driver_missing",
                      "mysql-connector-python is not installed.")
            return False

        with self._lock:
            try:
                if ensure_schema:
                    self._ensure_database_exists()
                self._pool = MySQLConnectionPool(
                    pool_name=self._db_config.pool_name,
                    pool_size=self._db_config.pool_size,
                    pool_reset_session=True,
                    **self._db_config.connection_kwargs(include_db=True),
                )
                self._connected = True
                LOG.info("database", "connected",
                         f"Pool '{self._db_config.pool_name}' -> "
                         f"{self._db_config.host}:{self._db_config.port}/"
                         f"{self._db_config.database}")
            except Exception as exc:  # noqa: BLE001
                self._connected = False
                LOG.exception("database", "connect_failed", exc)
                return False

        if ensure_schema:
            try:
                self.initialize_schema()
            except Exception as exc:  # noqa: BLE001
                LOG.exception("database", "schema_init_failed", exc)
                return False
        return True

    def _ensure_database_exists(self) -> None:
        """Create the target schema if the server does not yet have it."""
        conn = mysql.connector.connect(**self._db_config.connection_kwargs(include_db=False))
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{self._db_config.database}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            conn.commit()
            cursor.close()
        finally:
            conn.close()

    def initialize_schema(self) -> None:
        """Execute schema.sql then seed defaults (idempotent)."""
        schema_path = Path(BASE_DIR) / "database" / "schema.sql"
        if not schema_path.exists():
            raise DatabaseError(f"schema.sql not found at {schema_path}")
        sql = schema_path.read_text(encoding="utf-8")
        statements = [s.strip() for s in sql.split(";") if s.strip()]
        conn = self._raw_connection()
        try:
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)
            conn.commit()
            cursor.close()
            LOG.info("database", "schema_ready", f"Applied {len(statements)} statements.")
        finally:
            conn.close()

        # Seed defaults (import here to avoid a cycle at module import time).
        from database.seed import seed_defaults

        seed_defaults(self)

    # -- connection acquisition with reconnect -------------------------------
    def _raw_connection(self, retries: int = 3):
        """Return a pooled connection, reconnecting the pool if it dropped."""
        if not _MYSQL_AVAILABLE:
            raise DatabaseError("MySQL driver unavailable.")
        last_exc: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            try:
                if self._pool is None:
                    raise DatabaseError("Database pool not initialised.")
                conn = self._pool.get_connection()
                if not conn.is_connected():
                    conn.reconnect(attempts=2, delay=1)
                self._connected = True
                return conn
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                self._connected = False
                LOG.warning("database", "reconnect",
                            f"Attempt {attempt}/{retries} failed: {exc}")
                time.sleep(min(2 ** attempt, 8))
                # Try to rebuild the pool on the next loop.
                try:
                    self._pool = MySQLConnectionPool(
                        pool_name=self._db_config.pool_name,
                        pool_size=self._db_config.pool_size,
                        pool_reset_session=True,
                        **self._db_config.connection_kwargs(include_db=True),
                    )
                except Exception:  # noqa: BLE001
                    pass
        raise DatabaseError(f"Could not obtain a database connection: {last_exc}")

    # -- query helpers -------------------------------------------------------
    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        """Run a SELECT and return a list of dict rows."""
        conn = self._raw_connection()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            cursor.close()
            return rows
        except Exception as exc:  # noqa: BLE001
            LOG.exception("database", f"query_failed: {sql[:80]}", exc)
            raise DatabaseError(str(exc)) from exc
        finally:
            conn.close()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Sequence[Any] = (), commit: bool = True) -> int:
        """Run an INSERT/UPDATE/DELETE.  Returns lastrowid (or rowcount)."""
        conn = self._raw_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            if commit:
                conn.commit()
            result = cursor.lastrowid or cursor.rowcount
            cursor.close()
            return result
        except Exception as exc:  # noqa: BLE001
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            LOG.exception("database", f"execute_failed: {sql[:80]}", exc)
            raise DatabaseError(str(exc)) from exc
        finally:
            conn.close()

    def executemany(self, sql: str, seq_params: Sequence[Sequence[Any]], commit: bool = True) -> int:
        """Bulk insert/update.  Returns affected rowcount."""
        if not seq_params:
            return 0
        conn = self._raw_connection()
        try:
            cursor = conn.cursor()
            cursor.executemany(sql, seq_params)
            if commit:
                conn.commit()
            count = cursor.rowcount
            cursor.close()
            return count
        except Exception as exc:  # noqa: BLE001
            try:
                conn.rollback()
            except Exception:  # noqa: BLE001
                pass
            LOG.exception("database", "executemany_failed", exc)
            raise DatabaseError(str(exc)) from exc
        finally:
            conn.close()

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        """Return the first column of the first row (or None)."""
        row = self.query_one(sql, params)
        if not row:
            return None
        return next(iter(row.values()))

    def ping(self) -> bool:
        """Lightweight health check used by the status bar / reconnect timer."""
        try:
            self.scalar("SELECT 1")
            self._connected = True
            return True
        except Exception:  # noqa: BLE001
            self._connected = False
            return False


# Global singleton database handle.
DB = Database()
