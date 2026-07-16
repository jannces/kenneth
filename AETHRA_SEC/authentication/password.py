"""Password hashing utilities built on bcrypt.

Passwords are NEVER stored in plain text.  This module is the only place that
knows how to hash/verify, so the algorithm can be changed in one location.
"""

from __future__ import annotations

from logs.logger import LOG

try:
    import bcrypt
    _BCRYPT_AVAILABLE = True
except Exception:  # pragma: no cover - dependency optional at import time
    bcrypt = None  # type: ignore
    _BCRYPT_AVAILABLE = False

# bcrypt truncates input at 72 bytes; we guard against that explicitly.
_MAX_BCRYPT_BYTES = 72


def hash_password(plain: str, rounds: int = 12) -> str:
    """Return a bcrypt hash (utf-8 string) for ``plain``.

    :raises RuntimeError: if bcrypt is unavailable in the environment.
    """
    if not _BCRYPT_AVAILABLE:
        raise RuntimeError("bcrypt is not installed; cannot hash passwords securely.")
    raw = plain.encode("utf-8")[:_MAX_BCRYPT_BYTES]
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(raw, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if ``plain`` matches the stored ``hashed`` value."""
    if not _BCRYPT_AVAILABLE:
        LOG.error("auth", "bcrypt_missing", "Cannot verify password without bcrypt.")
        return False
    if not hashed:
        return False
    try:
        raw = plain.encode("utf-8")[:_MAX_BCRYPT_BYTES]
        return bcrypt.checkpw(raw, hashed.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        LOG.error("auth", "verify_error", str(exc))
        return False


def is_available() -> bool:
    return _BCRYPT_AVAILABLE
