"""Error logging + a decorator that guarantees the app never crashes.

The ``@guard`` decorator wraps risky callables so that any unexpected exception
is logged (file + DB) and swallowed with a safe fallback value, honouring the
spec's "Never crash" requirement while still recording a complete error trail.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional, TypeVar

from logs.logger import LOG

T = TypeVar("T")


def log_error(module: str, description: str, exc: BaseException, user: str = "system") -> None:
    """Record an exception through the central logging engine."""
    LOG.exception(module, description, exc, user=user)


def guard(module: str, fallback: Any = None, reraise: bool = False) -> Callable:
    """Decorator: run the wrapped function, logging and containing exceptions.

    :param module: logical module name used in the log entry.
    :param fallback: value returned when the wrapped function raises.
    :param reraise: if True the exception is re-raised after logging (useful for
        code paths where a caller wants to handle it but we still want the log).
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., Optional[T]]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> Optional[T]:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - intentional broad catch
                log_error(module, f"Unhandled error in {fn.__name__}", exc)
                if reraise:
                    raise
                return fallback

        return wrapper

    return decorator
