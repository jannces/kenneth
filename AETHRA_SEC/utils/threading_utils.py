"""Threading primitives used to keep the Tkinter GUI responsive.

The GUI must never block, so every long-running operation (scanning, packet
capture, Snort listening, database writes) runs on a background worker.  Results
are marshalled back onto the Tk main thread through a thread-safe queue that the
GUI drains on a timer.

Module name is ``threading_utils`` (not ``threading``) so it never shadows the
standard library module.
"""

from __future__ import annotations

import queue
import threading
import traceback
from typing import Any, Callable, Optional


class StoppableThread(threading.Thread):
    """A daemon thread with a cooperative stop flag.

    Subclasses / target functions should periodically check :meth:`stopped`
    and exit cleanly.  Because it is a daemon, it will not keep the interpreter
    alive if the application exits unexpectedly.
    """

    def __init__(self, target: Optional[Callable] = None, name: Optional[str] = None,
                 args: tuple = (), kwargs: Optional[dict] = None, daemon: bool = True):
        super().__init__(name=name, daemon=daemon)
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def wait(self, timeout: float) -> bool:
        """Sleep up to ``timeout`` seconds, returning early if stopped."""
        return self._stop_event.wait(timeout)

    def run(self) -> None:  # pragma: no cover - exercised at runtime
        if self._target is not None:
            self._target(self, *self._args, **self._kwargs)


class TaskResult:
    """Container for the outcome of a background worker task."""

    __slots__ = ("kind", "payload", "error")

    def __init__(self, kind: str, payload: Any = None, error: Optional[str] = None):
        self.kind = kind
        self.payload = payload
        self.error = error


def run_async(fn: Callable, *args,
              on_success: Optional[Callable[[Any], None]] = None,
              on_error: Optional[Callable[[Exception], None]] = None,
              result_queue: Optional["queue.Queue"] = None,
              name: str = "aethra-worker", **kwargs) -> threading.Thread:
    """Run ``fn`` on a daemon thread.

    Callbacks are invoked from the worker thread; if they touch the GUI they
    must re-schedule onto the Tk thread (usually via ``result_queue``).  When a
    ``result_queue`` is provided the result/exception is also pushed onto it so
    the GUI can drain it safely.
    """

    def _wrapper() -> None:
        try:
            value = fn(*args, **kwargs)
            if result_queue is not None:
                result_queue.put(TaskResult("success", value))
            if on_success is not None:
                on_success(value)
        except Exception as exc:  # noqa: BLE001 - surface every failure
            tb = traceback.format_exc()
            if result_queue is not None:
                result_queue.put(TaskResult("error", tb, str(exc)))
            if on_error is not None:
                on_error(exc)

    thread = threading.Thread(target=_wrapper, name=name, daemon=True)
    thread.start()
    return thread


class ThreadSafeCounter:
    """A simple lock-protected integer counter."""

    def __init__(self, initial: int = 0):
        self._value = initial
        self._lock = threading.Lock()

    def increment(self, amount: int = 1) -> int:
        with self._lock:
            self._value += amount
            return self._value

    def reset(self, value: int = 0) -> None:
        with self._lock:
            self._value = value

    @property
    def value(self) -> int:
        with self._lock:
            return self._value
