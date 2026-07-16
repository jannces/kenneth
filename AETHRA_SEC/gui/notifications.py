"""Non-intrusive toast notifications.

A small manager stacks transient toasts in the bottom-right of the main window.
Levels (info / success / warning / critical) each get a distinct colour and
icon; the icon + text carry the meaning so colour is not the only signal.
"""

from __future__ import annotations

from typing import List

import ttkbootstrap as ttk
from ttkbootstrap.constants import RIGHT, LEFT, X

from gui.theme import NOTIFY_STYLES


class Toast(ttk.Frame):
    """A single auto-dismissing toast."""

    def __init__(self, master, title: str, message: str, level: str,
                 on_close, **kwargs):
        bootstyle, icon = NOTIFY_STYLES.get(level, NOTIFY_STYLES["info"])
        super().__init__(master, bootstyle=bootstyle, padding=10, **kwargs)
        self._on_close = on_close

        top = ttk.Frame(self, bootstyle=bootstyle)
        top.pack(fill=X)
        ttk.Label(top, text=f"{icon} {title}", bootstyle=f"inverse-{bootstyle}",
                  font=("Segoe UI", 10, "bold")).pack(side=LEFT)
        ttk.Button(top, text="✕", bootstyle=f"{bootstyle}-link",
                   command=self._close, width=2).pack(side=RIGHT)
        ttk.Label(self, text=message, bootstyle=f"inverse-{bootstyle}",
                  font=("Segoe UI", 9), wraplength=260,
                  justify="left").pack(fill=X, pady=(4, 0))

    def _close(self) -> None:
        self._on_close(self)


class NotificationManager:
    """Stacks and auto-dismisses toasts over the main window."""

    def __init__(self, root, duration_ms: int = 6000) -> None:
        self._root = root
        self._duration = duration_ms
        self._active: List[Toast] = []

    def show(self, title: str, message: str, level: str = "info") -> None:
        # Ensure GUI-thread execution (alerts arrive from worker threads).
        self._root.after(0, lambda: self._show(title, message, level))

    def _show(self, title: str, message: str, level: str) -> None:
        toast = Toast(self._root, title, message, level, on_close=self._dismiss)
        self._active.append(toast)
        self._reposition()
        self._root.after(self._duration, lambda: self._dismiss(toast))

    def _dismiss(self, toast: Toast) -> None:
        if toast in self._active:
            self._active.remove(toast)
            try:
                toast.place_forget()
                toast.destroy()
            except Exception:  # noqa: BLE001
                pass
            self._reposition()

    def _reposition(self) -> None:
        y = 20
        for toast in reversed(self._active[-4:]):  # show at most 4 stacked
            toast.place(relx=1.0, x=-20, y=y, anchor="ne")
            toast.update_idletasks()
            y += toast.winfo_reqheight() + 10
