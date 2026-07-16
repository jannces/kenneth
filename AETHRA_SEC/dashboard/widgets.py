"""Reusable dashboard widgets (stat cards, section frames, empty states).

Built on ttkbootstrap so they inherit the active theme.  Kept free of business
logic - pages feed them values.
"""

from __future__ import annotations

from typing import Optional

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, X, YES

from gui.theme import severity_bootstyle, severity_symbol


class StatCard(ttk.Frame):
    """A summary card: title, big value, optional subtitle and accent colour."""

    def __init__(self, master, title: str, value: str = "0", subtitle: str = "",
                 bootstyle: str = "primary", icon: str = "", **kwargs):
        super().__init__(master, bootstyle=bootstyle, padding=14, **kwargs)
        self.columnconfigure(0, weight=1)

        header = ttk.Frame(self, bootstyle=bootstyle)
        header.grid(row=0, column=0, sticky="ew")
        self._title = ttk.Label(header, text=f"{icon} {title}".strip(),
                                bootstyle=f"inverse-{bootstyle}", font=("Segoe UI", 10))
        self._title.pack(side=LEFT)

        self._value = ttk.Label(self, text=value, bootstyle=f"inverse-{bootstyle}",
                                font=("Segoe UI", 24, "bold"))
        self._value.grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._subtitle = ttk.Label(self, text=subtitle,
                                   bootstyle=f"inverse-{bootstyle}",
                                   font=("Segoe UI", 9))
        self._subtitle.grid(row=2, column=0, sticky="w")

    def set_value(self, value: str, subtitle: Optional[str] = None) -> None:
        self._value.configure(text=str(value))
        if subtitle is not None:
            self._subtitle.configure(text=subtitle)


class SectionFrame(ttk.Labelframe):
    """A titled content section."""

    def __init__(self, master, title: str, **kwargs):
        super().__init__(master, text=title, padding=12, **kwargs)


class EmptyState(ttk.Frame):
    """Friendly placeholder shown when a table/section has no data yet."""

    def __init__(self, master, message: str = "No data yet.", icon: str = "📭", **kwargs):
        super().__init__(master, padding=24, **kwargs)
        ttk.Label(self, text=icon, font=("Segoe UI", 28)).pack()
        ttk.Label(self, text=message, bootstyle="secondary",
                  font=("Segoe UI", 11)).pack(pady=(6, 0))


class SeverityBadge(ttk.Label):
    """A coloured, symbol-prefixed severity label (colour is not the only cue)."""

    def __init__(self, master, severity: str, **kwargs):
        super().__init__(
            master,
            text=f"{severity_symbol(severity)} {severity}",
            bootstyle=f"inverse-{severity_bootstyle(severity)}",
            padding=(6, 2),
            **kwargs,
        )
