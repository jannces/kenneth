"""Base class for all content pages.

Provides a consistent header and lifecycle hooks the router calls:

* :meth:`on_show` - page becomes visible (load/refresh data).
* :meth:`on_refresh` - periodic tick from the GUI refresh timer (live pages).
* :meth:`on_hide` - page is navigated away from.
"""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, X, YES


class BasePage(ttk.Frame):
    """Common scaffolding for every page."""

    #: Whether the router should call :meth:`on_refresh` on the timer tick.
    live = False
    #: Page title shown in the content header.
    title = "Page"
    subtitle = ""

    def __init__(self, master, context):
        super().__init__(master, padding=16)
        self.context = context
        self._build_header()
        self.body = ttk.Frame(self)
        self.body.pack(fill=BOTH, expand=YES, pady=(10, 0))
        self.build()

    def _build_header(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill=X)
        text = ttk.Frame(header)
        text.pack(side=LEFT, fill=X, expand=YES)
        ttk.Label(text, text=self.title, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        if self.subtitle:
            ttk.Label(text, text=self.subtitle, bootstyle="secondary",
                      font=("Segoe UI", 10)).pack(anchor="w")
        self.header_actions = ttk.Frame(header)
        self.header_actions.pack(side="right")

    # ---- overridable lifecycle -------------------------------------------
    def build(self) -> None:
        """Construct page widgets (called once)."""

    def on_show(self) -> None:
        """Called each time the page is navigated to."""

    def on_refresh(self) -> None:
        """Called on the refresh timer for live pages."""

    def on_hide(self) -> None:
        """Called when navigating away."""

    # ---- helpers ----------------------------------------------------------
    def can(self, permission: str) -> bool:
        session = self.context.session
        return bool(session and session.can(permission))
