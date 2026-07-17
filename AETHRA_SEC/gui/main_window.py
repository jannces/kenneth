"""Main application shell: header, sidebar, content router, status bar.

Owns the single Tk root's post-login UI.  Instantiates pages lazily, routes
navigation, runs the GUI refresh timer that keeps live pages and the status bar
up to date, and wires alert notifications.  All heavy work happens on background
threads inside the services; this class only touches Tk widgets on the main
thread.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, Y, YES
from tkinter import messagebox

from config import APP_NAME, APP_VERSION, CONFIG
from gui.app_context import AppContext
from gui.notifications import NotificationManager
from gui.theme import NAV_ITEMS, status_symbol
from logs.logger import LOG
from utils.helpers import now


class MainWindow:
    """Builds and controls the authenticated application UI."""

    def __init__(self, root: ttk.Window, context: AppContext,
                 on_logout: Callable[[], None]):
        self.root = root
        self.context = context
        self._on_logout = on_logout
        self._pages: Dict[str, object] = {}
        self._current_page_id: Optional[str] = None
        self._nav_buttons: Dict[str, ttk.Button] = {}
        self._refresh_job: Optional[str] = None

        self.notifications = NotificationManager(root)
        context.subscribe_notifications(
            lambda title, msg, level: self.notifications.show(title, msg, level)
        )

        self._build()
        self._start_refresh_timer()
        self.navigate("dashboard")

    # ------------------------------------------------------------- build UI
    def _build(self) -> None:
        session = self.context.session
        self.root.title(f"{APP_NAME} - {session.username} ({session.role})")
        self.root.minsize(CONFIG.ui.window_min_width, CONFIG.ui.window_min_height)

        self._header = self._build_header()
        self._statusbar = self._build_statusbar()  # pack bottom before body

        middle = ttk.Frame(self.root)
        middle.pack(fill=BOTH, expand=YES)
        self._sidebar = self._build_sidebar(middle)
        self._content = ttk.Frame(middle, padding=0)
        self._content.pack(side=LEFT, fill=BOTH, expand=YES)

    def _build_header(self) -> ttk.Frame:
        header = ttk.Frame(self.root, bootstyle="dark", padding=(14, 10))
        header.pack(fill=X, side="top")

        left = ttk.Frame(header, bootstyle="dark")
        left.pack(side=LEFT)
        ttk.Label(left, text="🛡", font=("Segoe UI", 20),
                  bootstyle="inverse-dark").pack(side=LEFT, padx=(0, 8))
        ttk.Label(left, text=APP_NAME, font=("Segoe UI", 16, "bold"),
                  bootstyle="inverse-dark").pack(side=LEFT)

        right = ttk.Frame(header, bootstyle="dark")
        right.pack(side=RIGHT)

        self._clock = ttk.Label(right, text="", bootstyle="inverse-dark",
                                font=("Segoe UI", 10))
        self._clock.pack(side=LEFT, padx=10)

        self._status_indicators = ttk.Label(right, text="", bootstyle="inverse-dark",
                                            font=("Segoe UI", 10))
        self._status_indicators.pack(side=LEFT, padx=10)

        session = self.context.session
        ttk.Label(right, text=f"👤 {session.fullname or session.username} "
                              f"[{session.role}]",
                  bootstyle="inverse-dark", font=("Segoe UI", 10)).pack(side=LEFT, padx=10)
        ttk.Button(right, text="Logout", bootstyle="danger-outline",
                   command=self.logout).pack(side=LEFT, padx=(6, 0))
        return header

    def _build_sidebar(self, parent) -> ttk.Frame:
        sidebar = ttk.Frame(parent, bootstyle="secondary", padding=(6, 10))
        sidebar.pack(side=LEFT, fill=Y)
        session = self.context.session
        for page_id, icon, label, admin_only in NAV_ITEMS:
            if admin_only and not session.is_admin:
                continue
            btn = ttk.Button(sidebar, text=f"  {icon}  {label}",
                             bootstyle="secondary", width=22,
                             command=lambda p=page_id: self.navigate(p))
            btn.pack(fill=X, pady=2)
            self._nav_buttons[page_id] = btn
        return sidebar

    def _build_statusbar(self) -> ttk.Frame:
        bar = ttk.Frame(self.root, bootstyle="dark", padding=(12, 4))
        bar.pack(fill=X, side="bottom")
        self._status_db = ttk.Label(bar, text="Database: …", bootstyle="inverse-dark",
                                    font=("Segoe UI", 9))
        self._status_db.pack(side=LEFT, padx=8)
        self._status_snort = ttk.Label(bar, text="Snort: …", bootstyle="inverse-dark",
                                       font=("Segoe UI", 9))
        self._status_snort.pack(side=LEFT, padx=8)
        self._status_monitor = ttk.Label(bar, text="Monitoring: …",
                                         bootstyle="inverse-dark", font=("Segoe UI", 9))
        self._status_monitor.pack(side=LEFT, padx=8)
        ttk.Label(bar, text=f"v{APP_VERSION}", bootstyle="inverse-dark",
                  font=("Segoe UI", 9)).pack(side=RIGHT, padx=8)
        self._status_user = ttk.Label(bar, text=self.context.session.username,
                                      bootstyle="inverse-dark", font=("Segoe UI", 9))
        self._status_user.pack(side=RIGHT, padx=8)
        return bar

    # ------------------------------------------------------------- routing
    def navigate(self, page_id: str) -> None:
        session = self.context.session
        if not session:
            return
        # Enforce RBAC at the router level too.
        if not session.pages().get(page_id, False):
            messagebox.showwarning("Access denied",
                                   "You do not have permission to open this page.")
            return

        if self._current_page_id == page_id:
            return

        if self._current_page_id and self._current_page_id in self._pages:
            try:
                self._pages[self._current_page_id].on_hide()
            except Exception:  # noqa: BLE001
                pass
            self._pages[self._current_page_id].pack_forget()

        page = self._get_page(page_id)
        if page is None:
            return
        page.pack(fill=BOTH, expand=YES)
        self._current_page_id = page_id
        self._highlight_nav(page_id)
        try:
            page.on_show()
        except Exception as exc:  # noqa: BLE001
            LOG.exception("gui", f"page_show_failed:{page_id}", exc)

    def _highlight_nav(self, page_id: str) -> None:
        for pid, btn in self._nav_buttons.items():
            btn.configure(bootstyle="info" if pid == page_id else "secondary")

    def _get_page(self, page_id: str):
        if page_id in self._pages:
            return self._pages[page_id]
        page = self._create_page(page_id)
        if page is not None:
            self._pages[page_id] = page
        return page

    def _create_page(self, page_id: str):
        # Import lazily to keep startup fast and avoid import cycles.
        from gui.pages import (
            dashboard_page, scanner_page, monitoring_page, connections_page,
            alerts_page, mitigation_page, logs_page, reports_page, users_page,
            settings_page, help_page,
        )
        factory = {
            "dashboard": dashboard_page.DashboardPage,
            "scanner": scanner_page.ScannerPage,
            "monitoring": monitoring_page.MonitoringPage,
            "connections": connections_page.ConnectionsPage,
            "alerts": alerts_page.AlertsPage,
            "mitigation": mitigation_page.MitigationPage,
            "logs": logs_page.LogsPage,
            "reports": reports_page.ReportsPage,
            "users": users_page.UsersPage,
            "settings": settings_page.SettingsPage,
            "help": help_page.HelpPage,
            "about": help_page.AboutPage,
        }.get(page_id)
        if factory is None:
            return None
        try:
            return factory(self._content, self.context)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("gui", f"page_create_failed:{page_id}", exc)
            messagebox.showerror("Page error",
                                 f"Could not open '{page_id}':\n{exc}")
            return None

    # ------------------------------------------------------- refresh timer
    def _start_refresh_timer(self) -> None:
        self._tick()

    def _tick(self) -> None:
        try:
            self._update_header()
            self._update_statusbar()
            if self._current_page_id in self._pages:
                page = self._pages[self._current_page_id]
                if getattr(page, "live", False):
                    page.on_refresh()
            self._check_session_timeout()
        except Exception as exc:  # noqa: BLE001
            LOG.error("gui", "refresh_tick_error", str(exc))
        finally:
            self._refresh_job = self.root.after(
                CONFIG.ui.refresh_interval_ms, self._tick)

    def _update_header(self) -> None:
        self._clock.configure(text=now().strftime("%Y-%m-%d  %H:%M:%S"))
        snort = self.context.snort.stats.status
        self._status_indicators.configure(
            text=f"DB {status_symbol('Online' if self.context.db.connected else 'Stopped')}  "
                 f"Snort {status_symbol(snort)}  "
                 f"Mon {status_symbol('Active' if self.context.monitoring.running else 'Stopped')}"
        )

    def _update_statusbar(self) -> None:
        db_ok = self.context.db.connected
        self._status_db.configure(
            text=f"Database: {'Connected' if db_ok else 'Reconnecting…'}")
        snort = self.context.snort.stats.status
        self._status_snort.configure(text=f"Snort: {snort}")
        mon = self.context.monitoring
        self._status_monitor.configure(
            text=f"Monitoring: {'Active on ' + mon.interface if mon.running else 'Stopped'}")
        # Opportunistic DB reconnect if the connection dropped.
        if not db_ok:
            self.context.db.ping()

    def _check_session_timeout(self) -> None:
        session = self.context.session
        if session and session.is_expired():
            LOG.info("gui", "session_timeout", session.username, user=session.username)
            messagebox.showinfo("Session expired",
                                "Your session has timed out due to inactivity.")
            self.logout()

    # ------------------------------------------------------------- logout
    def logout(self) -> None:
        if self._refresh_job:
            try:
                self.root.after_cancel(self._refresh_job)
            except Exception:  # noqa: BLE001
                pass
            self._refresh_job = None
        self.context.stop_background_services()
        self.context.auth.logout(self.context.session)
        from authentication.session import SESSION
        SESSION.end()
        # Tear down all widgets.
        for child in self.root.winfo_children():
            child.destroy()
        self._on_logout()
