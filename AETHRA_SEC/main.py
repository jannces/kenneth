"""AETHRA-SEC application entry point.

Boot sequence (matching the manuscript workflow):

    launch -> logging -> database connect + schema/seed -> single Tk root
      -> Login window -> on success: build services + start background
      monitoring/Snort listener -> Dashboard -> run.

The application keeps a single Tk root for its whole lifetime; the login screen
is a modal Toplevel over the (hidden) root, and the authenticated UI is built
into the same root.  On logout the UI is torn down and the login screen returns.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox

# Third-party GUI toolkit (import guarded so we can show a helpful message).
try:
    import ttkbootstrap as ttk
    _TTK_AVAILABLE = True
except Exception:  # pragma: no cover
    _TTK_AVAILABLE = False

from config import APP_NAME, APP_VERSION, CONFIG
from logs.activity_logger import ACTIVITY
from logs.logger import LOG


class AethraApp:
    """Top-level application controller."""

    def __init__(self) -> None:
        self.root: "ttk.Window" = ttk.Window(themename=CONFIG.ui.theme)
        self.root.withdraw()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.db = None
        self.context = None
        self.main_window = None

        # Route uncaught Tk callback exceptions through the logger.
        self.root.report_callback_exception = self._tk_exception

    # ------------------------------------------------------------- startup
    def start(self) -> None:
        LOG.info("app", "startup", f"{APP_NAME} v{APP_VERSION} starting")
        if not self._init_database():
            # Non-fatal: allow the login screen so the user can read the error,
            # but authentication will fail until the DB is reachable.
            LOG.warning("app", "db_unavailable",
                        "Continuing without a database connection.")
        self._show_login()
        self.root.mainloop()

    def _init_database(self) -> bool:
        from database.database import DB

        self.db = DB
        LOG.attach_database(DB)
        ACTIVITY.attach_database(DB)

        if not DB.available:
            messagebox.showerror(
                "Database driver missing",
                "mysql-connector-python is not installed.\n\n"
                "Install dependencies with:\n    pip install -r requirements.txt")
            return False

        if not DB.connect(ensure_schema=True):
            messagebox.showerror(
                "Database connection failed",
                "Could not connect to MySQL.\n\n"
                "Verify that MySQL is running and that the credentials in your "
                ".env file are correct, then restart AETHRA-SEC.\n\n"
                "See logs/files/errors.log for details.")
            return False
        return True

    # ------------------------------------------------------------- login
    def _show_login(self) -> None:
        from authentication.auth_service import AuthService
        from authentication.login import LoginWindow

        if self.db is None:
            # Provide a stub so the login screen still renders; auth will report
            # a friendly failure.
            from database.database import DB
            self.db = DB
        auth = AuthService(self.db)
        LoginWindow(self.root, auth,
                    on_success=self._on_login,
                    on_exit=self._on_close)

    def _on_login(self, session) -> None:
        from gui.app_context import AppContext
        from gui.main_window import MainWindow

        try:
            self.context = AppContext(self.db)
            self.context.start_background_services()
            self.root.deiconify()
            self.root.state("normal")
            self.main_window = MainWindow(self.root, self.context,
                                          on_logout=self._on_logout)
            LOG.info("app", "dashboard_loaded", session.username, user=session.username)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("app", "post_login_failed", exc)
            messagebox.showerror("Startup error",
                                 f"Failed to load the application:\n{exc}")
            self._on_close()

    def _on_logout(self) -> None:
        self.context = None
        self.main_window = None
        self.root.withdraw()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self._show_login()

    # ------------------------------------------------------------- shutdown
    def _on_close(self) -> None:
        LOG.info("app", "shutdown", "Application closing")
        try:
            if self.context is not None:
                self.context.stop_background_services()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.root.destroy()
        except Exception:  # noqa: BLE001
            pass
        sys.exit(0)

    def _tk_exception(self, exc_type, exc_value, exc_tb) -> None:
        LOG.exception("gui", "tk_callback_error", exc_value or exc_type("unknown"))
        try:
            messagebox.showerror(
                "Unexpected error",
                f"An unexpected error occurred:\n{exc_value}\n\n"
                "The application will continue running. See errors.log for details.")
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    if not _TTK_AVAILABLE:
        print("ERROR: ttkbootstrap is not installed.\n"
              "Install dependencies with: pip install -r requirements.txt",
              file=sys.stderr)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Missing dependency",
                "ttkbootstrap is not installed.\n\n"
                "Run:  pip install -r requirements.txt")
        except Exception:  # noqa: BLE001
            pass
        return 1

    try:
        AethraApp().start()
        return 0
    except Exception as exc:  # noqa: BLE001
        LOG.exception("app", "fatal", exc)
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
