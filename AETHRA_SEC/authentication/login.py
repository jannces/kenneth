"""Login window - the first screen shown after launch.

Presents username/password with show-password and exit controls, validates
input, calls :class:`AuthService`, and on success stores the session and invokes
a callback that launches the main window.  Every attempt is logged by the
service layer; the window only surfaces friendly messages.

Implemented as a ``Toplevel`` over a single shared Tk root (created in main.py)
so the application never spawns two Tk interpreters.
"""

from __future__ import annotations

from typing import Callable

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, YES
from tkinter import messagebox

from authentication.auth_service import AuthService
from authentication.session import Session, SESSION
from config import APP_NAME, APP_VERSION
from logs.logger import LOG


class LoginWindow(ttk.Toplevel):
    """Themed login dialog shown over the (hidden) main root."""

    def __init__(self, master, auth: AuthService,
                 on_success: Callable[[Session], None],
                 on_exit: Callable[[], None]):
        super().__init__(master)
        self._auth = auth
        self._on_success = on_success
        self._on_exit = on_exit

        self.title(f"{APP_NAME} - Login")
        self.geometry("440x580")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._exit)

        self._build()
        self.bind("<Return>", lambda _e: self._attempt_login())
        self.place_window_center()
        self.grab_set()

    # ---------------------------------------------------------------- build
    def _build(self) -> None:
        container = ttk.Frame(self, padding=30)
        container.pack(fill=BOTH, expand=YES)

        ttk.Label(container, text="🛡", font=("Segoe UI", 48)).pack(pady=(10, 0))
        ttk.Label(container, text=APP_NAME, font=("Segoe UI", 26, "bold"),
                  bootstyle="info").pack()
        ttk.Label(container,
                  text="Unified Penetration Testing, Traffic Analysis\n"
                       "& Threat Mitigation Platform",
                  font=("Segoe UI", 9), bootstyle="secondary",
                  justify="center").pack(pady=(2, 20))

        form = ttk.Frame(container)
        form.pack(fill=X)

        ttk.Label(form, text="Username", font=("Segoe UI", 10)).pack(anchor="w")
        self._username = ttk.Entry(form, font=("Segoe UI", 11))
        self._username.pack(fill=X, pady=(2, 12))
        self._username.focus_set()

        ttk.Label(form, text="Password", font=("Segoe UI", 10)).pack(anchor="w")
        self._password = ttk.Entry(form, show="•", font=("Segoe UI", 11))
        self._password.pack(fill=X, pady=(2, 6))

        self._show_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(form, text="Show password", variable=self._show_var,
                        bootstyle="round-toggle",
                        command=self._toggle_password).pack(anchor="w", pady=(0, 14))

        self._status = ttk.Label(form, text="", bootstyle="danger",
                                 font=("Segoe UI", 9), wraplength=360)
        self._status.pack(fill=X, pady=(0, 6))

        self._login_btn = ttk.Button(form, text="Login", bootstyle="success",
                                     command=self._attempt_login)
        self._login_btn.pack(fill=X, pady=(0, 8), ipady=4)
        ttk.Button(form, text="Exit", bootstyle="secondary-outline",
                   command=self._exit).pack(fill=X, ipady=2)

        ttk.Button(container, text="Forgot password?",
                   bootstyle="link-secondary",
                   command=self._forgot_password).pack(pady=(10, 0))

        ttk.Label(container, text=f"v{APP_VERSION}  •  Educational Laboratory Use",
                  font=("Segoe UI", 8), bootstyle="secondary").pack(side="bottom")

    # -------------------------------------------------------------- actions
    def _toggle_password(self) -> None:
        self._password.configure(show="" if self._show_var.get() else "•")

    def _attempt_login(self) -> None:
        username = self._username.get().strip()
        password = self._password.get()
        self._status.configure(text="")
        self._login_btn.configure(state="disabled", text="Signing in…")
        self.update_idletasks()

        try:
            result = self._auth.authenticate(username, password)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("login", "auth_exception", exc)
            self._status.configure(text="An unexpected error occurred. See logs.")
            self._login_btn.configure(state="normal", text="Login")
            return

        if not result.ok:
            self._status.configure(text=result.message)
            self._login_btn.configure(state="normal", text="Login")
            self._password.delete(0, "end")
            return

        SESSION.start(result.session)
        LOG.info("login", "session_started", username, user=username)
        self.grab_release()
        self.destroy()
        self._on_success(result.session)

    def _forgot_password(self) -> None:
        messagebox.showinfo(
            "Forgot Password",
            "Password resets are performed by an administrator.\n\n"
            "Please contact your laboratory administrator, who can reset your "
            "password from User Management.",
        )

    def _exit(self) -> None:
        self.grab_release()
        self.destroy()
        self._on_exit()
