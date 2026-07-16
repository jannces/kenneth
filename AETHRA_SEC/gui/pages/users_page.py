"""User Management page (administrator only)."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox
from tkinter.simpledialog import askstring

from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from gui.pages.detail_windows import _ScrollableDialog
from utils.constants import Role, UserStatus
from utils.helpers import format_timestamp


class UsersPage(BasePage):
    title = "User Management"
    subtitle = "Create, edit and audit user accounts (administrator only)"

    def build(self) -> None:
        toolbar = ttk.Frame(self.body)
        toolbar.pack(fill=X)
        ttk.Button(toolbar, text="➕ Create User", bootstyle="success",
                   command=self._create_user).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="✏ Edit", bootstyle="info-outline",
                   command=self._edit_user).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="🔑 Reset Password", bootstyle="warning-outline",
                   command=self._reset_password).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="🔓 Unlock", bootstyle="secondary-outline",
                   command=self._unlock).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="⏸ Deactivate", bootstyle="secondary-outline",
                   command=self._deactivate).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="🗑 Delete", bootstyle="danger-outline",
                   command=self._delete).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="📜 Activity", bootstyle="secondary-outline",
                   command=self._view_activity).pack(side=RIGHT, padx=2)

        self._table = DataTable(
            self.body,
            columns=["id", "username", "fullname", "email", "role", "status",
                     "created_at", "last_login"],
            headings=["ID", "Username", "Full Name", "Email", "Role", "Status",
                      "Created", "Last Login"],
            on_double_click=lambda _r: self._edit_user(),
            height=16,
        )
        self._table.pack(fill=BOTH, expand=YES, pady=(8, 0))

    def on_show(self) -> None:
        self._load()

    def _load(self) -> None:
        rows = self.context.auth.list_users()
        for r in rows:
            r["created_at"] = format_timestamp(r.get("created_at"))
            r["last_login"] = format_timestamp(r.get("last_login"))
        self._table.set_rows(rows)

    def _selected(self):
        return self._table.selected_row()

    # ------------------------------------------------------------- actions
    def _create_user(self) -> None:
        UserFormWindow(self, self.context, None, on_saved=self._load)

    def _edit_user(self) -> None:
        row = self._selected()
        if not row:
            messagebox.showinfo("Edit", "Select a user first.")
            return
        user = self.context.auth.get_user(int(row["id"]))
        UserFormWindow(self, self.context, user, on_saved=self._load)

    def _reset_password(self) -> None:
        row = self._selected()
        if not row:
            messagebox.showinfo("Reset", "Select a user first.")
            return
        new_pw = askstring("Reset Password",
                           f"New password for '{row['username']}':", show="*")
        if not new_pw:
            return
        result = self.context.auth.reset_password(
            self.context.session, int(row["id"]), new_pw)
        messagebox.showinfo("Reset Password", result.message)

    def _unlock(self) -> None:
        row = self._selected()
        if not row:
            return
        result = self.context.auth.unlock_user(self.context.session, int(row["id"]))
        messagebox.showinfo("Unlock", result.message)
        self._load()

    def _deactivate(self) -> None:
        row = self._selected()
        if not row:
            return
        result = self.context.auth.deactivate_user(self.context.session, int(row["id"]))
        messagebox.showinfo("Deactivate", result.message)
        self._load()

    def _delete(self) -> None:
        row = self._selected()
        if not row:
            return
        if not messagebox.askyesno("Confirm delete",
                                   f"Permanently delete user '{row['username']}'?"):
            return
        result = self.context.auth.delete_user(self.context.session, int(row["id"]))
        messagebox.showinfo("Delete", result.message)
        self._load()

    def _view_activity(self) -> None:
        row = self._selected()
        if not row:
            messagebox.showinfo("Activity", "Select a user first.")
            return
        UserActivityWindow(self, self.context, row["username"], int(row["id"]))


class UserFormWindow(ttk.Toplevel):
    """Create/edit user dialog."""

    def __init__(self, master, context, user, on_saved):
        super().__init__(master)
        self._ctx = context
        self._user = user
        self._on_saved = on_saved
        self.title("Edit User" if user else "Create User")
        self.geometry("420x460")
        self.grab_set()
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=BOTH, expand=YES)
        editing = self._user is not None

        ttk.Label(frame, text="Username").pack(anchor="w")
        self._username = ttk.Entry(frame)
        self._username.pack(fill=X, pady=(0, 8))
        if editing:
            self._username.insert(0, self._user["username"])
            self._username.configure(state="disabled")

        ttk.Label(frame, text="Full Name").pack(anchor="w")
        self._fullname = ttk.Entry(frame)
        self._fullname.pack(fill=X, pady=(0, 8))
        if editing:
            self._fullname.insert(0, self._user.get("fullname", ""))

        ttk.Label(frame, text="Email").pack(anchor="w")
        self._email = ttk.Entry(frame)
        self._email.pack(fill=X, pady=(0, 8))
        if editing:
            self._email.insert(0, self._user.get("email", ""))

        if not editing:
            ttk.Label(frame, text="Password").pack(anchor="w")
            self._password = ttk.Entry(frame, show="*")
            self._password.pack(fill=X, pady=(0, 8))

        ttk.Label(frame, text="Role").pack(anchor="w")
        self._role = ttk.Combobox(frame, state="readonly",
                                 values=[Role.USER.value, Role.ADMIN.value])
        self._role.set(self._user.get("role") if editing else Role.USER.value)
        self._role.pack(fill=X, pady=(0, 8))

        if editing:
            ttk.Label(frame, text="Status").pack(anchor="w")
            self._status = ttk.Combobox(frame, state="readonly",
                                       values=[s.value for s in UserStatus])
            self._status.set(self._user.get("status"))
            self._status.pack(fill=X, pady=(0, 8))

        ttk.Button(frame, text="Save", bootstyle="success",
                   command=self._save).pack(fill=X, pady=(10, 0), ipady=4)

    def _save(self) -> None:
        if self._user is None:
            result = self._ctx.auth.create_user(
                self._ctx.session,
                self._username.get(), self._password.get(),
                self._fullname.get(), self._email.get(), self._role.get())
        else:
            result = self._ctx.auth.update_user(
                self._ctx.session, self._user["id"],
                self._fullname.get(), self._email.get(),
                self._role.get(), self._status.get())
        if result.ok:
            messagebox.showinfo("Saved", result.message)
            self._on_saved()
            self.destroy()
        else:
            messagebox.showerror("Error", result.message)


class UserActivityWindow(_ScrollableDialog):
    def __init__(self, master, context, username: str, user_id: int):
        super().__init__(master, f"Activity - {username}", "560x600")
        self.section("Login History")
        for h in context.auth.user_login_history(user_id):
            self.paragraph(
                f"• {format_timestamp(h['login_time'])}  "
                f"{h.get('ip_address','')} ({h.get('computer_name','')}) - "
                f"{h.get('status','')}")
        self.section("Recent Activity")
        for a in context.auth.user_activity(username):
            self.paragraph(
                f"• {format_timestamp(a['timestamp'])}  {a['activity']}: "
                f"{a.get('details','')}")
