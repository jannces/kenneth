"""Reports page - generate and export PDF / CSV / Excel reports."""

from __future__ import annotations

import os
import subprocess
import sys

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox

from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from reports.report_generator import REPORT_TYPES
from utils.threading_utils import run_async


class ReportsPage(BasePage):
    title = "Reports"
    subtitle = "Generate laboratory-ready security reports"

    def build(self) -> None:
        controls = ttk.Labelframe(self.body, text="Generate Report", padding=12)
        controls.pack(fill=X)

        row = ttk.Frame(controls)
        row.pack(fill=X)
        ttk.Label(row, text="Report Type").pack(side=LEFT)
        self._type = ttk.Combobox(row, width=26, state="readonly", values=REPORT_TYPES)
        self._type.set(REPORT_TYPES[0])
        self._type.pack(side=LEFT, padx=(6, 16))

        ttk.Label(row, text="Format").pack(side=LEFT)
        self._format = ttk.Combobox(row, width=10, state="readonly",
                                   values=["PDF", "CSV", "Excel"])
        self._format.set("PDF")
        self._format.pack(side=LEFT, padx=(6, 16))

        self._generate_btn = ttk.Button(row, text="Generate", bootstyle="success",
                                       command=self._generate)
        self._generate_btn.pack(side=LEFT, padx=4)
        ttk.Button(row, text="Open Reports Folder", bootstyle="secondary-outline",
                   command=self._open_folder).pack(side=LEFT, padx=4)

        self._status = ttk.Label(controls, text="", bootstyle="info")
        self._status.pack(anchor="w", pady=(8, 0))

        # History.
        hist = ttk.Labelframe(self.body, text="Generated Reports", padding=8)
        hist.pack(fill=BOTH, expand=YES, pady=(10, 0))
        self._history = DataTable(
            hist,
            columns=["generated_at", "report_type", "file_format", "filename",
                     "generated_by_name"],
            headings=["Generated", "Type", "Format", "File", "By"],
            on_double_click=self._open_report,
            height=12,
        )
        self._history.pack(fill=BOTH, expand=YES)

    def on_show(self) -> None:
        self._load_history()

    def _generate(self) -> None:
        report_type = self._type.get()
        fmt = {"PDF": "pdf", "CSV": "csv", "Excel": "xlsx"}[self._format.get()]
        self._generate_btn.configure(state="disabled")
        self._status.configure(text=f"Generating {report_type} ({fmt})…")

        def work():
            return self.context.reports.generate(
                report_type, self.context.session, fmt)

        run_async(
            work,
            on_success=lambda path: self.after(0, lambda: self._done(path)),
            on_error=lambda exc: self.after(0, lambda: self._failed(str(exc))),
            name="aethra-report",
        )

    def _done(self, path: str) -> None:
        self._generate_btn.configure(state="normal")
        self._status.configure(text=f"Report saved: {path}")
        self.context.notify("Report Ready", os.path.basename(path), "success")
        self._load_history()
        if messagebox.askyesno("Report generated",
                               f"Report saved to:\n{path}\n\nOpen it now?"):
            self._open_path(path)

    def _failed(self, message: str) -> None:
        self._generate_btn.configure(state="normal")
        self._status.configure(text=f"Failed: {message}")
        messagebox.showerror("Report failed",
                             f"{message}\n\nTip: PDF needs reportlab, Excel needs "
                             "openpyxl. CSV always works.")

    def _load_history(self) -> None:
        rows = self.context.reports.report_history()
        for r in rows:
            r["generated_at"] = str(r.get("generated_at"))
            r["filename"] = os.path.basename(r.get("filename") or "")
        self._history.set_rows(rows)

    def _open_report(self, row) -> None:
        # Resolve to full path in the report directory.
        from config import CONFIG
        path = os.path.join(str(CONFIG.report_path()), row.get("filename", ""))
        if os.path.exists(path):
            self._open_path(path)
        else:
            messagebox.showinfo("Open", "File not found (it may have been moved).")

    def _open_folder(self) -> None:
        from config import CONFIG
        self._open_path(str(CONFIG.report_path()))

    @staticmethod
    def _open_path(path: str) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Open failed", str(exc))
