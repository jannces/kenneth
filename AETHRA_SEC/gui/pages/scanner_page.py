"""Vulnerability Scanner page - configure, run and review Nmap scans."""

from __future__ import annotations

import time

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox

from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from utils.constants import SCAN_TYPE_LABELS, ScanType
from utils.helpers import format_duration


class ScannerPage(BasePage):
    title = "Vulnerability Scanner"
    subtitle = "Automated assessment with Nmap - authorized laboratory targets only"

    def build(self) -> None:
        self._scan_start_time = 0.0

        # -- controls --------------------------------------------------------
        controls = ttk.Labelframe(self.body, text="New Scan", padding=12)
        controls.pack(fill=X)

        row = ttk.Frame(controls)
        row.pack(fill=X)
        ttk.Label(row, text="Target").pack(side=LEFT)
        self._target = ttk.Entry(row, width=28)
        self._target.pack(side=LEFT, padx=(6, 16))
        self._target.insert(0, "192.168.1.0/24")

        ttk.Label(row, text="Scan Type").pack(side=LEFT)
        self._scan_type = ttk.Combobox(
            row, width=20, state="readonly",
            values=[SCAN_TYPE_LABELS[s.value] for s in ScanType],
        )
        self._scan_type.set(SCAN_TYPE_LABELS[ScanType.QUICK.value])
        self._scan_type.pack(side=LEFT, padx=(6, 16))

        self._scan_btn = ttk.Button(row, text="▶ Start Scan", bootstyle="success",
                                    command=self._start_scan)
        self._scan_btn.pack(side=LEFT, padx=4)
        self._stop_btn = ttk.Button(row, text="■ Stop", bootstyle="danger-outline",
                                   command=self._stop_scan, state="disabled")
        self._stop_btn.pack(side=LEFT, padx=4)

        # Engine availability hint.
        if not self.context.scan_controller.engine_available:
            ttk.Label(controls, bootstyle="warning",
                      text="⚠ Nmap not detected. Install Nmap + python-nmap and set "
                           "AETHRA_NMAP_PATH to enable scanning.").pack(anchor="w", pady=(8, 0))

        # -- progress --------------------------------------------------------
        progress = ttk.Frame(controls)
        progress.pack(fill=X, pady=(10, 0))
        self._progress = ttk.Progressbar(progress, mode="indeterminate",
                                        bootstyle="success-striped")
        self._progress.pack(fill=X)
        self._progress_label = ttk.Label(progress, text="Idle", bootstyle="secondary")
        self._progress_label.pack(anchor="w", pady=(4, 0))

        # -- results / history notebook -------------------------------------
        notebook = ttk.Notebook(self.body)
        notebook.pack(fill=BOTH, expand=YES, pady=(10, 0))

        results_tab = ttk.Frame(notebook, padding=8)
        notebook.add(results_tab, text="Scan Results")
        self._results = DataTable(
            results_tab,
            columns=["host", "port", "protocol", "service", "version", "state",
                     "risk_level", "recommendation"],
            headings=["Host", "Port", "Proto", "Service", "Version", "State",
                      "Risk", "Recommendation"],
            on_double_click=self._show_result,
            height=12,
        )
        self._results.pack(fill=BOTH, expand=YES)

        history_tab = ttk.Frame(notebook, padding=8)
        notebook.add(history_tab, text="Scan History")
        self._history = DataTable(
            history_tab,
            columns=["scan_name", "target_ip", "scan_type", "started_at",
                     "duration", "total_hosts", "total_open_ports", "highest_risk",
                     "status", "created_by_name"],
            headings=["Name", "Target", "Type", "Started", "Duration (s)",
                      "Hosts", "Open Ports", "Highest Risk", "Status", "By"],
            on_double_click=self._load_history_results,
            height=12,
        )
        self._history.pack(fill=BOTH, expand=YES)
        hist_actions = ttk.Frame(history_tab)
        hist_actions.pack(fill=X, pady=(6, 0))
        if self.can("delete_records"):
            ttk.Button(hist_actions, text="Delete Selected Scan",
                       bootstyle="danger-outline",
                       command=self._delete_scan).pack(side=LEFT)

    def on_show(self) -> None:
        self._load_history()

    # ------------------------------------------------------------- actions
    def _start_scan(self) -> None:
        if not self.can("run_scan"):
            messagebox.showwarning("Not permitted", "You cannot run scans.")
            return
        target = self._target.get().strip()
        label = self._scan_type.get()
        scan_type = next((v for v, l in SCAN_TYPE_LABELS.items() if l == label),
                         ScanType.QUICK.value)

        self._scan_start_time = time.time()
        error = self.context.scan_controller.start_scan(
            self.context.session, target, scan_type,
            on_progress=self._on_progress,
            on_complete=self._on_complete,
            on_error=self._on_error,
        )
        if error:
            messagebox.showerror("Scan not started", error)
            return
        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress.start(12)
        self._progress_label.configure(text=f"Scanning {target}…")

    def _stop_scan(self) -> None:
        self.context.scan_controller.cancel()
        self._progress_label.configure(text="Cancelling…")

    def _on_progress(self, message: str) -> None:
        elapsed = time.time() - self._scan_start_time
        self.after(0, lambda: self._progress_label.configure(
            text=f"{message}   (elapsed {format_duration(elapsed)})"))

    def _on_complete(self, summary: dict) -> None:
        def finish():
            self._progress.stop()
            self._scan_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            elapsed = time.time() - self._scan_start_time
            self._progress_label.configure(
                text=f"Completed: {summary['total_hosts']} host(s), "
                     f"{summary['total_open_ports']} open port(s), "
                     f"highest risk {summary['highest_risk']} "
                     f"(in {format_duration(elapsed)})")
            self._render_results(summary["scan_id"])
            self._load_history()
            self.context.notify("Scan Complete",
                                f"{summary['target']}: {summary['total_open_ports']} "
                                f"open port(s) found.", "success")
        self.after(0, finish)

    def _on_error(self, message: str) -> None:
        def fail():
            self._progress.stop()
            self._scan_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            self._progress_label.configure(text=f"Scan failed: {message}")
            messagebox.showerror("Scan failed", message)
        self.after(0, fail)

    # ------------------------------------------------------------- data
    def _render_results(self, scan_id: int) -> None:
        rows = []
        for r in self.context.scan_controller.scan_results(scan_id):
            rows.append(self._result_row(r))
        self._results.set_rows(rows)

    def _result_row(self, r: dict) -> dict:
        has_rec = r.get("description") and r.get("state") == "open"
        return {
            "host": r.get("host"),
            "port": r.get("port"),
            "protocol": r.get("protocol"),
            "service": r.get("service"),
            "version": r.get("version"),
            "state": r.get("state"),
            "risk_level": r.get("risk_level"),
            "recommendation": "Available" if r.get("state") == "open" else "-",
            "_severity": r.get("risk_level"),
            "_raw": r,
        }

    def _load_history(self) -> None:
        rows = self.context.scan_controller.scan_history()
        for r in rows:
            r["_severity"] = r.get("highest_risk")
            if r.get("started_at"):
                r["started_at"] = str(r["started_at"])
        self._history.set_rows(rows)

    def _load_history_results(self, row) -> None:
        # Find scan_id from the selected history row via name+target lookup.
        scans = self.context.scan_controller.scan_history(search=row.get("target_ip", ""))
        match = next((s for s in scans
                      if s.get("scan_name") == row.get("scan_name")), None)
        if match:
            self._render_results(match["id"])

    def _delete_scan(self) -> None:
        row = self._history.selected_row()
        if not row:
            messagebox.showinfo("Delete", "Select a scan first.")
            return
        if not messagebox.askyesno("Confirm delete",
                                   f"Delete scan '{row.get('scan_name')}' and all "
                                   "its results? This cannot be undone."):
            return
        scans = self.context.scan_controller.scan_history(search=row.get("target_ip", ""))
        match = next((s for s in scans
                      if s.get("scan_name") == row.get("scan_name")), None)
        if match:
            self.context.scan_controller.delete_scan(self.context.session, match["id"])
            self._load_history()

    def _show_result(self, row) -> None:
        raw = row.get("_raw", row)
        detail = (
            f"Host: {raw.get('host')}\n"
            f"Hostname: {raw.get('hostname', '-')}\n"
            f"Port: {raw.get('port')}/{raw.get('protocol')}\n"
            f"Service: {raw.get('service')} {raw.get('product', '')} "
            f"{raw.get('version', '')}\n"
            f"State: {raw.get('state')}\n"
            f"Risk: {raw.get('risk_level')}\n\n"
            f"Assessment: {raw.get('description', 'No details.')}"
        )
        messagebox.showinfo(f"Port {raw.get('port')} details", detail)
