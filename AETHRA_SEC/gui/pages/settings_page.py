"""Settings page (administrator only) - tabbed configuration sections."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, YES
from tkinter import messagebox

from config import CONFIG
from gui.data_table import DataTable
from gui.pages.base_page import BasePage
from ids.snort_listener import SnortListener


class SettingsPage(BasePage):
    title = "Settings"
    subtitle = "System configuration (administrator only)"

    def build(self) -> None:
        self._notebook = ttk.Notebook(self.body)
        self._notebook.pack(fill=BOTH, expand=YES)
        self._vars = {}

        self._build_general()
        self._build_network()
        self._build_scanner()
        self._build_snort()
        self._build_reports()
        self._build_security()

        ttk.Button(self.body, text="💾 Save All Settings", bootstyle="success",
                   command=self._save_all).pack(anchor="e", pady=(10, 0))

    # ------------------------------------------------------------- sections
    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self._notebook, padding=14)
        self._notebook.add(frame, text=title)
        return frame

    def _field(self, parent, label: str, key: str, value, kind: str = "entry",
               options=None) -> None:
        row = ttk.Frame(parent)
        row.pack(fill=X, pady=4)
        ttk.Label(row, text=label, width=28).pack(side=LEFT)
        if kind == "check":
            var = ttk.BooleanVar(value=bool(value))
            ttk.Checkbutton(row, variable=var, bootstyle="round-toggle").pack(side=LEFT)
        elif kind == "combo":
            var = ttk.StringVar(value=str(value))
            ttk.Combobox(row, textvariable=var, state="readonly",
                         values=options or [], width=24).pack(side=LEFT)
        else:
            var = ttk.StringVar(value=str(value))
            ttk.Entry(row, textvariable=var, width=30).pack(side=LEFT)
        self._vars[key] = (var, kind)

    def _build_general(self) -> None:
        t = self._tab("General")
        s = self.context.settings
        self._field(t, "Application Name", "app_name", s.get("app_name", "AETHRA-SEC"))
        self._field(t, "Theme", "theme", s.get("theme", CONFIG.ui.theme), "combo",
                    ["darkly", "cyborg", "superhero", "solar", "flatly", "litera",
                     "cosmo", "journal"])
        self._field(t, "Refresh Interval (ms)", "refresh_interval_ms",
                    s.get("refresh_interval_ms", "1000"))
        self._field(t, "Auto-start Monitoring", "auto_start_monitoring",
                    s.get("auto_start_monitoring", "true").lower() == "true", "check")

    def _build_network(self) -> None:
        t = self._tab("Network")
        ttk.Label(t, text="Monitoring Interface", font=("Segoe UI", 10, "bold")
                  ).pack(anchor="w")
        table = DataTable(
            t, columns=["name", "description", "ip_address", "status", "speed"],
            headings=["Interface", "Description", "IP", "Status", "Speed"],
            searchable=False, height=6)
        table.pack(fill=X, pady=(4, 8))
        table.set_rows(self.context.network_settings.interface_table())
        self._iface_table = table

        current = self.context.network_settings.get_selected()
        self._field(t, "Selected Interface (name)", "capture_interface", current)
        self._field(t, "Connection Timeout (s)", "connection_timeout",
                    self.context.settings.get("connection_timeout", "120"))
        ttk.Button(t, text="Use Selected Row", bootstyle="info-outline",
                   command=self._use_selected_iface).pack(anchor="w", pady=(4, 0))

    def _use_selected_iface(self) -> None:
        row = self._iface_table.selected_row()
        if row:
            var, _ = self._vars["capture_interface"]
            var.set(row.get("name", ""))

    def _build_scanner(self) -> None:
        t = self._tab("Scanner (Nmap)")
        s = self.context.settings
        from utils.constants import SCAN_TYPE_LABELS, ScanType
        self._field(t, "Default Scan Type", "default_scan_type",
                    s.get("default_scan_type", "quick"), "combo",
                    [x.value for x in ScanType])
        self._field(t, "Scan Timeout (s)", "scan_timeout", s.get("scan_timeout", "600"))
        self._field(t, "Nmap Executable Path", "nmap_path", CONFIG.nmap.executable)

    def _build_snort(self) -> None:
        t = self._tab("Snort IDS")
        cfg = CONFIG.snort
        self._field(t, "Snort Executable", "snort_exe", cfg.executable)
        self._field(t, "Configuration File", "snort_conf", cfg.config_file)
        self._field(t, "Rules Directory", "snort_rules", cfg.rules_dir)
        self._field(t, "Alert Socket Host", "snort_alert_host", cfg.alert_host)
        self._field(t, "Alert Socket Port", "snort_alert_port", str(cfg.alert_port))

        controls = ttk.Frame(t)
        controls.pack(fill=X, pady=(10, 0))
        ttk.Label(controls, text="Snort Control:").pack(side=LEFT)
        ttk.Button(controls, text="Start", bootstyle="success-outline",
                   command=self._snort_start).pack(side=LEFT, padx=2)
        ttk.Button(controls, text="Stop", bootstyle="danger-outline",
                   command=self._snort_stop).pack(side=LEFT, padx=2)
        ttk.Button(controls, text="Restart", bootstyle="warning-outline",
                   command=self._snort_restart).pack(side=LEFT, padx=2)
        self._snort_status = ttk.Label(controls, text="")
        self._snort_status.pack(side=LEFT, padx=10)
        self._refresh_snort_status()

    def _build_reports(self) -> None:
        t = self._tab("Reports")
        s = self.context.settings
        self._field(t, "Default Format", "report_default_format",
                    s.get("report_default_format", "pdf"), "combo",
                    ["pdf", "csv", "xlsx"])
        self._field(t, "Organization Name", "organization_name",
                    s.get("organization_name", CONFIG.reports.organization_name))
        self._field(t, "Laboratory Name", "laboratory_name",
                    s.get("laboratory_name", CONFIG.reports.laboratory_name))

    def _build_security(self) -> None:
        t = self._tab("Security")
        s = self.context.settings
        self._field(t, "Session Timeout (min)", "session_timeout_minutes",
                    s.get("session_timeout_minutes", "30"))
        self._field(t, "Max Login Attempts", "max_login_attempts",
                    s.get("max_login_attempts", "5"))
        ttk.Label(t, bootstyle="secondary", wraplength=520,
                  text="Password complexity, audit logging and automatic logout are "
                       "enforced according to the security policy. Historical security "
                       "records cannot be edited through the interface.").pack(
            anchor="w", pady=(10, 0))

    # ------------------------------------------------------------- snort
    def _refresh_snort_status(self) -> None:
        snap = self.context.snort.status_snapshot()
        self._snort_status.configure(
            text=f"{snap['status']}  •  {snap['rules_loaded']} rules  •  "
                 f"socket {snap['listening_socket']}")

    def _snort_start(self) -> None:
        messagebox.showinfo("Snort", self.context.snort.start_snort())
        self._refresh_snort_status()

    def _snort_stop(self) -> None:
        messagebox.showinfo("Snort", self.context.snort.stop_snort())
        self._refresh_snort_status()

    def _snort_restart(self) -> None:
        messagebox.showinfo("Snort", self.context.snort.restart_snort())
        self._refresh_snort_status()

    # ------------------------------------------------------------- save
    def _save_all(self) -> None:
        # Persist only the keys the settings service knows about; tool paths are
        # stored too so they survive restarts (they are non-secret).
        persistable = {
            "app_name", "theme", "refresh_interval_ms", "auto_start_monitoring",
            "capture_interface", "connection_timeout", "default_scan_type",
            "scan_timeout", "report_default_format", "organization_name",
            "laboratory_name", "session_timeout_minutes", "max_login_attempts",
            "snort_exe", "snort_conf", "snort_rules", "snort_alert_host",
            "snort_alert_port", "nmap_path",
        }
        values = {}
        for key, (var, kind) in self._vars.items():
            if key not in persistable:
                continue
            values[key] = bool(var.get()) if kind == "check" else var.get()
        self.context.settings.set_many(values, actor=self.context.session.username)
        self.context.settings.apply_to_config()
        messagebox.showinfo(
            "Settings saved",
            "Settings saved. Some changes (theme, interface) take effect after "
            "you log out and back in or restart monitoring.")
