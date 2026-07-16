"""Help and About pages - educational reference and system information."""

from __future__ import annotations

import platform
import sys

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, X, YES

from config import APP_FULL_NAME, APP_NAME, APP_VERSION
from gui.pages.base_page import BasePage


HELP_SECTIONS = [
    ("Application Overview",
     "AETHRA-SEC unifies vulnerability assessment (Nmap), live traffic monitoring "
     "(PyShark) and intrusion detection (Snort) into one dashboard, with "
     "educational threat-mitigation guidance. It is intended for controlled "
     "educational laboratory networks only."),
    ("How to Perform a Scan",
     "Open Vulnerability Scanner, enter an authorized target (IP, CIDR, range or "
     "hostname), choose a scan type, and click Start Scan. Results are risk-rated "
     "and stored in history. Double-click a result for details."),
    ("How Monitoring Works",
     "Live Monitoring captures packets on the selected interface, parses each one, "
     "and updates statistics, connections and device discovery in real time. "
     "Monitoring runs continuously and does not stop during scans."),
    ("Understanding Alerts",
     "Snort detections are received over the Alert Socket, classified into threat "
     "categories, deduplicated (repeated attacks increment an occurrence counter), "
     "and correlated with scan findings. Double-click an alert to see its full "
     "explanation, timeline and mitigation."),
    ("Understanding Recommendations",
     "The Mitigation Center explains each threat in plain language and provides "
     "step-by-step guidance: problem, why it happened, risk, how to verify, "
     "immediate actions and long-term prevention. AETHRA-SEC only recommends; it "
     "never blocks traffic or changes firewall rules."),
    ("Roles & Permissions",
     "Administrators manage users, settings and the mitigation database. Standard "
     "users can scan, monitor, view alerts, read recommendations and export "
     "reports, but cannot change system configuration."),
    ("Troubleshooting",
     "• Nmap features require Nmap + python-nmap installed and on PATH.\n"
     "• Live capture requires Wireshark/tshark + pyshark and Administrator rights.\n"
     "• Snort alerts require Snort configured to stream to the Alert Socket.\n"
     "• Database errors: verify MySQL is running and .env credentials are correct.\n"
     "All errors are written to logs/files/errors.log for review."),
    ("Frequently Asked Questions",
     "Q: Does AETHRA-SEC attack systems? No - it performs authorized vulnerability "
     "assessment and passive monitoring only.\n"
     "Q: Can it block attackers? No - mitigation is recommendation-based by design.\n"
     "Q: Where are reports saved? In the configured reports output folder."),
]


class HelpPage(BasePage):
    title = "Help & Documentation"
    subtitle = "Educational reference for using AETHRA-SEC"

    def build(self) -> None:
        canvas = ttk.Canvas(self.body, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.body, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas, padding=6)
        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw", width=900)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill=BOTH, expand=YES)
        scrollbar.pack(side="right", fill="y")

        for title, body in HELP_SECTIONS:
            ttk.Label(inner, text=title, font=("Segoe UI", 13, "bold"),
                      bootstyle="info").pack(anchor="w", pady=(12, 2))
            ttk.Label(inner, text=body, wraplength=860, justify="left",
                      font=("Segoe UI", 10)).pack(anchor="w")


class AboutPage(BasePage):
    title = "About AETHRA-SEC"
    subtitle = ""

    def build(self) -> None:
        ttk.Label(self.body, text="🛡", font=("Segoe UI", 56)).pack(pady=(10, 0))
        ttk.Label(self.body, text=APP_NAME, font=("Segoe UI", 28, "bold"),
                  bootstyle="info").pack()
        ttk.Label(self.body, text=APP_FULL_NAME, wraplength=700, justify="center",
                  font=("Segoe UI", 11), bootstyle="secondary").pack(pady=(4, 16))

        info = [
            ("Version", APP_VERSION),
            ("Purpose", "Educational cybersecurity monitoring & assessment platform"),
            ("Technology Stack",
             "Python 3.12+, Tkinter + ttkbootstrap, MySQL, python-nmap, PyShark, "
             "Snort (Alert Socket IPC), Matplotlib, ReportLab, bcrypt"),
            ("Integrated Tools", "Nmap (assessment), PyShark (monitoring), Snort (IDS)"),
            ("Scope", "Controlled laboratory LAN; detection & recommendation only"),
            ("Runtime", f"Python {sys.version.split()[0]} on {platform.system()} "
                        f"{platform.release()}"),
            ("License", "Educational use"),
        ]
        card = ttk.Labelframe(self.body, text="System Information", padding=16)
        card.pack(fill=X, padx=40)
        for label, value in info:
            row = ttk.Frame(card)
            row.pack(fill=X, pady=2)
            ttk.Label(row, text=f"{label}:", width=18,
                      font=("Segoe UI", 10, "bold")).pack(side="left", anchor="nw")
            ttk.Label(row, text=value, wraplength=560, justify="left",
                      font=("Segoe UI", 10)).pack(side="left", anchor="w")
