"""Mitigation Center - browsable educational knowledge base."""

from __future__ import annotations

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, LEFT, RIGHT, X, Y, YES
from tkinter import messagebox

from gui.pages.base_page import BasePage
from gui.theme import severity_bootstyle


class MitigationPage(BasePage):
    title = "Mitigation Center"
    subtitle = "Educational recommendations for detected and known threats"

    def build(self) -> None:
        container = ttk.Frame(self.body)
        container.pack(fill=BOTH, expand=YES)

        # Left: category list.
        left = ttk.Labelframe(container, text="Threat Categories", padding=6)
        left.pack(side=LEFT, fill=Y)
        self._listbox = ttk.Treeview(left, columns=["type", "sev"], show="headings",
                                    height=18, selectmode="browse")
        self._listbox.heading("type", text="Threat")
        self._listbox.heading("sev", text="Severity")
        self._listbox.column("type", width=170)
        self._listbox.column("sev", width=90)
        self._listbox.pack(fill=Y, expand=YES)
        self._listbox.bind("<<TreeviewSelect>>", lambda _e: self._show_selected())

        # Right: detail.
        right = ttk.Frame(container, padding=(12, 0))
        right.pack(side=LEFT, fill=BOTH, expand=YES)
        self._detail = ttk.Frame(right)
        self._detail.pack(fill=BOTH, expand=YES)

        if self.can("manage_mitigation"):
            ttk.Button(right, text="Edit This Recommendation",
                       bootstyle="info-outline",
                       command=self._edit_selected).pack(anchor="e", pady=(6, 0))

    def on_show(self) -> None:
        self._load_list()

    def _load_list(self) -> None:
        self._listbox.delete(*self._listbox.get_children())
        self._recs = {rec["alert_type"]: rec
                      for rec in self.context.mitigation.list_recommendations()}
        for alert_type, rec in self._recs.items():
            self._listbox.insert("", "end", iid=alert_type,
                                 values=[alert_type, rec.get("severity", "")])
        if self._recs:
            first = next(iter(self._recs))
            self._listbox.selection_set(first)
            self._render_detail(self._recs[first])

    def _show_selected(self) -> None:
        sel = self._listbox.selection()
        if sel and sel[0] in self._recs:
            self._render_detail(self._recs[sel[0]])

    def _render_detail(self, rec: dict) -> None:
        for child in self._detail.winfo_children():
            child.destroy()
        # Record the educational view for evaluation metrics.
        if self.context.session:
            from logs.activity_logger import ACTIVITY
            ACTIVITY.mitigation_viewed(self.context.session.username, rec["alert_type"])

        ttk.Label(self._detail, text=f"🛡  {rec['recommendation_title']}",
                  font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(self._detail,
                  text=f"Threat: {rec['alert_type']}   •   Severity: {rec['severity']}"
                       f"   •   Difficulty: {rec.get('difficulty','-')}",
                  bootstyle=severity_bootstyle(rec["severity"])).pack(anchor="w", pady=(2, 8))

        text = ttk.Text(self._detail, wrap="word", height=26)
        text.pack(fill=BOTH, expand=YES)
        content = self._format(rec)
        text.insert("1.0", content)
        text.configure(state="disabled")

    def _format(self, rec: dict) -> str:
        def block(title, value):
            return f"{title}\n{'-' * len(title)}\n{value or 'N/A'}\n\n"

        return (
            block("What does this attack mean?", rec.get("educational"))
            + block("Explanation", rec.get("explanation"))
            + block("Problem", rec.get("problem"))
            + block("Why it happened", rec.get("why_it_happened"))
            + block("Risk", rec.get("risk"))
            + block("How to verify", rec.get("how_to_verify"))
            + block("Immediate actions", rec.get("immediate_actions"))
            + block("Long-term prevention", rec.get("long_term_prevention"))
            + block("Summary recommendation", rec.get("recommendation"))
            + block("References", rec.get("reference"))
            + block("Administrator notes", rec.get("admin_notes"))
        )

    def _edit_selected(self) -> None:
        sel = self._listbox.selection()
        if not sel:
            messagebox.showinfo("Edit", "Select a recommendation first.")
            return
        MitigationEditWindow(self, self.context, self._recs[sel[0]],
                             on_saved=self._load_list)


class MitigationEditWindow(ttk.Toplevel):
    """Admin editor for a mitigation recommendation."""

    _FIELDS = [
        ("recommendation_title", "Title", 1),
        ("severity", "Severity", 1),
        ("difficulty", "Difficulty", 1),
        ("educational", "Educational explanation", 4),
        ("problem", "Problem", 2),
        ("why_it_happened", "Why it happened", 2),
        ("risk", "Risk", 2),
        ("how_to_verify", "How to verify", 2),
        ("immediate_actions", "Immediate actions", 3),
        ("long_term_prevention", "Long-term prevention", 3),
        ("recommendation", "Summary recommendation", 3),
        ("reference", "References", 2),
        ("admin_notes", "Administrator notes", 2),
    ]

    def __init__(self, master, context, rec: dict, on_saved):
        super().__init__(master)
        self._ctx = context
        self._rec = rec
        self._on_saved = on_saved
        self.title(f"Edit: {rec['alert_type']}")
        self.geometry("560x760")
        self._widgets = {}
        self._build()

    def _build(self) -> None:
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill=BOTH, expand=YES)
        for key, label, height in self._FIELDS:
            ttk.Label(frame, text=label, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            widget = ttk.Text(frame, height=height, wrap="word")
            widget.insert("1.0", self._rec.get(key) or "")
            widget.pack(fill=X, pady=(0, 6))
            self._widgets[key] = widget
        ttk.Button(frame, text="Save", bootstyle="success",
                   command=self._save).pack(anchor="e")

    def _save(self) -> None:
        fields = {key: w.get("1.0", "end").strip() for key, w in self._widgets.items()}
        ok = self._ctx.mitigation.repo.update(
            self._rec["id"], fields, actor=self._ctx.session.username)
        if ok:
            messagebox.showinfo("Saved", "Recommendation updated.")
            self._on_saved()
            self.destroy()
        else:
            messagebox.showerror("Error", "Could not update recommendation.")
