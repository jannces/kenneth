"""A reusable, searchable, sortable table widget built on ttk.Treeview.

Every data-heavy page uses this so search / sort / column behaviour is
consistent.  Supports:

* Instant text search across all columns.
* Click-to-sort on any column header (numeric-aware).
* Per-row severity/status colour tags (with text still carrying the meaning).
* Double-click callback for opening details.
* CSV export of the currently displayed rows.
"""

from __future__ import annotations

import csv
from typing import Any, Callable, Dict, List, Optional, Sequence

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, END, LEFT, RIGHT, X, Y, YES

from gui.theme import severity_color


class DataTable(ttk.Frame):
    """A themed, filterable table."""

    def __init__(self, master, columns: Sequence[str],
                 headings: Optional[Sequence[str]] = None,
                 on_double_click: Optional[Callable[[Dict[str, Any]], None]] = None,
                 height: int = 12, searchable: bool = True, **kwargs):
        super().__init__(master, **kwargs)
        self._columns = list(columns)
        self._headings = list(headings) if headings else [c.title() for c in columns]
        self._on_double_click = on_double_click
        self._rows: List[Dict[str, Any]] = []
        self._sort_state: Dict[str, bool] = {}

        if searchable:
            self._build_search_bar()

        container = ttk.Frame(self)
        container.pack(fill=BOTH, expand=YES)

        self.tree = ttk.Treeview(container, columns=self._columns,
                                 show="headings", height=height)
        for col, head in zip(self._columns, self._headings):
            self.tree.heading(col, text=head,
                              command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=120, anchor="w", stretch=True)

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        if on_double_click:
            self.tree.bind("<Double-1>", self._handle_double_click)

        # Severity tag colours (text still says the severity too).
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            self.tree.tag_configure(sev, foreground=severity_color(sev))

    # --------------------------------------------------------------- search
    def _build_search_bar(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill=X, pady=(0, 6))
        ttk.Label(bar, text="🔍").pack(side=LEFT, padx=(0, 4))
        self._search_var = ttk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        entry = ttk.Entry(bar, textvariable=self._search_var)
        entry.pack(side=LEFT, fill=X, expand=YES)
        ttk.Button(bar, text="Export CSV", bootstyle="secondary-outline",
                   command=self.export_csv).pack(side=RIGHT, padx=(6, 0))
        self._count_label = ttk.Label(bar, text="", bootstyle="secondary")
        self._count_label.pack(side=RIGHT, padx=6)

    # ---------------------------------------------------------------- data
    def set_rows(self, rows: List[Dict[str, Any]]) -> None:
        """Replace the table contents, honouring any active search filter."""
        self._rows = rows or []
        if getattr(self, "_search_var", None) and self._search_var.get().strip():
            self._apply_filter()
        else:
            self._render(self._rows)

    def _render(self, rows: List[Dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for row in rows:
            values = [row.get(col, "") for col in self._columns]
            tag = row.get("_severity", "")
            self.tree.insert("", END, values=values, tags=(tag,) if tag else ())
        if hasattr(self, "_count_label"):
            self._count_label.configure(text=f"{len(rows)} row(s)")

    def _apply_filter(self) -> None:
        query = self._search_var.get().strip().lower()
        if not query:
            self._render(self._rows)
            return
        filtered = [
            r for r in self._rows
            if any(query in str(r.get(c, "")).lower() for c in self._columns)
        ]
        self._render(filtered)

    # ---------------------------------------------------------------- sort
    def _sort_by(self, column: str) -> None:
        ascending = not self._sort_state.get(column, False)
        self._sort_state[column] = ascending

        def key(row: Dict[str, Any]):
            value = row.get(column, "")
            try:
                return (0, float(str(value).replace(",", "")))
            except (ValueError, TypeError):
                return (1, str(value).lower())

        self._rows.sort(key=key, reverse=not ascending)
        self._apply_filter()

    # -------------------------------------------------------------- events
    def _handle_double_click(self, _event) -> None:
        selected = self.selected_row()
        if selected and self._on_double_click:
            self._on_double_click(selected)

    def selected_row(self) -> Optional[Dict[str, Any]]:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        return dict(zip(self._columns, values))

    # -------------------------------------------------------------- export
    def export_csv(self) -> None:
        from tkinter import filedialog, messagebox

        if not self._rows:
            messagebox.showinfo("Export", "There is no data to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export table to CSV",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(self._headings)
                for row in self._rows:
                    writer.writerow([row.get(c, "") for c in self._columns])
            messagebox.showinfo("Export", f"Exported {len(self._rows)} row(s) to:\n{path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Export failed", str(exc))
