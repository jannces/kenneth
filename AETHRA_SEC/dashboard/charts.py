"""Matplotlib charts embedded in Tkinter for the live dashboard.

Charts avoid animation; the dashboard simply calls ``update_*`` on its refresh
timer and the figure is redrawn.  All chart widgets degrade to a friendly label
if Matplotlib is unavailable so the GUI still loads.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List

import ttkbootstrap as ttk
from ttkbootstrap.constants import BOTH, YES

from gui.theme import severity_color

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    _MPL = True
except Exception:  # pragma: no cover
    _MPL = False


_PROTO_COLORS = {
    "TCP": "#3E7CB1", "UDP": "#6a994e", "ICMP": "#bc4749", "HTTP": "#f4a259",
    "HTTPS": "#8ac926", "DNS": "#9d4edd", "Other": "#8a8f98",
}


class _BaseChart(ttk.Frame):
    def __init__(self, master, title: str, figsize=(4, 2.4), **kwargs):
        super().__init__(master, **kwargs)
        self._ok = _MPL
        if not _MPL:
            ttk.Label(self, text=f"{title}\n(matplotlib not installed)",
                      bootstyle="secondary", anchor="center").pack(fill=BOTH, expand=YES)
            return
        self.figure = Figure(figsize=figsize, dpi=96)
        self.figure.patch.set_alpha(0.0)
        self.ax = self.figure.add_subplot(111)
        self._title = title
        self._style_axes()
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().pack(fill=BOTH, expand=YES)

    def _style_axes(self) -> None:
        self.ax.set_title(self._title, fontsize=10, color="#cccccc")
        self.ax.tick_params(colors="#999999", labelsize=7)
        self.ax.set_facecolor("none")
        for spine in self.ax.spines.values():
            spine.set_color("#555555")

    def _redraw(self) -> None:
        self.figure.tight_layout()
        self.canvas.draw_idle()


class LineChart(_BaseChart):
    """Rolling line chart (e.g. packets/sec or bandwidth)."""

    def __init__(self, master, title: str, max_points: int = 60,
                 series: List[str] | None = None, **kwargs):
        super().__init__(master, title, **kwargs)
        self._max = max_points
        self._series = series or ["value"]
        self._data: Dict[str, Deque[float]] = {
            s: deque(maxlen=max_points) for s in self._series
        }

    def push(self, values: Dict[str, float]) -> None:
        if not self._ok:
            return
        for name in self._series:
            self._data[name].append(float(values.get(name, 0.0)))
        self.ax.clear()
        self._style_axes()
        for name in self._series:
            self.ax.plot(list(self._data[name]), label=name, linewidth=1.6)
        if len(self._series) > 1:
            self.ax.legend(fontsize=7, loc="upper left")
        self.ax.set_ylim(bottom=0)
        self._redraw()


class PieChart(_BaseChart):
    """Protocol distribution pie chart."""

    def update_distribution(self, distribution: Dict[str, int]) -> None:
        if not self._ok:
            return
        self.ax.clear()
        self.ax.set_title(self._title, fontsize=10, color="#cccccc")
        items = [(k, v) for k, v in distribution.items() if v > 0]
        if not items:
            self.ax.text(0.5, 0.5, "No traffic yet", ha="center", va="center",
                         color="#888888", fontsize=9)
            self._redraw()
            return
        labels = [k for k, _ in items]
        values = [v for _, v in items]
        colors = [_PROTO_COLORS.get(k, "#8a8f98") for k in labels]
        self.ax.pie(values, labels=labels, colors=colors, autopct="%1.0f%%",
                    textprops={"fontsize": 7, "color": "#dddddd"})
        self._redraw()


class BarChart(_BaseChart):
    """Vertical or horizontal bar chart (severity / top threats)."""

    def __init__(self, master, title: str, horizontal: bool = False, **kwargs):
        super().__init__(master, title, **kwargs)
        self._horizontal = horizontal

    def update_values(self, data: Dict[str, int], severity_colored: bool = False) -> None:
        if not self._ok:
            return
        self.ax.clear()
        self._style_axes()
        items = list(data.items())
        if not items:
            self.ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                         color="#888888", fontsize=9)
            self._redraw()
            return
        labels = [k for k, _ in items]
        values = [v for _, v in items]
        if severity_colored:
            colors = [severity_color(k) for k in labels]
        else:
            colors = ["#3E7CB1"] * len(labels)
        if self._horizontal:
            self.ax.barh(labels, values, color=colors)
            self.ax.invert_yaxis()
        else:
            self.ax.bar(labels, values, color=colors)
            for label in self.ax.get_xticklabels():
                label.set_rotation(20)
                label.set_ha("right")
        self._redraw()
