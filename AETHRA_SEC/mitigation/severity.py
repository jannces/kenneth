"""Severity helpers shared by the mitigation engine and analytics."""

from __future__ import annotations

from utils.constants import Severity


def escalate(current: str, occurrences: int) -> str:
    """Return a possibly-escalated severity string based on repetition."""
    sev = _to_sev(current)
    order = Severity.order()
    idx = order.index(sev)
    if occurrences >= 100:
        idx = max(0, idx - 2)
    elif occurrences >= 20:
        idx = max(0, idx - 1)
    return order[idx].value


def highest(*severities: str) -> str:
    """Return the most severe of the given severity strings."""
    sevs = [_to_sev(s) for s in severities if s]
    if not sevs:
        return Severity.INFORMATIONAL.value
    return max(sevs, key=lambda s: s.rank).value


def rank(severity: str) -> int:
    return _to_sev(severity).rank


def _to_sev(value: str) -> Severity:
    try:
        return Severity(value)
    except (ValueError, TypeError):
        return Severity.INFORMATIONAL
