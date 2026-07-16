"""Input validation helpers.

Every user-supplied value that reaches a scan, a database write, or an auth
check passes through one of these functions first.  Validators return a
``ValidationResult`` so callers can surface a friendly message instead of a
raw exception.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

from config import CONFIG

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)


@dataclass
class ValidationResult:
    """Outcome of a validation call."""

    ok: bool
    message: str = ""
    value: Optional[str] = None

    def __bool__(self) -> bool:  # allow ``if validate(...):``
        return self.ok


def validate_username(username: str) -> ValidationResult:
    username = (username or "").strip()
    if not username:
        return ValidationResult(False, "Username is required.")
    if not _USERNAME_RE.match(username):
        return ValidationResult(
            False,
            "Username must be 3-32 characters using letters, numbers, '.', '_' or '-'.",
        )
    return ValidationResult(True, value=username)


def validate_email(email: str) -> ValidationResult:
    email = (email or "").strip()
    if not email:
        return ValidationResult(False, "Email is required.")
    if not _EMAIL_RE.match(email):
        return ValidationResult(False, "Please enter a valid email address.")
    return ValidationResult(True, value=email)


def validate_password(password: str) -> ValidationResult:
    """Validate against the configured complexity policy."""
    policy = CONFIG.security
    if not password:
        return ValidationResult(False, "Password is required.")
    if len(password) < policy.password_min_length:
        return ValidationResult(
            False, f"Password must be at least {policy.password_min_length} characters."
        )
    if policy.password_require_upper and not re.search(r"[A-Z]", password):
        return ValidationResult(False, "Password must contain an uppercase letter.")
    if policy.password_require_lower and not re.search(r"[a-z]", password):
        return ValidationResult(False, "Password must contain a lowercase letter.")
    if policy.password_require_digit and not re.search(r"\d", password):
        return ValidationResult(False, "Password must contain a digit.")
    if policy.password_require_symbol and not re.search(r"[^\w\s]", password):
        return ValidationResult(False, "Password must contain a symbol.")
    return ValidationResult(True, value=password)


def validate_scan_target(target: str) -> ValidationResult:
    """Validate an Nmap target: single IP, CIDR, range or hostname.

    Accepted forms:
      * ``192.168.1.20``           single IPv4/IPv6
      * ``192.168.1.0/24``         CIDR
      * ``192.168.1.1-100``        last-octet range
      * ``example.local``          hostname
    """
    target = (target or "").strip()
    if not target:
        return ValidationResult(False, "A scan target is required.")

    # CIDR notation.
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return ValidationResult(True, value=target)
        except ValueError:
            return ValidationResult(False, "Invalid CIDR network (e.g. 192.168.1.0/24).")

    # Dash range on the final octet: 192.168.1.1-100
    range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if range_match:
        base, start, end = range_match.groups()
        try:
            ipaddress.ip_address(base + start)
            ipaddress.ip_address(base + end)
        except ValueError:
            return ValidationResult(False, "Invalid IP range.")
        if int(start) > int(end):
            return ValidationResult(False, "Range start must be <= range end.")
        return ValidationResult(True, value=target)

    # Single IP address.
    try:
        ipaddress.ip_address(target)
        return ValidationResult(True, value=target)
    except ValueError:
        pass

    # A string shaped like dotted-decimal (all numeric octets) that failed the
    # IP parse above is a malformed IP, not a hostname - reject it clearly.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", target):
        return ValidationResult(False, "Invalid IPv4 address (octets must be 0-255).")

    # Hostname.
    if _HOSTNAME_RE.match(target):
        return ValidationResult(True, value=target)

    return ValidationResult(False, "Enter a valid IP, CIDR, range or hostname.")


def validate_port(port: str | int) -> ValidationResult:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return ValidationResult(False, "Port must be a number.")
    if not 0 <= value <= 65535:
        return ValidationResult(False, "Port must be between 0 and 65535.")
    return ValidationResult(True, value=str(value))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except (ValueError, TypeError):
        return False
