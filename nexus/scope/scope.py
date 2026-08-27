"""Engagement scope model and in-scope checks.

Supports IPv4/IPv6 addresses, CIDR networks, and domains (with subdomain matching).
In SANDBOX mode enforcement is disabled (everything is in scope). In SCOPE mode any
target must match an entry or the action is refused.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlparse

from ..config import Mode
from ..logging_ import audit, get_logger

log = get_logger(__name__)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


class ScopeError(PermissionError):
    """Raised when an action targets an out-of-scope asset in SCOPE mode."""


@dataclass
class Scope:
    mode: Mode
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # normalized lowercase
    raw: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, mode: Mode, entries: Iterable[str]) -> "Scope":
        networks: list[ipaddress._BaseNetwork] = []
        domains: list[str] = []
        raw: list[str] = []
        for entry in entries:
            e = entry.strip()
            if not e:
                continue
            raw.append(e)
            parsed = _parse_entry(e)
            if isinstance(parsed, str):
                domains.append(parsed)
            elif parsed is not None:
                networks.append(parsed)
            else:
                log.warning("Ignoring unrecognized scope entry: %s", e)
        return cls(mode=mode, networks=networks, domains=sorted(set(domains)), raw=raw)

    def is_empty(self) -> bool:
        return not self.networks and not self.domains

    def contains(self, target: str) -> bool:
        """True if the target (IP, hostname, or URL) is within scope."""
        if self.mode == Mode.SANDBOX:
            return True
        host = _extract_host(target)
        if host is None:
            return False
        ip = _try_ip(host)
        if ip is not None:
            return any(ip in net for net in self.networks)
        host = host.lower().rstrip(".")
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def enforce(self, target: str, action: str = "") -> None:
        """Raise ScopeError if target is out of scope (SCOPE mode only)."""
        if self.mode == Mode.SANDBOX:
            return
        if not self.contains(target):
            audit(
                "scope.denied",
                target=target,
                action=action,
                mode=self.mode.value,
            )
            raise ScopeError(f"Target '{target}' is out of scope for action '{action}'.")


def _parse_entry(entry: str) -> Optional[object]:
    # try CIDR / network first
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        pass
    # bare IP -> /32 or /128 network
    ip = _try_ip(entry)
    if ip is not None:
        return ipaddress.ip_network(entry, strict=False)
    host = _extract_host(entry)
    if host and _DOMAIN_RE.match(host):
        return host.lower().rstrip(".")
    return None


def _try_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _extract_host(target: str) -> Optional[str]:
    t = target.strip()
    if not t:
        return None
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname
    # strip possible port
    if t.count(":") == 1 and not _looks_like_ipv6(t):
        t = t.split(":", 1)[0]
    return t or None


def _looks_like_ipv6(value: str) -> bool:
    return value.count(":") >= 2
