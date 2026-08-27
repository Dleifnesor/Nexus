"""Breach / leaked-credential data access with mode-gated validation.

In SCOPE mode, breach data may only be used to *validate* whether in-scope assets (domains,
emails) appear in known breaches. Actual credential validation against live services is an
intrusive action and is scope-enforced and audit-logged by the executor, not here.

Uses the HaveIBeenPwned API when a key is configured. Without a key, breach lookups are
skipped (recorded as a coverage gap by the caller).
"""
from __future__ import annotations

from typing import Optional

import httpx

from ..config import Mode
from ..logging_ import audit, get_logger
from ..scope.scope import Scope

log = get_logger(__name__)

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


class BreachClient:
    def __init__(self, scope: Scope, api_key: Optional[str] = None):
        self.scope = scope
        self.api_key = api_key

    def enabled(self) -> bool:
        return bool(self.api_key)

    def check_domain_breaches(self, domain: str) -> list[dict]:
        """List breaches associated with a domain (HIBP breaches endpoint)."""
        if self.scope.mode == Mode.SCOPE and not self.scope.contains(domain):
            log.info("Breach check skipped; domain out of scope: %s", domain)
            return []
        if not self.api_key:
            return []
        audit("osint.breach_domain", domain=domain, mode=self.scope.mode.value)
        try:
            resp = httpx.get(
                f"{HIBP_BASE}/breaches",
                params={"domain": domain},
                headers={"hibp-api-key": self.api_key, "user-agent": "nexus-scanner"},
                timeout=30,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("HIBP domain breach lookup failed for %s: %s", domain, e)
            return []
        return resp.json() if isinstance(resp.json(), list) else []

    def check_account(self, email: str) -> list[dict]:
        """Check whether an in-scope email appears in known breaches."""
        if self.scope.mode == Mode.SCOPE and not self.scope.contains(email.split("@")[-1]):
            return []
        if not self.api_key:
            return []
        audit("osint.breach_account", account=email, mode=self.scope.mode.value)
        try:
            resp = httpx.get(
                f"{HIBP_BASE}/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": self.api_key, "user-agent": "nexus-scanner"},
                timeout=30,
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("HIBP account lookup failed for %s: %s", email, e)
            return []
        return resp.json() if isinstance(resp.json(), list) else []
