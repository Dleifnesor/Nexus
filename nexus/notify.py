"""Outbound notifications for completed scans.

Supports a Slack incoming webhook and a generic JSON webhook (for Jira, ServiceNow, or any
HTTP receiver). Configured via environment variables:
- NEXUS_SLACK_WEBHOOK
- NEXUS_WEBHOOK_URL
"""
from __future__ import annotations

import httpx

from .logging_ import get_logger

log = get_logger(__name__)


class Notifier:
    def __init__(self, slack_webhook: str | None = None, generic_webhook: str | None = None):
        self.slack_webhook = slack_webhook
        self.generic_webhook = generic_webhook

    def notify(self, summary: dict) -> None:
        if not (self.slack_webhook or self.generic_webhook):
            return
        try:
            if self.slack_webhook:
                self._post_json(self.slack_webhook, {"text": self.format_slack(summary)})
            if self.generic_webhook:
                self._post_json(self.generic_webhook, summary)
        except httpx.HTTPError as e:
            log.warning("Notification delivery failed: %s", e)

    @staticmethod
    def format_slack(summary: dict) -> str:
        counts = summary.get("counts", {})
        lines = [
            f"*Nexus scan complete* — run `{summary.get('run_id')}` (status: {summary.get('status')})",
            f"Findings: {summary.get('findings', 0)} "
            f"(critical: {counts.get('critical', 0)}, high: {counts.get('high', 0)})",
        ]
        for f in summary.get("critical_findings", [])[:5]:
            lines.append(f"• `{f.get('severity', '')}` {f.get('title', '')}")
        return "\n".join(lines)

    @staticmethod
    def _post_json(url: str, payload: dict) -> None:
        resp = httpx.post(url, json=payload, timeout=20)
        resp.raise_for_status()
