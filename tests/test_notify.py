from nexus.notify import Notifier


def test_format_slack():
    summary = {
        "run_id": "abc123",
        "status": "completed",
        "findings": 5,
        "counts": {"critical": 2, "high": 1},
        "critical_findings": [{"severity": "critical", "title": "SQL injection"}],
    }
    text = Notifier.format_slack(summary)
    assert "Nexus scan complete" in text
    assert "abc123" in text
    assert "SQL injection" in text


def test_notify_no_webhooks_is_noop():
    # Should not raise when no webhooks are configured.
    Notifier().notify({"run_id": "x"})
