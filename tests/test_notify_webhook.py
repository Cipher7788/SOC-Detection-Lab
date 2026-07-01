"""
Unit tests for scripts/notify-webhook.py
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from datetime import datetime, timezone
import argparse

import pytest

_spec = importlib.util.spec_from_file_location(
    "notify_webhook",
    Path(__file__).parent.parent / "scripts" / "notify-webhook.py",
)
nw = importlib.util.module_from_spec(_spec)  # type: ignore
_spec.loader.exec_module(nw)  # type: ignore


def make_args(**kwargs) -> argparse.Namespace:
    defaults = dict(
        provider="slack",
        webhook_url="https://hooks.slack.com/test",
        alert_name="Test Alert",
        severity="high",
        src_ip="1.2.3.4",
        host="WORKSTATION-001",
        details="Test details",
        dry_run=False,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestSlackPayload:

    def test_slack_payload_keys(self):
        payload = nw.build_slack_payload(make_args())
        assert "text" in payload
        assert "attachments" in payload

    def test_slack_payload_contains_alert_name(self):
        payload = nw.build_slack_payload(make_args(alert_name="Brute Force"))
        assert "Brute Force" in payload["text"]

    def test_slack_payload_severity_in_text(self):
        payload = nw.build_slack_payload(make_args(severity="critical"))
        assert "CRITICAL" in payload["text"]

    def test_slack_color_for_critical(self):
        payload = nw.build_slack_payload(make_args(severity="critical"))
        assert payload["attachments"][0]["color"] == "#cc0000"

    def test_slack_color_for_high(self):
        payload = nw.build_slack_payload(make_args(severity="high"))
        assert payload["attachments"][0]["color"] == "#e07b00"


class TestTeamsPayload:

    def test_teams_payload_type(self):
        payload = nw.build_teams_payload(make_args())
        assert payload["@type"] == "MessageCard"

    def test_teams_payload_has_summary(self):
        payload = nw.build_teams_payload(make_args(alert_name="Malware"))
        assert "Malware" in payload["summary"]

    def test_teams_payload_has_facts(self):
        payload = nw.build_teams_payload(make_args())
        facts = payload["sections"][0]["facts"]
        fact_names = [f["name"] for f in facts]
        assert "Severity" in fact_names
        assert "Time" in fact_names


class TestGenericPayload:

    def test_generic_payload_has_required_fields(self):
        payload = nw.build_generic_payload(make_args())
        assert "alert_name" in payload
        assert "severity" in payload
        assert "timestamp" in payload
        assert "source" in payload

    def test_generic_payload_timestamp_format(self):
        payload = nw.build_generic_payload(make_args())
        ts = payload["timestamp"]
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def test_generic_payload_severity_passthrough(self):
        payload = nw.build_generic_payload(make_args(severity="critical"))
        assert payload["severity"] == "critical"


class TestSeverityConstants:

    def test_all_severities_in_emoji_map(self):
        for sev in ["low", "medium", "high", "critical"]:
            assert sev in nw.SEVERITY_EMOJI

    def test_all_severities_in_color_map(self):
        for sev in ["low", "medium", "high", "critical"]:
            assert sev in nw.SEVERITY_COLOR
