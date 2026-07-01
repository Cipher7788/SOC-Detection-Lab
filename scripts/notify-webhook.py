#!/usr/bin/env python3
"""
SOC Detection Lab – Webhook Notification Helper
================================================
Sends alert notifications to Slack, Microsoft Teams, or a generic webhook
(PagerDuty, Discord, etc.).

Usage
-----
    # Slack
    python3 notify-webhook.py \
        --provider slack \
        --webhook-url https://hooks.slack.com/services/T.../B.../xxx \
        --alert-name "Brute Force Detected" \
        --severity high \
        --src-ip 45.33.32.156 \
        --details "15 failed logins in 10 minutes"

    # Microsoft Teams
    python3 notify-webhook.py \
        --provider teams \
        --webhook-url https://outlook.office.com/webhook/... \
        --alert-name "Malware Detected" \
        --severity critical

    # Generic JSON POST (PagerDuty, Discord, etc.)
    python3 notify-webhook.py \
        --provider generic \
        --webhook-url https://events.pagerduty.com/v2/enqueue \
        --alert-name "Data Exfiltration" \
        --severity critical
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict


# ── Payload builders ─────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "low":      "🟢",
    "medium":   "🟡",
    "high":     "🟠",
    "critical": "🔴",
}

SEVERITY_COLOR = {
    "low":      "#36a64f",
    "medium":   "#f4c542",
    "high":     "#e07b00",
    "critical": "#cc0000",
}


def build_slack_payload(args: argparse.Namespace) -> Dict[str, Any]:
    emoji = SEVERITY_EMOJI.get(args.severity, "⚠️")
    color = SEVERITY_COLOR.get(args.severity, "#888888")
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} SOC Alert: {args.alert_name}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n`{args.severity.upper()}`"},
                {"type": "mrkdwn", "text": f"*Time:*\n{ts}"},
            ],
        },
    ]

    if args.src_ip:
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source IP:*\n`{args.src_ip}`"},
                {"type": "mrkdwn", "text": f"*Host:*\n`{args.host or 'Unknown'}`"},
            ],
        })

    if args.details:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Details:*\n{args.details}"},
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": "SOC Detection Lab | http://localhost:8000"}
        ],
    })

    return {
        "text": f"{emoji} SOC Alert: {args.alert_name} [{args.severity.upper()}]",
        "attachments": [{"color": color, "blocks": blocks}],
    }


def build_teams_payload(args: argparse.Namespace) -> Dict[str, Any]:
    emoji = SEVERITY_EMOJI.get(args.severity, "⚠️")
    color = SEVERITY_COLOR.get(args.severity, "#888888").lstrip("#")
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    facts = [
        {"name": "Severity", "value": args.severity.upper()},
        {"name": "Time",     "value": ts},
    ]
    if args.src_ip:
        facts.append({"name": "Source IP", "value": args.src_ip})
    if args.host:
        facts.append({"name": "Host", "value": args.host})

    return {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": color,
        "summary":    f"SOC Alert: {args.alert_name}",
        "sections": [
            {
                "activityTitle":    f"{emoji} **SOC Alert: {args.alert_name}**",
                "activitySubtitle": args.details or "See Splunk for details.",
                "facts":            facts,
                "markdown":         True,
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name":  "Open Splunk",
                "targets": [{"os": "default", "uri": "http://localhost:8000"}],
            }
        ],
    }


def build_generic_payload(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "alert_name": args.alert_name,
        "severity":   args.severity,
        "src_ip":     args.src_ip or "",
        "host":       args.host or "",
        "details":    args.details or "",
        "timestamp":  datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source":     "SOC Detection Lab",
        "splunk_url": "http://localhost:8000",
    }


PAYLOAD_BUILDERS = {
    "slack":   build_slack_payload,
    "teams":   build_teams_payload,
    "generic": build_generic_payload,
}


# ── Sender ───────────────────────────────────────────────────────────────────

def send_notification(url: str, payload: Dict[str, Any]) -> bool:
    try:
        import requests  # type: ignore
    except ImportError:
        print("[!] 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
        return False

    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code in (200, 202, 204):
            print(f"[✓] Notification sent (HTTP {resp.status_code})")
            return True
        print(f"[!] Webhook returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return False
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}", file=sys.stderr)
        return False


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send SOC alert notifications via webhook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--provider",    required=True, choices=["slack", "teams", "generic"])
    parser.add_argument("--webhook-url", required=True,
                        default=os.environ.get("ALERT_WEBHOOK_URL"),
                        help="Webhook URL (or set $ALERT_WEBHOOK_URL)")
    parser.add_argument("--alert-name",  required=True)
    parser.add_argument("--severity",    default="high",
                        choices=["low", "medium", "high", "critical"])
    parser.add_argument("--src-ip",      default=None)
    parser.add_argument("--host",        default=None)
    parser.add_argument("--details",     default=None)
    parser.add_argument("--dry-run",     action="store_true",
                        help="Print payload without sending")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    builder = PAYLOAD_BUILDERS[args.provider]
    payload = builder(args)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    return 0 if send_notification(args.webhook_url, payload) else 1


if __name__ == "__main__":
    sys.exit(main())
