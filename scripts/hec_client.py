"""Shared HEC transport for JSON arrays and JSON Lines event files."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import requests


def load_events(filename: str) -> List[dict]:
    text = Path(filename).read_text(encoding="utf-8")
    try:
        events = json.loads(text)
    except json.JSONDecodeError:
        events = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(events, dict):
        events = [events]
    if not isinstance(events, list) or not events or not all(isinstance(ev, dict) for ev in events):
        raise ValueError("Expected a nonempty JSON array or JSON Lines of event objects")
    return events


def envelope(event: dict) -> dict:
    """HEC's time field accepts epoch seconds, not an ISO timestamp."""
    if not isinstance(event, dict):
        raise ValueError("Each event must be an object")
    result = {"sourcetype": "soc_lab_json", "index": "security", "event": event}
    if "timestamp" in event:
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        result["time"] = timestamp.timestamp()
    if event.get("host"):
        result["host"] = event["host"]
    return result


def send_events(events: List[dict], hec_url: str, hec_token: str, batch_size: int = 100) -> bool:
    """Retry explicit 503s only; retrying timeouts could duplicate events."""
    if batch_size < 1 or not hec_token or not isinstance(events, list) or not events:
        print("[!] A token, nonempty event list, and positive batch size are required", file=sys.stderr)
        return False
    try:
        encoded = [json.dumps(envelope(ev)) for ev in events]
    except (ValueError, TypeError, AttributeError) as exc:
        print(f"[!] Invalid event: {exc}", file=sys.stderr)
        return False
    endpoint = hec_url.rstrip("/") + "/services/collector/event"
    headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    for i in range(0, len(encoded), batch_size):
        chunk = encoded[i:i + batch_size]
        try:
            for attempt in range(5):
                response = requests.post(endpoint, data="\n".join(chunk), headers=headers, timeout=15)
                if response.status_code != 503 or attempt == 4:
                    break
                time.sleep(2 ** attempt)
            if response.status_code != 200 or response.json().get("code") != 0:
                print(f"[!] HEC rejected batch (HTTP {response.status_code}): {response.text[:200]}",
                      file=sys.stderr)
                return False
        except (requests.RequestException, ValueError, AttributeError) as exc:
            print(f"[!] HEC request failed: {exc}", file=sys.stderr)
            return False
        print(f"[+] Sent {i + len(chunk)}/{len(events)} events")
    return True
