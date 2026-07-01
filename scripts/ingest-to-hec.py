#!/usr/bin/env python3
"""
SOC Detection Lab – HEC Ingestion Helper
=========================================
Reads a JSON events file (produced by generate-sample-data.py) and
forwards each event to the Splunk HTTP Event Collector (HEC).

Usage
-----
    python3 ingest-to-hec.py --file sample_security_events.json
    python3 ingest-to-hec.py --file data-sources/logs/initial-events.json \
        --hec-url http://localhost:8088 --hec-token YOUR_TOKEN
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List


def send_events(events: List[dict], hec_url: str, hec_token: str, batch_size: int = 100) -> bool:
    try:
        import requests  # type: ignore
    except ImportError:
        print("[!] 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
        return False

    headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    endpoint = hec_url.rstrip("/") + "/services/collector"
    total_sent = 0

    for i in range(0, len(events), batch_size):
        chunk = events[i : i + batch_size]
        payload = "\n".join(
            json.dumps({"sourcetype": "json", "index": "security", "event": ev})
            for ev in chunk
        )
        try:
            resp = requests.post(endpoint, data=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                total_sent += len(chunk)
                print(f"[+] Sent {total_sent}/{len(events)} events")
            else:
                print(f"[!] HEC error {resp.status_code}: {resp.text}", file=sys.stderr)
                return False
        except requests.RequestException as exc:
            print(f"[!] Connection error: {exc}", file=sys.stderr)
            return False

    print(f"\n[✓] All {total_sent} events ingested successfully.")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest JSON events into Splunk HEC")
    parser.add_argument("--file",      required=True, metavar="FILE", help="Path to JSON events file")
    parser.add_argument("--hec-url",   default=os.environ.get("SPLUNK_HEC_URL",   "http://localhost:8088"))
    parser.add_argument("--hec-token", default=os.environ.get("SPLUNK_HEC_TOKEN", ""))
    parser.add_argument("--batch",     type=int, default=100, metavar="N", help="Events per HEC batch")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.hec_token:
        print("[!] Provide --hec-token or set $SPLUNK_HEC_TOKEN", file=sys.stderr)
        return 1

    try:
        with open(args.file, encoding="utf-8") as fh:
            events = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Could not load events file: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Loaded {len(events)} events from {args.file}")
    print(f"[*] Sending to {args.hec_url} ...")

    ok = send_events(events, args.hec_url, args.hec_token, batch_size=args.batch)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
