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
import os
import sys


from hec_client import send_events, load_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest JSON events into Splunk HEC")
    parser.add_argument("--file",      required=True, metavar="FILE", help="Path to JSON events file")
    parser.add_argument("--hec-url",   default=os.environ.get("SPLUNK_HEC_URL",   "http://localhost:8088"))
    parser.add_argument("--hec-token", default=os.environ.get("SPLUNK_HEC_TOKEN", ""))
    parser.add_argument("--batch",     type=int, default=100, metavar="N", help="Events per HEC batch")
    args = parser.parse_args()
    if args.batch < 1:
        parser.error("--batch must be positive")
    return args


def main() -> int:
    args = parse_args()

    if not args.hec_token:
        print("[!] Provide --hec-token or set $SPLUNK_HEC_TOKEN", file=sys.stderr)
        return 1

    try:
        events = load_events(args.file)
    except (OSError, ValueError) as exc:
        print(f"[!] Could not load events file: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Loaded {len(events)} events from {args.file}")
    print(f"[*] Sending to {args.hec_url} ...")

    ok = send_events(events, args.hec_url, args.hec_token, batch_size=args.batch)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
