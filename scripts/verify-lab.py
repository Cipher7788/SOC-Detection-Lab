#!/usr/bin/env python3
"""Read-only live checks: HEC health, app loading, indexes, views and events."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--management-url", default="https://localhost:8089")
    parser.add_argument("--hec-url", default="http://localhost:8088")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--insecure", action="store_true", help="Accept the local Splunk self-signed certificate")
    parser.add_argument("--detections", action="store_true", help="Require results from all five seeded scenarios")
    args = parser.parse_args()
    values = {}
    if args.env_file.exists():
        for line in args.env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    password = os.environ.get("SPLUNK_PASSWORD", values.get("SPLUNK_PASSWORD"))
    if not password:
        print("Set SPLUNK_PASSWORD or provide .env", file=sys.stderr)
        return 1
    session = requests.Session()
    session.auth = HTTPBasicAuth("admin", password)
    session.verify = not args.insecure
    base = args.management_url.rstrip("/")
    try:
        requests.get(args.hec_url.rstrip("/") + "/services/collector/health", timeout=15).raise_for_status()
        for endpoint in ["/services/apps/local/soc_lab", "/services/data/indexes/security",
                         "/services/data/indexes/network", "/services/data/indexes/alerts",
                         "/servicesNS/admin/soc_lab/data/ui/views/security-overview"]:
            session.get(base + endpoint, timeout=15).raise_for_status()
            print(f"PASS: {endpoint}")
        response = session.post(base + "/services/search/jobs/export", data={
            "search": "search index=security earliest=-15m | stats count",
            "output_mode": "json",
        }, timeout=30)
        response.raise_for_status()
        rows = [json.loads(line) for line in response.text.splitlines() if line]
        counts = [int(row["result"]["count"]) for row in rows if "result" in row]
        if not counts or counts[-1] < 1:
            print("FAIL: no recent security events (indexing may still be catching up)", file=sys.stderr)
            return 1
        print(f"PASS: {counts[-1]} recent security events")
        if args.detections:
            from urllib.parse import quote
            for title in ["Brute Force Detection", "Privilege Escalation Detection", "Lateral Movement Detection",
                          "Data Exfiltration Detection", "Malware Detection"]:
                saved = session.get(base + "/servicesNS/admin/soc_lab/saved/searches/" + quote(title, safe=""),
                                    params={"output_mode": "json"}, timeout=15)
                saved.raise_for_status()
                query = saved.json()["entry"][0]["content"]["search"]
                result = session.post(base + "/servicesNS/admin/soc_lab/search/jobs/export", data={
                    "search": "search " + query + " | head 1", "earliest_time": "-15m", "latest_time": "now",
                    "output_mode": "json",
                }, timeout=30)
                result.raise_for_status()
                if not any("result" in json.loads(line) for line in result.text.splitlines() if line):
                    print(f"FAIL: no results for {title}", file=sys.stderr)
                    return 1
                print(f"PASS: {title}")
        return 0
    except (requests.RequestException, ValueError, KeyError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
