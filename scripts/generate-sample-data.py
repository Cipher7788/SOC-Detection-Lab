#!/usr/bin/env python3
"""
SOC Detection Lab – Sample Security Event Data Generator
=========================================================
Generates realistic security event data for the SOC Detection Lab.
Events cover authentication, process execution, network connections,
and file access activities across five attack scenarios.

Usage
-----
    python3 generate-sample-data.py                          # 100 random events
    python3 generate-sample-data.py --events 500             # 500 random events
    python3 generate-sample-data.py --scenario brute-force   # scenario-specific events
    python3 generate-sample-data.py --scenario lateral-movement --events 50
    python3 generate-sample-data.py --output /path/to/out.json
    python3 generate-sample-data.py --send-hec               # send directly to Splunk HEC

Scenarios
---------
    brute-force           Multiple failed logins from the same IP
    privilege-escalation  Sensitive privilege assignment events
    lateral-movement      Remote admin tool execution across hosts
    data-exfiltration     Large outbound transfers and DNS tunnelling
    malware               Malicious process names and C2 beacons
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

# ─── Constants ───────────────────────────────────────────────────────────────

INTERNAL_IPS: List[str] = (
    [f"192.168.1.{i}" for i in range(10, 100)]
    + [f"10.0.0.{i}" for i in range(5, 50)]
)

EXTERNAL_IPS: List[str] = [
    "45.33.32.156",
    "185.220.101.5",
    "94.102.49.190",
    "198.51.100.42",
    "203.0.113.17",
    "91.108.56.12",
    "104.244.42.1",
    "51.15.0.1",
    "77.109.139.87",
]

HOSTNAMES: List[str] = (
    [f"WORKSTATION-{n:03d}" for n in range(1, 21)]
    + [f"SERVER-{n:02d}" for n in range(1, 6)]
)

USERS: List[str] = [
    "alice", "bob", "charlie", "diana", "eve",
    "frank", "grace", "heidi", "ivan", "judy",
    "admin", "svc_backup", "svc_sql", "helpdesk",
]

LEGITIMATE_PROCESSES: List[str] = [
    "explorer.exe", "svchost.exe", "chrome.exe", "outlook.exe",
    "excel.exe", "word.exe", "notepad.exe", "taskmgr.exe",
]

SUSPICIOUS_PROCESSES: List[str] = [
    "psexec.exe", "wmic.exe", "powershell.exe", "mimikatz.exe",
    "meterpreter.exe", "nc.exe", "ncat.exe", "certutil.exe",
    "bitsadmin.exe", "regsvr32.exe", "mshta.exe",
]

MALWARE_PROCESSES: List[str] = [
    "mimikatz.exe", "meterpreter.exe", "pwdump.exe",
    "fgdump.exe", "wce.exe", "cobalt_strike.exe",
]

SENSITIVE_FILES: List[str] = [
    "C:\\Finance\\Q4_Budget.xlsx",
    "C:\\HR\\Employee_Records.csv",
    "C:\\IT\\passwords.kdbx",
    "/etc/shadow",
    "/var/lib/secrets/api_keys.json",
    "D:\\Confidential\\M&A_Plans.docx",
]

WINDOWS_EVENTIDS: Dict[str, int] = {
    "login_success":  4624,
    "login_failure":  4625,
    "privilege_use":  4672,
    "process_create": 4688,
    "file_access":    4663,
    "registry_change": 4657,
    "account_change": 4728,
}

SENSITIVE_PRIVILEGES: List[str] = [
    "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
    "SeLoadDriverPrivilege", "SeBackupPrivilege",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _ts(dt: datetime) -> str:
    """Return ISO-8601 UTC timestamp string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Event builders ──────────────────────────────────────────────────────────

def make_login_success(dt: datetime) -> dict:
    return {
        "timestamp":  _ts(dt),
        "event_type": "authentication",
        "EventID":    WINDOWS_EVENTIDS["login_success"],
        "host":       random.choice(HOSTNAMES),
        "user":       random.choice(USERS),
        "src_ip":     random.choice(INTERNAL_IPS),
        "logon_type": random.choice([2, 3, 10]),
        "outcome":    "success",
    }


def make_login_failure(dt: datetime, src_ip: Optional[str] = None) -> dict:
    return {
        "timestamp":      _ts(dt),
        "event_type":     "authentication",
        "EventID":        WINDOWS_EVENTIDS["login_failure"],
        "host":           random.choice(HOSTNAMES),
        "user":           random.choice(USERS),
        "src_ip":         src_ip or random.choice(INTERNAL_IPS + EXTERNAL_IPS),
        "logon_type":     3,
        "outcome":        "failure",
        "failure_reason": random.choice([
            "Unknown username or bad password",
            "Account locked out",
            "Account disabled",
        ]),
    }


def make_process_event(dt: datetime, process: Optional[str] = None) -> dict:
    proc = process or random.choice(LEGITIMATE_PROCESSES + SUSPICIOUS_PROCESSES)
    return {
        "timestamp":      _ts(dt),
        "event_type":     "process_creation",
        "EventID":        WINDOWS_EVENTIDS["process_create"],
        "host":           random.choice(HOSTNAMES),
        "user":           random.choice(USERS),
        "process_name":   proc,
        "process_path":   f"C:\\Windows\\System32\\{proc}",
        "parent_process": random.choice(LEGITIMATE_PROCESSES),
        "cmdline":        f"{proc} /silent",
        "pid":            random.randint(1000, 65535),
    }


def make_network_event(
    dt: datetime,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    bytes_out: Optional[int] = None,
) -> dict:
    return {
        "timestamp":  _ts(dt),
        "event_type": "network_connection",
        "host":       random.choice(HOSTNAMES),
        "src_ip":     src_ip or random.choice(INTERNAL_IPS),
        "dest_ip":    dest_ip or random.choice(EXTERNAL_IPS),
        "dest_port":  random.choice([80, 443, 445, 3389, 8080, 22, 21]),
        "protocol":   random.choice(["TCP", "UDP"]),
        "bytes_in":   random.randint(1_000, 50_000),
        "bytes_out":  bytes_out if bytes_out is not None else random.randint(1_000, 100_000),
        "direction":  "outbound",
    }


def make_file_event(dt: datetime, file_path: Optional[str] = None) -> dict:
    return {
        "timestamp":    _ts(dt),
        "event_type":   "file_access",
        "EventID":      WINDOWS_EVENTIDS["file_access"],
        "host":         random.choice(HOSTNAMES),
        "user":         random.choice(USERS),
        "file_path":    file_path or random.choice(SENSITIVE_FILES),
        "operation":    random.choice(["READ", "WRITE", "DELETE", "RENAME"]),
        "process_name": random.choice(LEGITIMATE_PROCESSES),
    }


def make_privilege_event(dt: datetime, privilege: Optional[str] = None) -> dict:
    return {
        "timestamp":  _ts(dt),
        "event_type": "privilege_use",
        "EventID":    WINDOWS_EVENTIDS["privilege_use"],
        "host":       random.choice(HOSTNAMES),
        "user":       random.choice(USERS),
        "privilege":  privilege or random.choice(SENSITIVE_PRIVILEGES),
        "logon_id":   hex(random.randint(0x10000, 0xFFFFFF)),
    }


# ─── Scenario generators ─────────────────────────────────────────────────────

def scenario_brute_force(start: datetime, n: int) -> List[dict]:
    """Brute force: bursts of failures from attacker IP, then a success."""
    events: List[dict] = []
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_user = random.choice(USERS)

    for i in range(n):
        dt = start + timedelta(seconds=i * 10)
        if i < n - 1 or n == 1:
            ev = make_login_failure(dt, src_ip=attacker_ip)
            ev["user"] = target_user
        else:
            ev = make_login_success(dt)
            ev["user"] = target_user
            ev["src_ip"] = attacker_ip
        events.append(ev)

    return events


def scenario_privilege_escalation(start: datetime, n: int) -> List[dict]:
    """Privilege escalation: normal login then sensitive privilege use."""
    events: List[dict] = []
    user = random.choice(USERS)

    for i in range(n):
        dt = start + timedelta(minutes=i)
        if i == 0:
            ev = make_login_success(dt)
            ev["user"] = user
        else:
            ev = make_privilege_event(dt)
            ev["user"] = user
        events.append(ev)

    return events


def scenario_lateral_movement(start: datetime, n: int) -> List[dict]:
    """Lateral movement: PSExec / WMI calls across multiple hosts."""
    events: List[dict] = []
    attacker_host = random.choice(HOSTNAMES)

    for i in range(n):
        dt = start + timedelta(minutes=i * 2)
        proc = random.choice(["psexec.exe", "wmic.exe", "winrs.exe", "powershell.exe"])
        ev = make_process_event(dt, process=proc)
        ev["host"] = attacker_host
        ev["cmdline"] = f"{proc} \\\\{random.choice(HOSTNAMES)} cmd /c whoami"
        events.append(ev)

    return events


def scenario_data_exfiltration(start: datetime, n: int) -> List[dict]:
    """Data exfiltration: large outbound transfers to external IPs."""
    events: List[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    dest_ip = random.choice(EXTERNAL_IPS)

    for i in range(n):
        dt = start + timedelta(minutes=i * 3)
        if i % 5 == 0:
            ev = make_file_event(dt)
        else:
            ev = make_network_event(
                dt,
                src_ip=src_ip,
                dest_ip=dest_ip,
                bytes_out=random.randint(50_000_000, 500_000_000),
            )
        events.append(ev)

    return events


def scenario_malware(start: datetime, n: int) -> List[dict]:
    """Malware execution and C2 beaconing."""
    events: List[dict] = []
    attacker_c2 = random.choice(EXTERNAL_IPS)
    beacon_interval = random.choice([30, 60, 120, 300])

    for i in range(n):
        dt = start + timedelta(seconds=i * beacon_interval)
        if i % 4 == 0:
            ev = make_process_event(dt, process=random.choice(MALWARE_PROCESSES))
        else:
            ev = make_network_event(
                dt, dest_ip=attacker_c2, bytes_out=random.randint(500, 5_000)
            )
            ev["beacon_interval_seconds"] = beacon_interval
        events.append(ev)

    return events


SCENARIO_MAP: Dict[str, Callable[[datetime, int], List[dict]]] = {
    "brute-force":           scenario_brute_force,
    "privilege-escalation":  scenario_privilege_escalation,
    "lateral-movement":      scenario_lateral_movement,
    "data-exfiltration":     scenario_data_exfiltration,
    "malware":               scenario_malware,
}


# ─── Random event mix ────────────────────────────────────────────────────────

def random_events(start: datetime, n: int) -> List[dict]:
    """Generate a random mix of security events."""
    generators = [
        make_login_success,
        make_login_failure,
        make_process_event,
        make_network_event,
        make_file_event,
        make_privilege_event,
    ]
    events: List[dict] = []
    for i in range(n):
        dt = start + timedelta(minutes=i)
        ev = random.choice(generators)(dt)
        events.append(ev)
    return events


# ─── HEC sender (optional) ────────────────────────────────────────────────────

def send_to_hec(events: List[dict], hec_url: str, hec_token: str) -> None:
    """Send events to Splunk HTTP Event Collector."""
    try:
        import requests  # type: ignore
    except ImportError:
        print("[!] 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
        sys.exit(1)

    headers = {"Authorization": f"Splunk {hec_token}"}
    endpoint = hec_url.rstrip("/") + "/services/collector"

    batch: List[dict] = []
    for ev in events:
        batch.append({"time": ev["timestamp"], "sourcetype": "json", "event": ev})

    # Send in chunks of 100
    chunk_size = 100
    for i in range(0, len(batch), chunk_size):
        chunk = batch[i : i + chunk_size]
        payload = "\n".join(json.dumps(e) for e in chunk)
        resp = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        if resp.status_code != 200:
            print(f"[!] HEC returned {resp.status_code}: {resp.text}", file=sys.stderr)
        else:
            print(f"[+] Sent {len(chunk)} events to HEC ({i + len(chunk)}/{len(events)})")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate sample security events for the SOC Detection Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_MAP.keys()),
        default=None,
        help="Attack scenario to simulate (default: random mix)",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=100,
        metavar="N",
        help="Number of events to generate (default: 100)",
    )
    parser.add_argument(
        "--output",
        default="sample_security_events.json",
        metavar="FILE",
        help="Output file path (default: sample_security_events.json)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation level (default: 2)",
    )
    parser.add_argument(
        "--send-hec",
        action="store_true",
        help="Send events to Splunk HEC instead of writing to file",
    )
    parser.add_argument(
        "--hec-url",
        default=os.environ.get("SPLUNK_HEC_URL", "http://localhost:8088"),
        metavar="URL",
        help="Splunk HEC URL (default: $SPLUNK_HEC_URL or http://localhost:8088)",
    )
    parser.add_argument(
        "--hec-token",
        default=os.environ.get("SPLUNK_HEC_TOKEN", ""),
        metavar="TOKEN",
        help="Splunk HEC token (default: $SPLUNK_HEC_TOKEN)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    start_time = datetime.now(tz=timezone.utc) - timedelta(hours=1)

    print(f"[*] Generating {args.events} events", end="")
    if args.scenario:
        print(f" for scenario: {args.scenario}")
        generator = SCENARIO_MAP[args.scenario]
    else:
        print(" (random mix)")
        generator = random_events

    events = generator(start_time, args.events)

    # Sort chronologically
    events.sort(key=lambda e: e["timestamp"])

    if args.send_hec:
        if not args.hec_token:
            print("[!] --hec-token or $SPLUNK_HEC_TOKEN is required for --send-hec", file=sys.stderr)
            return 1
        send_to_hec(events, args.hec_url, args.hec_token)
    else:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(events, fh, indent=args.indent)
            print(f"[+] {len(events)} events written to {args.output}")
        except OSError as exc:
            print(f"[!] Failed to write output file: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
