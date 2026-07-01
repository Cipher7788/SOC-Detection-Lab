"""
Unit tests for scripts/generate-sample-data.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ── Import the generator module without executing __main__ ──────────────────
_SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location(
    "generate_sample_data", _SCRIPTS_DIR / "generate-sample-data.py"
)
gen = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(gen)  # type: ignore[union-attr]

NOW = datetime.now(tz=timezone.utc)


# ── Helper ──────────────────────────────────────────────────────────────────
def ts_ok(ts: str) -> bool:
    """Return True if ts is a valid ISO-8601 UTC timestamp."""
    try:
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


# ── Event builder tests ─────────────────────────────────────────────────────

class TestEventBuilders:

    def test_login_success_fields(self):
        ev = gen.make_login_success(NOW)
        assert ev["event_type"] == "authentication"
        assert ev["EventID"] == 4624
        assert ev["outcome"] == "success"
        assert ts_ok(ev["timestamp"])
        assert ev["src_ip"] in gen.INTERNAL_IPS
        assert ev["user"] in gen.USERS

    def test_login_failure_fields(self):
        ev = gen.make_login_failure(NOW)
        assert ev["EventID"] == 4625
        assert ev["outcome"] == "failure"
        assert "failure_reason" in ev

    def test_login_failure_custom_src_ip(self):
        ev = gen.make_login_failure(NOW, src_ip="1.2.3.4")
        assert ev["src_ip"] == "1.2.3.4"

    def test_process_event_fields(self):
        ev = gen.make_process_event(NOW)
        assert ev["event_type"] == "process_creation"
        assert ev["EventID"] == 4688
        assert "process_name" in ev
        assert "pid" in ev
        assert 1000 <= ev["pid"] <= 65535

    def test_process_event_custom_process(self):
        ev = gen.make_process_event(NOW, process="mimikatz.exe")
        assert ev["process_name"] == "mimikatz.exe"

    def test_network_event_fields(self):
        ev = gen.make_network_event(NOW)
        assert ev["event_type"] == "network_connection"
        assert ev["direction"] == "outbound"
        assert ev["bytes_out"] >= 0
        assert ev["dest_port"] in [80, 443, 445, 3389, 8080, 22, 21]

    def test_network_event_custom_bytes(self):
        ev = gen.make_network_event(NOW, bytes_out=999_999)
        assert ev["bytes_out"] == 999_999

    def test_file_event_fields(self):
        ev = gen.make_file_event(NOW)
        assert ev["event_type"] == "file_access"
        assert ev["EventID"] == 4663
        assert ev["operation"] in ["READ", "WRITE", "DELETE", "RENAME"]

    def test_privilege_event_fields(self):
        ev = gen.make_privilege_event(NOW)
        assert ev["event_type"] == "privilege_use"
        assert ev["EventID"] == 4672
        assert ev["privilege"] in gen.SENSITIVE_PRIVILEGES

    def test_privilege_event_custom_privilege(self):
        ev = gen.make_privilege_event(NOW, privilege="SeDebugPrivilege")
        assert ev["privilege"] == "SeDebugPrivilege"


# ── Scenario tests ──────────────────────────────────────────────────────────

class TestScenarios:

    def _check_events(self, events, expected_n):
        assert len(events) == expected_n
        for ev in events:
            assert ts_ok(ev["timestamp"])
            assert "event_type" in ev

    def test_brute_force_count(self):
        events = gen.scenario_brute_force(NOW, 10)
        self._check_events(events, 10)

    def test_brute_force_last_event_is_success(self):
        events = gen.scenario_brute_force(NOW, 10)
        assert events[-1]["outcome"] == "success"

    def test_brute_force_failures_share_ip(self):
        events = gen.scenario_brute_force(NOW, 10)
        failures = [e for e in events if e["outcome"] == "failure"]
        ips = {e["src_ip"] for e in failures}
        assert len(ips) == 1, "All failures should come from the same attacker IP"

    def test_privilege_escalation_count(self):
        events = gen.scenario_privilege_escalation(NOW, 8)
        self._check_events(events, 8)

    def test_privilege_escalation_first_is_login(self):
        events = gen.scenario_privilege_escalation(NOW, 5)
        assert events[0]["EventID"] == 4624

    def test_lateral_movement_count(self):
        events = gen.scenario_lateral_movement(NOW, 5)
        self._check_events(events, 5)

    def test_lateral_movement_uses_suspicious_procs(self):
        events = gen.scenario_lateral_movement(NOW, 10)
        procs = {e["process_name"] for e in events}
        lateral_procs = {"psexec.exe", "wmic.exe", "winrs.exe", "powershell.exe"}
        assert procs & lateral_procs, "Should include lateral movement tools"

    def test_data_exfiltration_count(self):
        events = gen.scenario_data_exfiltration(NOW, 10)
        self._check_events(events, 10)

    def test_data_exfiltration_has_large_transfers(self):
        events = gen.scenario_data_exfiltration(NOW, 10)
        net_events = [e for e in events if e["event_type"] == "network_connection"]
        assert any(e["bytes_out"] > 1_000_000 for e in net_events)

    def test_malware_count(self):
        events = gen.scenario_malware(NOW, 8)
        self._check_events(events, 8)

    def test_malware_has_malware_processes(self):
        events = gen.scenario_malware(NOW, 20)
        proc_events = [e for e in events if e["event_type"] == "process_creation"]
        procs = {e["process_name"] for e in proc_events}
        assert procs & set(gen.MALWARE_PROCESSES)

    def test_malware_has_c2_beaconing(self):
        events = gen.scenario_malware(NOW, 20)
        beacon_events = [e for e in events if "beacon_interval_seconds" in e]
        assert len(beacon_events) > 0

    def test_all_scenarios_in_scenario_map(self):
        expected = {
            "brute-force", "privilege-escalation",
            "lateral-movement", "data-exfiltration", "malware"
        }
        assert set(gen.SCENARIO_MAP.keys()) == expected


# ── Random mix tests ────────────────────────────────────────────────────────

class TestRandomMix:

    def test_random_events_count(self):
        events = gen.random_events(NOW, 100)
        assert len(events) == 100

    def test_random_events_mixed_types(self):
        events = gen.random_events(NOW, 100)
        types = {e["event_type"] for e in events}
        assert len(types) >= 2, "Should have at least 2 different event types"

    def test_random_events_all_have_timestamps(self):
        events = gen.random_events(NOW, 50)
        for ev in events:
            assert ts_ok(ev["timestamp"])


# ── CLI / file output tests ─────────────────────────────────────────────────

class TestCLI:

    def test_output_file_written(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            sys.argv = ["generate-sample-data.py", "--events", "5", "--output", path]
            gen.main()
            data = json.loads(Path(path).read_text())
            assert len(data) == 5
        finally:
            os.unlink(path)

    def test_output_sorted_by_timestamp(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            sys.argv = ["generate-sample-data.py", "--events", "30", "--output", path]
            gen.main()
            data = json.loads(Path(path).read_text())
            timestamps = [e["timestamp"] for e in data]
            assert timestamps == sorted(timestamps), "Events should be sorted by timestamp"
        finally:
            os.unlink(path)

    def test_scenario_flag(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            sys.argv = [
                "generate-sample-data.py",
                "--scenario", "brute-force",
                "--events", "10",
                "--output", path,
            ]
            gen.main()
            data = json.loads(Path(path).read_text())
            assert len(data) == 10
        finally:
            os.unlink(path)
