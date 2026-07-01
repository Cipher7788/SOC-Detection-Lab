"""
Unit tests for detection-rules/*.json
Validates schema integrity and required fields for every rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "detection-rules"
RULE_FILES = list(RULES_DIR.glob("*.json"))

REQUIRED_TOP_LEVEL = {
    "rule_name", "description", "version", "severity",
    "mitre_attack", "detection", "response_actions",
    "enabled", "created_at", "author",
}

REQUIRED_MITRE = {"tactic", "technique"}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}

VALID_RESPONSE_ACTIONS = {"alert", "block_ip", "lock_account", "block_destination",
                           "preserve_evidence", "notify_dpo", "capture_memory",
                           "isolate_host", "block_smb", "block_destination"}


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=[f.name for f in RULE_FILES])
class TestDetectionRuleSchema:

    def _load(self, rule_file: Path) -> dict:
        return json.loads(rule_file.read_text())

    def test_is_valid_json(self, rule_file):
        data = self._load(rule_file)
        assert isinstance(data, dict)

    def test_required_top_level_fields(self, rule_file):
        data = self._load(rule_file)
        missing = REQUIRED_TOP_LEVEL - set(data.keys())
        assert not missing, f"Missing fields: {missing}"

    def test_severity_is_valid(self, rule_file):
        data = self._load(rule_file)
        assert data["severity"] in VALID_SEVERITIES

    def test_mitre_fields_present(self, rule_file):
        data = self._load(rule_file)
        mitre = data.get("mitre_attack", {})
        missing = REQUIRED_MITRE - set(mitre.keys())
        assert not missing, f"Missing MITRE fields: {missing}"

    def test_mitre_technique_format(self, rule_file):
        data = self._load(rule_file)
        technique = data["mitre_attack"].get("technique", "")
        assert technique.startswith("T"), f"MITRE technique should start with T: {technique}"

    def test_detection_block_exists(self, rule_file):
        data = self._load(rule_file)
        assert "detection" in data
        assert isinstance(data["detection"], dict)

    def test_response_actions_is_list(self, rule_file):
        data = self._load(rule_file)
        assert isinstance(data["response_actions"], list)
        assert len(data["response_actions"]) >= 1

    def test_response_actions_have_required_fields(self, rule_file):
        data = self._load(rule_file)
        for action in data["response_actions"]:
            assert "action" in action, f"Response action missing 'action': {action}"
            assert "priority" in action, f"Response action missing 'priority': {action}"

    def test_enabled_is_bool(self, rule_file):
        data = self._load(rule_file)
        assert isinstance(data["enabled"], bool)

    def test_splunk_query_present(self, rule_file):
        data = self._load(rule_file)
        assert "splunk_query" in data
        assert len(data["splunk_query"]) > 10, "Splunk query seems too short"

    def test_splunk_query_has_index(self, rule_file):
        data = self._load(rule_file)
        query = data["splunk_query"]
        assert "index=" in query, f"Splunk query should reference an index: {query}"

    def test_author_field(self, rule_file):
        data = self._load(rule_file)
        assert data.get("author"), "Author field should not be empty"

    def test_version_is_string(self, rule_file):
        data = self._load(rule_file)
        assert isinstance(data["version"], str)


class TestAllRulesPresent:

    def test_five_rules_exist(self):
        assert len(RULE_FILES) == 5, f"Expected 5 rules, found {len(RULE_FILES)}"

    def test_expected_rule_files_exist(self):
        expected = {
            "brute-force-detection.json",
            "privilege-escalation.json",
            "lateral-movement.json",
            "data-exfiltration.json",
            "malware-detection.json",
        }
        actual = {f.name for f in RULE_FILES}
        assert expected == actual, f"Missing rules: {expected - actual}"

    def test_all_rules_enabled(self):
        for rule_file in RULE_FILES:
            data = json.loads(rule_file.read_text())
            assert data["enabled"] is True, f"{rule_file.name} should be enabled"
