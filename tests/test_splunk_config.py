"""
Unit tests for Splunk configuration files.
Validates that all .conf files are well-formed and contain required stanzas.
"""

from __future__ import annotations

import configparser
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SPLUNK_DEFAULT = Path(__file__).parent.parent / "splunk/apps/soc_lab/default"
SPLUNK_DASHBOARDS = Path(__file__).parent.parent / "splunk/apps/soc_lab/default/data/ui/views"


def load_conf(filename: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False)
    cp.read(SPLUNK_DEFAULT / filename, encoding="utf-8")
    return cp


class TestInputsConf:

    def test_file_exists(self):
        assert (SPLUNK_DEFAULT / "inputs.conf").exists()

    def test_hec_managed_by_official_image(self):
        content = (SPLUNK_DEFAULT / "inputs.conf").read_text()
        assert "REPLACE_WITH_HEC_TOKEN" not in content
        assert "[http://" not in content

    def test_hec_defaults(self):
        import yaml
        defaults = yaml.safe_load((SPLUNK_DEFAULT.parents[2] / "defaults.yml").read_text())
        assert defaults["splunk"]["hec"] == {"enable": True, "ssl": False, "port": 8088}


class TestPropsConf:

    def test_file_exists(self):
        assert (SPLUNK_DEFAULT / "props.conf").exists()

    def test_windows_events_stanza(self):
        content = (SPLUNK_DEFAULT / "props.conf").read_text()
        assert "windows_events" in content.lower() or "[windows_events]" in content

    def test_timestamp_format_defined(self):
        content = (SPLUNK_DEFAULT / "props.conf").read_text()
        assert "TIME_FORMAT" in content


class TestTransformsConf:

    def test_file_exists(self):
        assert (SPLUNK_DEFAULT / "transforms.conf").exists()

    def test_lookup_stanzas(self):
        content = (SPLUNK_DEFAULT / "transforms.conf").read_text()
        assert "internal_ips" in content
        assert "known_bad" in content


class TestSavedSearchesConf:

    def test_file_exists(self):
        assert (SPLUNK_DEFAULT / "savedsearches.conf").exists()

    def test_five_alert_stanzas(self):
        content = (SPLUNK_DEFAULT / "savedsearches.conf").read_text()
        expected_alerts = [
            "Brute Force Detection",
            "Privilege Escalation Detection",
            "Lateral Movement Detection",
            "Data Exfiltration Detection",
            "Malware Detection",
        ]
        for alert in expected_alerts:
            assert alert in content, f"Missing alert: {alert}"

    def test_all_alerts_have_cron(self):
        content = (SPLUNK_DEFAULT / "savedsearches.conf").read_text()
        assert content.count("cron_schedule") >= 5

    def test_alerts_have_no_placeholder_destinations(self):
        content = (SPLUNK_DEFAULT / "savedsearches.conf").read_text()
        assert "security@company.com" not in content
        assert "REPLACE/YOUR/WEBHOOK" not in content

    def test_all_alerts_enabled(self):
        content = (SPLUNK_DEFAULT / "savedsearches.conf").read_text()
        # Check no alert is disabled
        assert "disabled = 1" not in content


class TestEventTypesConf:

    def test_file_exists(self):
        assert (SPLUNK_DEFAULT / "eventtypes.conf").exists()

    def test_authentication_event_types(self):
        content = (SPLUNK_DEFAULT / "eventtypes.conf").read_text()
        assert "authentication_success" in content
        assert "authentication_failure" in content

    def test_threat_indicator_event_types(self):
        content = (SPLUNK_DEFAULT / "eventtypes.conf").read_text()
        assert "brute_force_indicator" in content
        assert "malware_indicator" in content


class TestDashboardXML:

    def test_security_overview_exists(self):
        assert (SPLUNK_DASHBOARDS / "security-overview.xml").exists()

    def test_valid_xml(self):
        tree = ET.parse(SPLUNK_DASHBOARDS / "security-overview.xml")
        root = tree.getroot()
        assert root.tag == "form", f"Root tag should be 'form', got '{root.tag}'"

    def test_dashboard_has_panels(self):
        tree = ET.parse(SPLUNK_DASHBOARDS / "security-overview.xml")
        panels = tree.findall(".//panel")
        assert len(panels) >= 4, f"Expected at least 4 panels, found {len(panels)}"

    def test_dashboard_has_searches(self):
        tree = ET.parse(SPLUNK_DASHBOARDS / "security-overview.xml")
        searches = tree.findall(".//query")
        assert len(searches) >= 4, f"Expected at least 4 search queries"

    def test_all_searches_reference_index(self):
        tree = ET.parse(SPLUNK_DASHBOARDS / "security-overview.xml")
        queries = [q.text for q in tree.findall(".//query") if q.text]
        for q in queries:
            assert "index=" in q, f"Query missing index=: {q[:60]}"
