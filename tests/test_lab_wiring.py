"""Regression checks for the configuration paths that broke fresh startup."""
import configparser
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "splunk/apps/soc_lab"


def conf(name):
    parser = configparser.RawConfigParser()
    parser.read(APP / "default" / name, encoding="utf-8")
    return parser


def test_compose_mount_sources_exist():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for service in compose["services"].values():
        for mount in service.get("volumes", []):
            source = mount.split(":")[0]
            if source.startswith("./"):
                assert (ROOT / source).exists(), source
    assert "./splunk/apps/soc_lab:/opt/splunk/etc/apps/soc_lab" in compose["services"]["splunk"]["volumes"]
    assert (APP / "lookups").is_dir()


def test_all_referenced_lookups_exist():
    transforms = conf("transforms.conf")
    for section in transforms.sections():
        if transforms.has_option(section, "filename"):
            assert (ROOT / "splunk/lookups" / transforms.get(section, "filename")).is_file()


def test_required_indexes_and_jsonl_monitor():
    assert {"security", "network", "alerts"} <= set(conf("indexes.conf").sections())
    inputs = conf("inputs.conf")
    monitor = inputs["monitor:///data-sources/logs/*.jsonl"]
    assert monitor["index"] == "security"
    assert monitor["sourcetype"] == "soc_lab_json"
    assert "[monitor:///data-sources/logs/*.json]" not in (APP / "default/inputs.conf").read_text()


def test_json_catalog_and_installed_searches_match():
    searches = conf("savedsearches.conf")
    installed = {" ".join(searches.get(s, "search").replace("\\\n", " ").split())
                 for s in searches.sections()}
    catalog = {" ".join(json.loads(p.read_text())["splunk_query"].split())
               for p in (ROOT / "detection-rules").glob("*.json")}
    assert installed == catalog


def test_all_searches_track_only_nonempty_results():
    searches = conf("savedsearches.conf")
    for section in searches.sections():
        assert searches.get(section, "alert_type") == "number of events"
        assert searches.get(section, "alert_threshold") == "0"
        assert searches.get(section, "alert.track") == "1"
        assert searches.get(section, "actions") == ""
