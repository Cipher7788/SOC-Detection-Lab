import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

import hec_client

EVENT = {"timestamp": "2026-11-08T12:00:00Z", "host": "SERVER-01", "EventID": 4625}


def response(status=200, code=0):
    result = Mock(status_code=status, text="HEC response")
    result.json.return_value = {"code": code}
    return result


def test_epoch_timestamp_and_host():
    result = hec_client.envelope(EVENT)
    assert result["time"] == datetime(2026, 11, 8, 12, tzinfo=timezone.utc).timestamp()
    assert result["index"] == "security"
    assert result["host"] == EVENT["host"]
    assert result["event"] == EVENT


def test_batches_and_preserves_events(monkeypatch):
    post = Mock(return_value=response())
    monkeypatch.setattr(hec_client.requests, "post", post)
    assert hec_client.send_events([EVENT] * 5, "http://splunk:8088/", "token", 2)
    assert post.call_count == 3
    sent = [json.loads(line) for call in post.call_args_list for line in call.kwargs["data"].splitlines()]
    assert len(sent) == 5
    assert all(item["event"] == EVENT for item in sent)


@pytest.mark.parametrize("reply", [response(400), response(200, 6), response(401)])
def test_rejected_batches_fail(monkeypatch, reply):
    monkeypatch.setattr(hec_client.requests, "post", Mock(return_value=reply))
    assert not hec_client.send_events([EVENT], "http://splunk:8088", "token")


def test_connection_timeout_does_not_duplicate(monkeypatch):
    post = Mock(side_effect=requests.Timeout("timeout"))
    monkeypatch.setattr(hec_client.requests, "post", post)
    assert not hec_client.send_events([EVENT], "http://splunk:8088", "token")
    assert post.call_count == 1


def test_busy_hec_retry_is_bounded(monkeypatch):
    post = Mock(return_value=response(503, 9))
    monkeypatch.setattr(hec_client.requests, "post", post)
    monkeypatch.setattr(hec_client.time, "sleep", lambda _: None)
    assert not hec_client.send_events([EVENT], "http://splunk:8088", "token")
    assert post.call_count == 5


@pytest.mark.parametrize("batch", [0, -1])
def test_invalid_batch_is_rejected_without_network(monkeypatch, batch):
    post = Mock()
    monkeypatch.setattr(hec_client.requests, "post", post)
    assert not hec_client.send_events([EVENT], "http://splunk:8088", "token", batch)
    post.assert_not_called()


@pytest.mark.parametrize("content", [json.dumps([EVENT]), json.dumps(EVENT) + "\n" + json.dumps(EVENT)])
def test_load_array_and_jsonl(tmp_path, content):
    source = tmp_path / "events.json"
    source.write_text(content)
    assert all(item == EVENT for item in hec_client.load_events(str(source)))


@pytest.mark.parametrize("content", ['"not-an-object"', '[]', '[1, 2]', 'broken'])
def test_invalid_files(tmp_path, content):
    source = tmp_path / "events.json"
    source.write_text(content)
    with pytest.raises(ValueError):
        hec_client.load_events(str(source))


def load_generator():
    path = Path(__file__).resolve().parents[1] / "scripts/generate-sample-data.py"
    spec = importlib.util.spec_from_file_location("generator_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_returns_failure_when_hec_rejects(monkeypatch):
    generator = load_generator()
    monkeypatch.setattr("sys.argv", ["generator", "--events", "1", "--send-hec", "--hec-token", "token"])
    monkeypatch.setattr(hec_client.requests, "post", Mock(return_value=response(400)))
    assert generator.main() == 1


@pytest.mark.parametrize("scenario", ["brute-force", "privilege-escalation", "lateral-movement",
                                     "data-exfiltration", "malware"])
def test_cli_scenarios_fit_recent_search_window(monkeypatch, tmp_path, scenario):
    generator = load_generator()
    target = tmp_path / "nested/events.jsonl"
    monkeypatch.setattr("sys.argv", ["generator", "--scenario", scenario, "--events", "200",
                                    "--format", "jsonl", "--output", str(target)])
    assert generator.main() == 0
    events = hec_client.load_events(str(target))
    now = datetime.now(timezone.utc).timestamp()
    assert len(events) == 200
    assert all(0 <= now - hec_client.envelope(ev)["time"] < 310 for ev in events)
