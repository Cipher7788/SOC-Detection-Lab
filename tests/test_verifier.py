import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-lab.py"
spec = importlib.util.spec_from_file_location("verify_lab", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.mark.parametrize("count,expected", [(400, 1), (450, 0)])
def test_verifier_waits_for_full_ingestion(monkeypatch, tmp_path, count, expected):
    monkeypatch.setenv("SPLUNK_PASSWORD", "example")
    monkeypatch.setattr("sys.argv", ["verify-lab", "--min-events", "450", "--env-file", str(tmp_path / "missing")])
    response = Mock(text='{"result":{"count":"' + str(count) + '"}}\n')
    session = Mock()
    session.post.return_value = response
    monkeypatch.setattr(verifier.requests, "Session", Mock(return_value=session))
    monkeypatch.setattr(verifier.requests, "get", Mock())
    assert verifier.main() == expected


@pytest.mark.parametrize("severity", ["ERROR", "FATAL"])
def test_export_rejects_partial_results_with_errors(severity):
    response = Mock(text='{"result":{"count":"450"}}\n'
                    '{"messages":[{"type":"' + severity + '","text":"Search failed"}]}\n')
    with pytest.raises(ValueError, match="Search failed"):
        verifier.export_results(response)
