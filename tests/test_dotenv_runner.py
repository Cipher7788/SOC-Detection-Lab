import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-with-env.py"
spec = importlib.util.spec_from_file_location("dotenv_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.parametrize("quote", ["'", '"'])
def test_quoted_credentials_are_literal(tmp_path, quote):
    path = tmp_path / ".env"
    secret = "literal$dollar${VALUE}#hash&tail$(touch injected)"
    path.write_text(f"SPLUNK_HEC_TOKEN={quote}{secret}{quote} # comment\n", encoding="utf-8-sig")
    assert runner.command_environment(path, {})["SPLUNK_HEC_TOKEN"] == secret
    assert not (tmp_path / "injected").exists()


def test_environment_and_alias_precedence(tmp_path):
    path = tmp_path / ".env"
    path.write_text("SPLUNK_HEC_TOKEN='file-token'\nEMPTY=\nBARE\n")
    inherited = {"SPLUNK_HEC_TOKEN": "shell$token", "SOC_LAB_HEC_TOKEN": ""}
    values = runner.command_environment(path, inherited)
    assert values["SPLUNK_HEC_TOKEN"] == "shell$token"
    assert values["EMPTY"] == ""
    assert "BARE" not in values
    inherited["SOC_LAB_HEC_TOKEN"] = "override${literal}"
    assert runner.command_environment(path, inherited)["SPLUNK_HEC_TOKEN"] == "override${literal}"


def test_runner_preserves_values_and_child_exit_status(tmp_path):
    token = "quoted$dollar${HOME}#hash&tail"
    (tmp_path / ".env").write_text(f"SPLUNK_HEC_TOKEN='{token}'\n")
    env = {k: v for k, v in os.environ.items() if k not in {"SPLUNK_HEC_TOKEN", "SOC_LAB_HEC_TOKEN"}}
    result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, "-c",
                             "import os,json,sys; print(json.dumps(os.environ['SPLUNK_HEC_TOKEN'])); sys.exit(7)"],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 7
    assert json.loads(result.stdout) == token
