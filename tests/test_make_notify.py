import os
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

MAKE = shutil.which("make")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(MAKE is None, reason="GNU Make is required (covered by Linux CI)")
@pytest.mark.parametrize("explicit", [True, False])
def test_make_notify_preserves_webhook_query(tmp_path, explicit):
    prepare(tmp_path)
    url = "https://example.invalid/webhook?key=$one&signature=${two}"
    args = [MAKE, "--no-print-directory", "notify",
            "PYTHON=" + sys.executable, "P=generic", "A=Example", "SEV=high"]
    if explicit:
        args.append("W=" + url)
    result = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, "ALERT_WEBHOOK_URL": url}, timeout=10)
    assert result.returncode == 0, result.stderr
    assert recorded(result)["ALERT_WEBHOOK_URL"] == url


def prepare(path):
    (path / "scripts").mkdir()
    shutil.copy(ROOT / "Makefile", path / "Makefile")
    shutil.copy(ROOT / "scripts/run-with-env.py", path / "scripts/run-with-env.py")
    # Fake helpers only record their environment. No network or notifications.
    recorder = ('import json, os\nprint("RECORDED:" + json.dumps(dict(os.environ)))\n')
    for name in ["notify-webhook.py", "ingest-to-hec.py", "generate-sample-data.py"]:
        (path / "scripts" / name).write_text(recorder)


def recorded(result):
    return json.loads(next(line.removeprefix("RECORDED:") for line in result.stdout.splitlines()
                           if line.startswith("RECORDED:")))


@pytest.mark.skipif(MAKE is None, reason="GNU Make is required (covered by Linux CI)")
@pytest.mark.parametrize("target", ["ingest", "ingest-all", "notify"])
def test_make_loads_quoted_dotenv_without_evaluation(tmp_path, target):
    prepare(tmp_path)
    token = 'token$literal${KEEP}#hash&tail$(touch injected)'
    password = 'password$literal${KEEP}#hash'
    url = 'https://example.invalid/?token=$literal&key=${KEEP}'
    (tmp_path / ".env").write_text(f"SPLUNK_HEC_TOKEN='{token}'\nSPLUNK_PASSWORD=\"{password}\"\n"
                                 f"ALERT_WEBHOOK_URL='{url}'\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if k not in {"SPLUNK_HEC_TOKEN", "SPLUNK_PASSWORD", "ALERT_WEBHOOK_URL"}}
    result = subprocess.run([MAKE, "--no-print-directory", target, "PYTHON=" + sys.executable,
                             "P=generic", "A=Example", "SEV=high"],
                            cwd=tmp_path, capture_output=True, text=True, env=env, timeout=15)
    assert result.returncode == 0, result.stderr
    values = recorded(result)
    assert values["SPLUNK_HEC_TOKEN"] == token
    assert values["SPLUNK_PASSWORD"] == password
    assert values["ALERT_WEBHOOK_URL"] == url
    assert not (tmp_path / "injected").exists()
    command_output = "\n".join(line for line in result.stdout.splitlines() if not line.startswith("RECORDED:"))
    assert token not in command_output


@pytest.mark.skipif(MAKE is None, reason="GNU Make is required (covered by Linux CI)")
def test_make_token_override_preserves_dollars(tmp_path):
    prepare(tmp_path)
    (tmp_path / ".env").write_text("SPLUNK_HEC_TOKEN='from-file'\n")
    token = 'override$literal${KEEP}#hash&tail$(touch injected)'
    result = subprocess.run([MAKE, "--no-print-directory", "ingest", "PYTHON=" + sys.executable,
                             "HEC_TOKEN=" + token], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, "SPLUNK_HEC_TOKEN": "from-shell"}, timeout=10)
    assert result.returncode == 0, result.stderr
    assert recorded(result)["SPLUNK_HEC_TOKEN"] == token
    assert not (tmp_path / "injected").exists()
