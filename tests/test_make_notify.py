import os
from pathlib import Path
import shutil
import subprocess

import pytest

MAKE = shutil.which("make")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(MAKE is None, reason="GNU Make is required (covered by Linux CI)")
@pytest.mark.parametrize("explicit", [True, False])
def test_make_notify_preserves_webhook_query(tmp_path, explicit):
    # Override the Python command with a harmless argument recorder. No message is sent.
    recorder = tmp_path / "record.sh"
    recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    url = "https://example.invalid/webhook?key=one&signature=two"
    args = [MAKE, "--no-print-directory", "-f", str(ROOT / "Makefile"), "notify",
            "PYTHON=sh " + str(recorder), "P=generic", "A=Example", "SEV=high"]
    if explicit:
        args.append("W=" + url)
    result = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, "ALERT_WEBHOOK_URL": url}, timeout=10)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    index = lines.index("--webhook-url")
    assert lines[index + 1] == url
