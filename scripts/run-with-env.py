#!/usr/bin/env python3
"""Run a helper with literal dotenv values, without Make or shell evaluation."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from dotenv import dotenv_values


def command_environment(path: Path, inherited: dict) -> dict:
    # Disabling interpolation preserves both $name and ${name} in credentials.
    values = dotenv_values(path, encoding="utf-8-sig", interpolate=False) if path.exists() else {}
    environment = {key: value for key, value in values.items() if value is not None}
    environment.update(inherited)
    for alias, target in [("SOC_LAB_HEC_URL", "SPLUNK_HEC_URL"),
                          ("SOC_LAB_HEC_TOKEN", "SPLUNK_HEC_TOKEN"),
                          ("SOC_LAB_WEBHOOK_URL", "ALERT_WEBHOOK_URL")]:
        if inherited.get(alias):
            environment[target] = inherited[alias]
    return environment


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: run-with-env.py COMMAND [ARG ...]", file=sys.stderr)
        return 2
    try:
        environment = command_environment(Path(".env"), os.environ)
        return subprocess.run(sys.argv[1:], env=environment, check=False).returncode
    except OSError as exc:
        print(f"[!] Could not run command: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
