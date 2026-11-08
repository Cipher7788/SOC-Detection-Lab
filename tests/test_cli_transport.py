"""Exercise real CLI processes against a local HEC-compatible HTTP fixture."""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def hec_server():
    received = []
    reply = {"status": 200, "code": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.extend(json.loads(line) for line in
                            self.rfile.read(int(self.headers["Content-Length"])).decode().splitlines())
            assert self.headers["Authorization"] == "Splunk test-token"
            assert self.path == "/services/collector/event"
            self.send_response(reply["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"code": reply["code"]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received, reply
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def cli(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *args],
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, "PYTHONUTF8": "1"})


def test_generate_and_ingest_end_to_end(hec_server, tmp_path):
    url, received, _ = hec_server
    generated = cli("generate-sample-data.py", "--scenario", "brute-force", "--events", "10",
                    "--send-hec", "--hec-url", url, "--hec-token", "test-token")
    assert generated.returncode == 0, generated.stderr
    assert len(received) == 10
    assert all(isinstance(item["time"], (int, float)) for item in received)
    assert sum(item["event"].get("EventID") == 4625 for item in received) == 9
    source = tmp_path / "events.jsonl"
    source.write_text("\n".join(json.dumps(item["event"]) for item in received[:3]))
    ingested = cli("ingest-to-hec.py", "--file", str(source), "--batch", "2",
                   "--hec-url", url, "--hec-token", "test-token")
    assert ingested.returncode == 0, ingested.stderr
    assert len(received) == 13


def test_cli_reports_hec_failure(hec_server):
    url, _, reply = hec_server
    reply.update(status=200, code=6)
    result = cli("generate-sample-data.py", "--events", "2", "--send-hec",
                 "--hec-url", url, "--hec-token", "test-token")
    assert result.returncode == 1
    assert "HEC rejected" in result.stderr
