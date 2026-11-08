# Configuration

## Docker and credentials

Compose requires `SPLUNK_PASSWORD` and `SPLUNK_HEC_TOKEN` from `.env`.
`SPLUNK_IMAGE` optionally selects a specific image tag; the example uses latest.
Existing `.env` files are preserved by setup. Existing Splunk volumes may retain
the previous admin password; changing the environment does not reset it.

Make does not parse or source `.env`. The `ingest`, `ingest-all` and `notify`
targets use `scripts/run-with-env.py` to parse dotenv quotes and comments without
expanding `$name` or `${name}`, or executing shell expressions. Install
`requirements.txt` before using these host Python targets. Existing shell
environment variables take precedence over `.env`. Legacy Make arguments
`HEC_URL=...`, `HEC_TOKEN=...` and `W=...` take precedence over both; use shell
single quotes around arguments containing dollar signs. Credentials travel in
the child environment, rather than being inserted into the shell command.
Docker Compose continues to parse `.env` itself; single-quote literal dollar
signs in Compose credentials to prevent Compose's own interpolation.

The official Splunk image reads `splunk/defaults.yml` and provisions HEC using
`SPLUNK_HEC_TOKEN`. HEC uses HTTP on port 8088 inside this local lab; published
ports bind to localhost. Compose includes the license and general-terms startup
flags required by current images. Startup uses the image's trial license rather
than forcing Free mode, which does not support scheduled alerting.

## App layout and indexes

`splunk/apps/soc_lab` mounts directly at `/opt/splunk/etc/apps/soc_lab`.
`default/indexes.conf` creates `security`, `network` and `alerts` at startup.
Views belong in `default/data/ui/views`; navigation is in `default/data/ui/nav`.
Lookups mount inside the app's existing `lookups` directory. These app mounts are
writable so the official image can manage ownership and Splunk can save UI edits
under `local/`. Runtime local overrides are ignored by Git. Edit tracked defaults
on the host and restart Splunk to apply changes; local overrides take precedence.

## Event ingestion

The default generator sends events once via HEC, with sourcetype `soc_lab_json`,
index `security`, event host metadata, and numeric epoch timestamps. Connection
and HEC errors return a nonzero exit code. HTTP 503 responses have bounded retries.
Requests that time out are not retried automatically, to avoid duplicate ingestion.

For host Python workflows:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/generate-sample-data.py --scenario malware --events 50 \
  --output data-sources/logs/malware.json
# Set SPLUNK_HEC_TOKEN in your shell, or supply --hec-token.
python3 scripts/ingest-to-hec.py --file data-sources/logs/malware.json
```

The ingestion helper accepts JSON arrays and JSON Lines. To use file monitoring
instead of HEC, generate `--format jsonl --output data-sources/logs/events.jsonl`.
Only `.jsonl` files are monitored under `logs`, so array files do not get split
into invalid events or ingest twice. Windows and network CSV monitors are optional.
Generated network events remain in `security`; the exfiltration search includes
both `security` and `network`. CSV network events need the same fields, including
`event_type=network_connection`, `src_ip`, `dest_ip`, and `bytes_out`.

Port 9997 accepts Splunk forwarder traffic; UDP syslog is exposed on localhost:5514.
The generator only creates synthetic events; no attack tools execute.

## Alerts and notifications

Five scheduled searches are enabled, owned by admin and tracked as triggered
alerts when they return results. Email and webhook actions have no placeholder
destinations. Configure destinations and SMTP in Splunk before enabling those
actions. The `alerts` index is reserved; searches do not automatically write to it.

`scripts/notify-webhook.py` is a separate command-line helper, not an installed
Splunk custom alert action. It supports Slack, Teams MessageCard and generic JSON
payloads. Generic JSON is not a provider-specific PagerDuty/Discord API adapter.
Pass `--webhook-url` or set `ALERT_WEBHOOK_URL`; use `--dry-run` to preview.

## Development checks

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests -q
python3 -m flake8 scripts --max-line-length=120 --extend-ignore=E203,W503
python3 -m bandit -r scripts --severity-level medium --confidence-level medium
bash -n scripts/setup.sh
docker compose config --quiet
```

CI enforces tests and the medium/high security scan, validates Compose, builds the
generator, and runs a live Splunk integration check. Tests mock external services;
`verify-lab.py` supplies the separate live check.
