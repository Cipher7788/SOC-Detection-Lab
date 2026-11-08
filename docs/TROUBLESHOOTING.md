# Troubleshooting

## Startup or build fails

Run `docker info`, `docker compose config --quiet`, and `docker compose logs splunk`.
Copy `.env.example` to `.env` if credentials are missing. The setup script supports
Compose V2 and the legacy executable; Windows users can run the direct Compose
commands from the quick start. Ensure Docker has sufficient memory and disk.

The generator image needs only scripts and requirements; sample directories are
tracked and contain `.gitkeep` files. Shell files use LF endings via `.gitattributes`.

## No events or generator exited nonzero

Inspect `docker compose logs data-generator`. A 401/403 means the token differs
from the token configured in Splunk. A 400 may indicate an invalid event or index.
The shared HEC client uses epoch seconds and propagates HEC response codes.
Use `python3 scripts/verify-lab.py --insecure` to check the running services.
Allow a few seconds for indexing after the generator exits.

Run another scenario with `docker compose run --rm data-generator python3
/scripts/generate-sample-data.py --scenario malware --events 50 --send-hec`
(put that command on one line). Search `index=security earliest=-15m`.
The default container ingests once; it is not a continuous event stream.

## Empty detections or dashboard

Select the SOC Detection Lab app and widen the search time range for old data.
Generate a specific scenario to ensure relevant events exist. Brute-force
aggregation groups by `src_ip,user`; login events do not contain `dest_ip`.
Network JSON events are in `security`, and exfiltration searches both indexes.
Privilege events use lowercase `privilege`. Severity is derived at search time.

Views must be installed at `default/data/ui/views`. Restart Splunk after editing
app configuration. CSV inputs must have field names matching the saved SPL.
Free licenses and expired trials do not support scheduled alerting; check the
license if manual searches work but scheduled alerts do not.

## Existing installation

Stop the old stack before starting this version. Existing named volumes and any
`local/*.conf` overrides can supersede the corrected defaults. Inspect effective
configuration with `docker compose exec splunk /opt/splunk/bin/splunk btool
inputs list --debug` (one line), and similarly inspect indexes and props.
Remove obsolete overrides only after reviewing them. Existing admin passwords
are retained in volumes. Back up needed data before intentionally resetting
volumes with `docker compose down -v`.

## Notifications

Fresh installs record triggered alerts without external delivery. Set up SMTP
and real destinations before enabling email/webhook actions. The command-line
notification helper is separate from Splunk's native webhook action; Slack and
Teams payload formats differ from the native Splunk webhook body.
