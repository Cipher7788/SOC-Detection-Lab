# SOC Detection Lab

A local Splunk Enterprise lab with synthetic security events, five scheduled
detections, a security overview dashboard, and Python HEC/notification helpers.

## Start

Install Docker with Compose, then run:

```bash
bash scripts/setup.sh
```

Or copy `.env.example` to `.env`, choose credentials, and run
`docker compose up -d --build`. On PowerShell use `Copy-Item .env.example .env`.
Open http://localhost:8000, sign in as `admin` with the password in `.env`, and
select **SOC Detection Lab**. Initial startup can take several minutes.

The generator sends 200 events once and exits. Generate a specific scenario:

```bash
docker compose run --rm data-generator python3 /scripts/generate-sample-data.py \
  --scenario brute-force --events 50 --send-hec
```

Search `index=security earliest=-15m | stats count by event_type`.

## Included

- Brute force, privilege escalation, lateral movement, exfiltration and malware scenarios.
- Shared HEC client with epoch timestamps, bounded 503 retries and failure exit codes.
- Startup index definitions, native Docker HEC provisioning, JSON Lines monitors.
- Dashboard installed in Splunk's view directory, with severity field extraction.
- Tracked triggered alerts; configure email/webhook destinations before delivery.
- Unit/regression tests, Docker CI and a read-only live verifier.

The JSON rule catalog includes descriptive detection and response ideas; it is
not an automated attack, containment, or provider-specific response engine.

## Documentation

- [Quick start and verification](docs/QUICKSTART.md)
- [Configuration and development checks](docs/CONFIGURATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Scenarios](docs/SCENARIOS.md)
- [Troubleshooting and existing installations](docs/TROUBLESHOOTING.md)

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests -q
```

Run live checks against a started lab with
`python3 scripts/verify-lab.py --insecure`. Docker image defaults and HEC
provisioning follow the [official Splunk Docker documentation](https://splunk.github.io/docker-splunk/ADVANCED.html).
