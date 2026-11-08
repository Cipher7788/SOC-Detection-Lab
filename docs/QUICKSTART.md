# Quick start

Install Docker Engine/Desktop with Compose. Allow at least 4 GB RAM for Splunk
and keep ports 8000, 8088, 8089, 9997 and 5514 available on localhost.

## Start

On Linux, macOS or Git Bash:

```bash
bash scripts/setup.sh
```

The script creates random credentials in `.env`, builds the generator, starts
Splunk, and checks the generator's exit status. Docker is the only prerequisite.

On PowerShell, or to configure credentials yourself:

```powershell
Copy-Item .env.example .env
# Edit .env to choose your password and UUID HEC token.
docker compose up -d --build
docker compose logs -f data-generator
```

The one-shot generator exits with status 0 after sending 200 events. Splunk can
take several minutes to initialize. Open http://localhost:8000 and sign in as
`admin` using `SPLUNK_PASSWORD` from `.env`. Select the **SOC Detection Lab** app.
The official Docker image provisions the same HEC token automatically.

```spl
index=security earliest=-15m | stats count by event_type
```

## Verify

With Python 3.11+ installed:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/verify-lab.py --insecure
```

`--insecure` is needed only for the local management API's self-signed certificate.
The verifier checks HEC health, the app, indexes, dashboard and recent data.
If indexing is still catching up, rerun it after a few seconds.

## Generate more data

```bash
docker compose run --rm data-generator python3 /scripts/generate-sample-data.py \
  --scenario brute-force --events 50 --send-hec
```

Replace `brute-force` with `privilege-escalation`, `lateral-movement`,
`data-exfiltration` or `malware`. Events are placed in the most recent five
minutes so the scheduled detections can see them immediately.

## Stop

```bash
docker compose down
```

Named volumes preserve indexed data and Splunk state. `docker compose down -v`
deletes that data and should be used only when you intend to reset the lab.
