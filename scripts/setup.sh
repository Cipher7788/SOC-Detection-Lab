#!/usr/bin/env bash
# Configure credentials and start the lab with Compose V2 or legacy Compose.
set -euo pipefail
LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_ROOT"
command -v docker >/dev/null || { echo "Install Docker Desktop or Docker Engine." >&2; exit 1; }
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "Install Docker Compose." >&2
    exit 1
fi
docker info >/dev/null 2>&1 || { echo "Start the Docker daemon." >&2; exit 1; }
if [[ ! -f .env ]]; then
    umask 077
    docker run --rm python:3.11-slim python3 -c \
        'import secrets, uuid; print("SPLUNK_PASSWORD=SocLab@" + secrets.token_hex(12)); print("SPLUNK_HEC_TOKEN=" + str(uuid.uuid4()))' \
        > .env.tmp
    mv .env.tmp .env
    echo "Created .env with random local lab credentials."
fi
mkdir -p data-sources/{logs,windows,network}
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" up -d --build
for ((i=0; i<120; i++)); do
    generator_id="$("${COMPOSE[@]}" ps -a -q data-generator)"
    if [[ -n "$generator_id" ]]; then
        state="$(docker inspect --format '{{.State.Status}}' "$generator_id")"
        if [[ "$state" == exited ]]; then
            code="$(docker inspect --format '{{.State.ExitCode}}' "$generator_id")"
            if [[ "$code" != 0 ]]; then
                "${COMPOSE[@]}" logs data-generator >&2
                exit 1
            fi
            echo "Lab ready: http://localhost:8000 (admin; password: SPLUNK_PASSWORD in .env)"
            echo "Open the SOC Detection Lab app. Run scripts/verify-lab.py for live checks."
            exit 0
        fi
    fi
    sleep 5
done
echo "Timed out waiting for ingestion. Inspect: ${COMPOSE[*]} logs" >&2
exit 1
