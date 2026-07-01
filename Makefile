# =============================================================================
# SOC Detection Lab – Makefile
# Convenience targets for common lab operations
# =============================================================================

PYTHON     := python3
PIP        := pip3
COMPOSE    := $(shell command -v docker-compose 2>/dev/null || echo "docker compose")
HEC_URL    ?= http://localhost:8088
HEC_TOKEN  ?= $(SPLUNK_HEC_TOKEN)

.PHONY: help setup up down logs test lint security clean generate ingest notify

# ── Default: show help ───────────────────────────────────────────────────────
help:
	@echo ""
	@echo "SOC Detection Lab – Available Commands"
	@echo "────────────────────────────────────────────────────────"
	@echo "  make setup       Run full lab initialisation (setup.sh)"
	@echo "  make up          Start Docker Compose stack"
	@echo "  make down        Stop Docker Compose stack"
	@echo "  make logs        Tail Splunk container logs"
	@echo ""
	@echo "  make test        Run all 118 unit tests"
	@echo "  make lint        Run flake8 + bash syntax checks"
	@echo "  make security    Run Bandit security scan"
	@echo ""
	@echo "  make generate    Generate 200 mixed events → data-sources/logs/"
	@echo "  make ingest      Ingest generated events into Splunk HEC"
	@echo "  make scenario S=brute-force    Generate specific scenario"
	@echo ""
	@echo "  make notify P=slack W=<url> A='Alert Name' SEV=high"
	@echo "  make clean       Remove generated data files"
	@echo ""

# ── Lab lifecycle ────────────────────────────────────────────────────────────
setup:
	@echo "[*] Running lab setup..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh

up:
	@echo "[*] Starting stack..."
	$(COMPOSE) up -d
	@echo "[+] Splunk UI: http://localhost:8000"

down:
	@echo "[*] Stopping stack..."
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f splunk

restart:
	$(COMPOSE) restart splunk

# ── Testing ──────────────────────────────────────────────────────────────────
test:
	@echo "[*] Running unit tests..."
	$(PYTHON) -m pytest tests/ -v --tb=short

test-cov:
	$(PYTHON) -m pytest tests/ -v --cov=scripts --cov-report=term-missing --cov-report=html
	@echo "[+] HTML coverage report: htmlcov/index.html"

# ── Lint & security ──────────────────────────────────────────────────────────
lint:
	@echo "[*] Checking Python style..."
	flake8 scripts/ --max-line-length=120 --extend-ignore=E203,W503 --statistics
	@echo "[*] Checking shell syntax..."
	bash -n scripts/setup.sh && echo "  OK: scripts/setup.sh"
	bash -n splunk/init/setup.sh && echo "  OK: splunk/init/setup.sh"
	@echo "[*] Validating JSON rules..."
	@for f in detection-rules/*.json; do \
		$(PYTHON) -c "import json; json.load(open('$$f')); print('  OK:', '$$f')"; \
	done
	@echo "[✓] All lint checks passed"

security:
	@echo "[*] Running security scan..."
	bandit -r scripts/ --severity-level medium --confidence-level medium --format txt || true

# ── Data generation ──────────────────────────────────────────────────────────
generate:
	@echo "[*] Generating 200 mixed events..."
	$(PYTHON) scripts/generate-sample-data.py \
		--events 200 \
		--output data-sources/logs/generated-events.json
	@echo "[+] Written to data-sources/logs/generated-events.json"

scenario:
	@echo "[*] Generating scenario: $(S)"
	$(PYTHON) scripts/generate-sample-data.py \
		--scenario $(S) \
		--events 50 \
		--output data-sources/logs/$(S)-events.json

ingest:
	@echo "[*] Ingesting events into Splunk HEC..."
	$(PYTHON) scripts/ingest-to-hec.py \
		--file data-sources/logs/generated-events.json \
		--hec-url $(HEC_URL) \
		--hec-token $(HEC_TOKEN)

ingest-all:
	@echo "[*] Generating and ingesting all 5 scenarios..."
	@for s in brute-force privilege-escalation lateral-movement data-exfiltration malware; do \
		$(PYTHON) scripts/generate-sample-data.py \
			--scenario $$s --events 50 \
			--send-hec --hec-url $(HEC_URL) --hec-token $(HEC_TOKEN); \
	done

# ── Notifications ─────────────────────────────────────────────────────────────
# Usage: make notify P=slack W=https://... A="Brute Force" SEV=high
notify:
	$(PYTHON) scripts/notify-webhook.py \
		--provider $(P) \
		--webhook-url $(W) \
		--alert-name "$(A)" \
		--severity $(SEV)

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	@echo "[*] Removing generated data..."
	rm -f data-sources/logs/*.json
	rm -f data-sources/network/*.csv
	rm -f data-sources/windows/*.csv
	rm -f output/*
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "[+] Clean done"
