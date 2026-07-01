#!/bin/bash
# =============================================================================
# Splunk Init Script
# Runs inside the Splunk container on first boot to configure indexes,
# create the HEC token, and copy lookup files.
# =============================================================================

set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"
ADMIN_PASS="${SPLUNK_PASSWORD:-SocLab@2026}"

echo "[init] Waiting for Splunkd to be ready..."
until "$SPLUNK_BIN" status 2>/dev/null | grep -q "splunkd is running"; do
    sleep 3
done
echo "[init] Splunkd is ready."

# ── Create custom indexes ────────────────────────────────────────────────────
echo "[init] Creating indexes..."
"$SPLUNK_BIN" add index security   -auth "admin:$ADMIN_PASS" 2>/dev/null || true
"$SPLUNK_BIN" add index network    -auth "admin:$ADMIN_PASS" 2>/dev/null || true
"$SPLUNK_BIN" add index alerts     -auth "admin:$ADMIN_PASS" 2>/dev/null || true

# ── Create HEC token ─────────────────────────────────────────────────────────
echo "[init] Creating HEC token..."
"$SPLUNK_BIN" http-event-collector create soc_lab_token \
    -uri https://localhost:8089 \
    -auth "admin:$ADMIN_PASS" \
    -index security \
    -sourcetype json 2>/dev/null || true

echo "[init] Setup complete."
