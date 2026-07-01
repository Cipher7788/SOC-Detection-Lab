#!/bin/bash
# =============================================================================
# SOC Detection Lab - Setup Script
# Initialises the lab environment: checks prerequisites, creates directories,
# and starts the Splunk stack via Docker Compose.
# =============================================================================

set -euo pipefail

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# ─── Helpers ─────────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        SOC Detection Lab - Setup             ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(dirname "$SCRIPT_DIR")"

info "Lab root: $LAB_ROOT"
info "Started : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# ─── 1. Prerequisite checks ──────────────────────────────────────────────────
info "Checking prerequisites..."

check_command() {
    local cmd="$1"
    local install_hint="${2:-}"
    if command -v "$cmd" &>/dev/null; then
        success "$cmd found ($(command -v "$cmd"))"
    else
        error "$cmd is not installed."
        [ -n "$install_hint" ] && echo "  Install: $install_hint"
        die "Missing prerequisite: $cmd"
    fi
}

check_command docker   "https://docs.docker.com/get-docker/"
check_command docker-compose "https://docs.docker.com/compose/install/" 2>/dev/null || \
    check_command "docker compose" "Docker Compose V2 (bundled with Docker Desktop)"
check_command python3  "sudo apt install python3 / brew install python"
check_command curl     "sudo apt install curl / brew install curl"
check_command git      "sudo apt install git / brew install git"

echo ""

# ─── 2. Docker daemon check ──────────────────────────────────────────────────
info "Checking Docker daemon..."
if ! docker info &>/dev/null; then
    die "Docker daemon is not running. Please start Docker and try again."
fi
success "Docker daemon is running"
echo ""

# ─── 3. System resources check ───────────────────────────────────────────────
info "Checking system resources..."

# RAM check (need ≥ 4 GB)
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1024}' || echo 0)
TOTAL_MEM_GB=$(( TOTAL_MEM_KB / 1024 / 1024 ))
if [ "$TOTAL_MEM_GB" -ge 4 ]; then
    success "RAM: ${TOTAL_MEM_GB} GB (minimum 4 GB met)"
else
    warn "RAM: ${TOTAL_MEM_GB} GB detected — Splunk recommends at least 4 GB"
fi

# Disk check (need ≥ 10 GB free)
FREE_DISK_GB=$(df -BG "$LAB_ROOT" | awk 'NR==2{gsub("G",""); print $4}')
if [ "${FREE_DISK_GB:-0}" -ge 10 ]; then
    success "Disk: ${FREE_DISK_GB} GB free (minimum 10 GB met)"
else
    warn "Disk: ${FREE_DISK_GB:-unknown} GB free — recommend at least 10 GB"
fi
echo ""

# ─── 4. Directory structure ──────────────────────────────────────────────────
info "Creating required directories..."

dirs=(
    "$LAB_ROOT/data-sources/logs"
    "$LAB_ROOT/data-sources/network"
    "$LAB_ROOT/data-sources/windows"
    "$LAB_ROOT/splunk/apps"
    "$LAB_ROOT/splunk/init"
    "$LAB_ROOT/splunk/lookups"
    "$LAB_ROOT/output"
)

for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
    success "Created: $dir"
done
echo ""

# ─── 5. Python dependencies ──────────────────────────────────────────────────
info "Installing Python dependencies for data generator..."
if python3 -c "import faker, requests" &>/dev/null 2>&1; then
    success "Python dependencies already installed"
else
    python3 -m pip install --quiet faker requests 2>/dev/null || \
        warn "pip install failed — run 'pip3 install faker requests' manually"
    success "Python dependencies installed"
fi
echo ""

# ─── 6. Generate initial sample data ─────────────────────────────────────────
info "Generating initial sample security events..."
SAMPLE_FILE="$LAB_ROOT/data-sources/logs/initial-events.json"

if python3 "$SCRIPT_DIR/generate-sample-data.py" \
        --events 200 \
        --output "$SAMPLE_FILE" 2>/dev/null; then
    success "Sample data written to $SAMPLE_FILE"
else
    warn "Sample data generation skipped (optional)"
fi
echo ""

# ─── 7. Start Docker Compose stack ──────────────────────────────────────────
info "Starting SOC Detection Lab stack..."
cd "$LAB_ROOT"

COMPOSE_CMD="docker-compose"
command -v docker-compose &>/dev/null || COMPOSE_CMD="docker compose"

"$COMPOSE_CMD" up -d

echo ""
success "Docker stack started"
echo ""

# ─── 8. Wait for Splunk to be ready ─────────────────────────────────────────
info "Waiting for Splunk to become healthy (up to 120 s)..."

SPLUNK_URL="http://localhost:8000"
MAX_WAIT=120
WAITED=0

until curl -sf "$SPLUNK_URL" -o /dev/null 2>/dev/null || [ "$WAITED" -ge "$MAX_WAIT" ]; do
    printf "."
    sleep 5
    WAITED=$(( WAITED + 5 ))
done
echo ""

if curl -sf "$SPLUNK_URL" -o /dev/null 2>/dev/null; then
    success "Splunk is ready at $SPLUNK_URL"
else
    warn "Splunk did not become ready within ${MAX_WAIT}s — it may still be starting."
    warn "Check status with: docker-compose logs splunk"
fi
echo ""

# ─── 9. Summary ──────────────────────────────────────────────────────────────
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Setup Complete! 🎉                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Splunk Web UI : http://localhost:8000"
echo "  Username      : admin"
echo "  Password      : SocLab@2026"
echo ""
echo "  Next steps:"
echo "    1. Open http://localhost:8000 in your browser"
echo "    2. Log in with admin / SocLab@2026"
echo "    3. Generate more test data:"
echo "       python3 scripts/generate-sample-data.py --scenario brute-force"
echo "    4. Read the docs: docs/QUICKSTART.md"
echo ""
