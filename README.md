# 🛡️ SOC Detection Lab

A comprehensive Security Operations Center (SOC) detection lab built with Splunk Enterprise, featuring pre-configured threat detection rules, attack simulation scenarios, and automation scripts for hands-on security training.

> ⚠️ **For educational and research purposes only.** Do not expose this lab to the public internet. Change default credentials before use.

---

## ✨ Features

- **Enterprise SIEM** – Splunk Enterprise deployed via Docker Compose
- **5 Detection Rules** – Brute force, privilege escalation, lateral movement, data exfiltration, and malware detection
- **5 Attack Scenarios** – Realistic incident response practice exercises
- **Automation Scripts** – One-command lab setup and realistic data generation
- **HEC Ingestion** – Push generated events directly to Splunk
- **Dashboards** – Pre-built Splunk security overview dashboard
- **Lookup Tables** – Known-bad IPs, domains, and internal IP enrichment
- **Comprehensive Docs** – Architecture, configuration, quick-start, and scenario guides

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose installed
- 8 GB RAM (16 GB recommended)
- 20 GB free disk space
- Python 3.8+

### Deploy in 3 Steps

```bash
# 1. Clone the repository
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git
cd SOC-Detection-Lab

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env — at minimum change SPLUNK_PASSWORD

# 3. Run the setup script
chmod +x scripts/setup.sh
./scripts/setup.sh
```

**Access Splunk:** http://localhost:8000
**Default Credentials:** `admin` / `SocLab@2026`  ← **change this in `.env`**

---

## 📁 Directory Structure

```
SOC-Detection-Lab/
├── .env.example                  # ← Copy to .env and configure
├── docker-compose.yml            # Splunk + data-generator stack
├── data-generator.dockerfile     # Data generator container build
│
├── detection-rules/              # Threat detection rule definitions (JSON)
│   ├── brute-force-detection.json
│   ├── privilege-escalation.json
│   ├── lateral-movement.json
│   ├── data-exfiltration.json
│   └── malware-detection.json
│
├── scripts/                      # Automation scripts
│   ├── setup.sh                  # Lab initialisation script
│   ├── generate-sample-data.py   # Realistic event data generator
│   └── ingest-to-hec.py          # Push events to Splunk HEC
│
├── splunk/
│   ├── apps/soc_lab/default/     # Splunk app configuration
│   │   ├── inputs.conf           # Data inputs (HEC, syslog, TCP, files)
│   │   ├── props.conf            # Field extractions & timestamp parsing
│   │   ├── transforms.conf       # Routing & enrichment
│   │   ├── savedsearches.conf    # Scheduled alert definitions
│   │   └── eventtypes.conf       # Event categorisation
│   ├── apps/soc_lab/dashboards/
│   │   └── security-overview.xml # Pre-built security dashboard
│   ├── apps/soc_lab/metadata/
│   │   └── default.meta          # App permissions
│   ├── lookups/                  # Enrichment lookup tables
│   │   ├── internal_ips.csv
│   │   ├── known_bad_ips.csv
│   │   └── known_bad_domains.csv
│   └── init/
│       └── setup.sh              # Container init (indexes + HEC token)
│
├── data-sources/                 # Generated/ingested data (git-ignored)
│   ├── logs/
│   ├── network/
│   └── windows/
│
└── docs/                         # Extended documentation
    ├── QUICKSTART.md
    ├── ARCHITECTURE.md
    ├── CONFIGURATION.md
    ├── SCENARIOS.md
    └── TROUBLESHOOTING.md
```

---

## 🔍 Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `brute-force-detection.json` | ≥5 failed logins from the same IP in 10 min | High |
| `privilege-escalation.json` | Sensitive Windows privilege usage (SeDebugPrivilege, etc.) | Critical |
| `lateral-movement.json` | Suspicious lateral-movement tools (psexec, wmic, etc.) | High |
| `data-exfiltration.json` | Anomalous outbound traffic volume & sensitive file access | Critical |
| `malware-detection.json` | Known malware process names, registry keys, and C2 patterns | Critical |

---

## 📖 Usage Examples

### Generate Sample Security Events

```bash
# Generate 500 mixed events to a file
python3 scripts/generate-sample-data.py --events 500

# Generate a specific attack scenario
python3 scripts/generate-sample-data.py --scenario brute-force --events 100
python3 scripts/generate-sample-data.py --scenario lateral-movement --events 50
python3 scripts/generate-sample-data.py --scenario malware --events 30

# Send events directly to Splunk HEC
python3 scripts/generate-sample-data.py --events 200 --send-hec \
    --hec-url http://localhost:8088 --hec-token YOUR_HEC_TOKEN
```

### Ingest an Existing Events File into Splunk

```bash
python3 scripts/ingest-to-hec.py \
    --file data-sources/logs/initial-events.json \
    --hec-token YOUR_HEC_TOKEN
```

### Search for Threats in Splunk

```spl
-- Brute force attempts
index=security EventID=4625 | stats count by src_ip | where count > 5

-- Privilege escalation
index=security EventID=4672 | table _time, user, Privilege

-- Lateral movement
index=security EventID=4688 process_name IN ("psexec.exe","wmic.exe","powershell.exe")

-- Data exfiltration
index=network dest_ip!=10.0.0.0/8 dest_ip!=192.168.0.0/16
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 104857600

-- Malware
index=security EventID=4688 process_name IN ("mimikatz.exe","meterpreter.exe","cobalt_strike.exe")
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | 5-minute setup guide |
| [Architecture](docs/ARCHITECTURE.md) | System design & component overview |
| [Configuration](docs/CONFIGURATION.md) | Detailed configuration reference |
| [Scenarios](docs/SCENARIOS.md) | Attack simulation walkthroughs |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues & fixes |

---

## 🎓 Learning Objectives

- SIEM fundamentals with Splunk
- Threat detection rule creation and tuning
- Incident investigation techniques
- Attack pattern recognition (MITRE ATT&CK)
- Log correlation and timeline analysis
- Incident response procedures

---

## 🔐 Security Notes

- **Never commit `.env`** — it contains credentials. Only `.env.example` is committed.
- Change `SPLUNK_PASSWORD` before first boot.
- This lab binds to `localhost` only by default — do not expose Docker ports publicly.
- `SPLUNK_HEC_TOKEN` must be replaced with a real token generated from the Splunk UI after first boot.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is intended for educational and research purposes only.
