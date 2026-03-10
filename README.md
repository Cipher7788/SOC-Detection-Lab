# 🛡️ SOC Detection Lab

A comprehensive Security Operations Center (SOC) detection lab built with Splunk Enterprise, featuring pre-configured threat detection rules, attack simulation scenarios, and automation scripts for hands-on security training.

## ✨ Features

- **Enterprise SIEM** – Splunk Enterprise deployed via Docker Compose
- **5 Detection Rules** – Brute force, privilege escalation, lateral movement, data exfiltration, and malware detection
- **5 Attack Scenarios** – Realistic incident response practice exercises
- **Automation Scripts** – One-command lab setup and realistic data generation
- **Comprehensive Docs** – Architecture, configuration, quick-start, and scenario guides

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose installed
- 8 GB RAM (16 GB recommended)
- 20 GB free disk space

### Deploy in 3 Steps

```bash
# 1. Clone the repository
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git
cd SOC-Detection-Lab

# 2. Run the setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# 3. Launch the lab
docker-compose up -d
```

**Access Splunk:** http://localhost:8000  
**Credentials:** `admin` / `SocLab@2026`

## 📁 Directory Structure

```
SOC-Detection-Lab/
├── detection-rules/              # Threat detection rule definitions
│   ├── brute-force-detection.json
│   ├── privilege-escalation.json
│   ├── lateral-movement.json
│   ├── data-exfiltration.json
│   └── malware-detection.json
├── scripts/                      # Automation scripts
│   ├── setup.sh                  # Lab initialisation script
│   └── generate-sample-data.py  # Realistic event data generator
├── docs/                         # Extended documentation
│   ├── QUICKSTART.md
│   ├── ARCHITECTURE.md
│   ├── CONFIGURATION.md
│   └── SCENARIOS.md
└── docker-compose.yml            # Splunk stack definition
```

## 🔍 Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `brute-force-detection.json` | ≥5 failed logins from the same IP in 10 min | High |
| `privilege-escalation.json` | Sensitive Windows privilege usage (SeDebugPrivilege, etc.) | Critical |
| `lateral-movement.json` | Suspicious lateral-movement tools (psexec, wmic, etc.) | High |
| `data-exfiltration.json` | Anomalous outbound traffic volume & sensitive file access | Critical |
| `malware-detection.json` | Known malware process names, registry keys, and C2 patterns | Critical |

## 📖 Usage Examples

### Generate Sample Security Events

```bash
# Generate 500 mixed events
python3 scripts/generate-sample-data.py --events 500

# Generate a specific attack scenario
python3 scripts/generate-sample-data.py --scenario brute-force --events 100
python3 scripts/generate-sample-data.py --scenario lateral-movement --events 50
```

### Search for Threats in Splunk

```spl
# Brute force attempts
index=security EventID=4625 | stats count by src_ip | where count > 5

# Privilege escalation
index=security EventID=4672 | table _time, user, Privilege

# Lateral movement
index=security process_name IN ("psexec.exe","wmic.exe","powershell.exe")
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | 5-minute setup guide |
| [Architecture](docs/ARCHITECTURE.md) | System design & component overview |
| [Configuration](docs/CONFIGURATION.md) | Detailed configuration reference |
| [Scenarios](docs/SCENARIOS.md) | Attack simulation walkthroughs |

## 🎓 Learning Objectives

- SIEM fundamentals with Splunk
- Threat detection rule creation and tuning
- Incident investigation techniques
- Attack pattern recognition (MITRE ATT&CK)
- Log correlation and timeline analysis
- Incident response procedures

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is intended for educational and research purposes.
