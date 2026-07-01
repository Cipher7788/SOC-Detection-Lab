# 🚀 Quick Start Guide

Get your SOC Detection Lab up and running in 5 minutes!

## Prerequisites Checklist

- [ ] Docker installed (v20.10+)
- [ ] Docker Compose installed (v1.29+)
- [ ] 8GB RAM available
- [ ] 30GB free disk space
- [ ] Ports available: 8000, 8088, 9997, 514

## 1️⃣ Clone & Setup (2 minutes)

```bash
# Clone the repository
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git
cd SOC-Detection-Lab

# Make scripts executable
chmod +x scripts/*.sh
```

## 2️⃣ Start Splunk (1 minute)

```bash
# Start all services
docker-compose up -d

# Watch startup logs
docker logs -f splunk-soc-lab
```

**Wait for**: "Splunk is ready to accept logins"

## 3️⃣ Initial Login (1 minute)

1. Open browser: **http://localhost:8000**
2. Login with:
   - Username: `admin`
   - Password: `SocLab@2026`
3. Accept the license agreement

## 4️⃣ Generate Sample Data (1 minute)

```bash
# Generate realistic security events
python3 scripts/generate-sample-data.py

# Or run specific scenario
python3 scripts/generate-sample-data.py --scenario brute-force
```

## 5️⃣ Ingest Data (automated)

Data will be automatically ingested into Splunk. Check:

```bash
# Verify data ingestion
python3 scripts/ingest-data.py --verify
```

## ✅ Lab is Ready!

Access your dashboards:

### 🔍 Key Features to Explore

**In Splunk Web:**
1. **Search & Reporting** → Run detection queries
2. **Dashboards** → View threat insights
3. **Alerts** → Monitor active threats
4. **Settings** → Manage inputs and outputs

### 📊 Sample Searches

Search for security events:
```spl
index=security | stats count by event_type
```

Find suspicious activity:
```spl
index=security severity=high | timeline
```

Analyze user behavior:
```spl
index=security user=* | stats count by user
```

## 🎬 Run an Attack Scenario

```bash
# Simulate brute force
python3 scripts/generate-sample-data.py --scenario brute-force

# Simulate ransomware
python3 scripts/generate-sample-data.py --scenario ransomware

# Simulate data exfiltration
python3 scripts/generate-sample-data.py --scenario exfiltration
```

Then search in Splunk for the generated events!

## 🛑 Stop the Lab

```bash
# Stop services (keeps data)
docker-compose down

# Full reset (removes all data)
./scripts/cleanup.sh
```

## 🔧 Common Commands

```bash
# View logs
docker logs -f splunk-soc-lab

# Restart Splunk
docker-compose restart splunk

# Check container status
docker-compose ps

# Shell into container
docker exec -it splunk-soc-lab /bin/bash

# View configuration
docker exec splunk-soc-lab cat /opt/splunk/etc/apps/soc_lab/default/inputs.conf
```

## 🆘 Troubleshooting

**Splunk won't start?**
```bash
# Check logs for errors
docker logs splunk-soc-lab

# Increase memory and restart
docker-compose down
docker-compose up -d
```

**Can't access Splunk web?**
- Wait 2-3 minutes after startup
- Check: http://localhost:8000 (not https)
- Try: docker restart splunk-soc-lab

**No data showing?**
```bash
# Check data ingestion status
docker logs soc-data-generator

# Manually check indexes
docker exec splunk-soc-lab splunk list index -auth admin:SocLab@2026
```

## 📚 Next Steps

1. **[Read Full Documentation](ARCHITECTURE.md)**
2. **[Run Incident Scenarios](SCENARIOS.md)**
3. **[Configure Detection Rules](CONFIGURATION.md)**
4. **[Troubleshooting Guide](TROUBLESHOOTING.md)**

## 🎓 Learning Objectives

After completing this quick start, you'll:
✅ Understand SIEM basics with Splunk
✅ Ingest security event data
✅ Search and analyze logs
✅ Create detection rules
✅ Build dashboards
✅ Respond to incidents

---

**Estimated Setup Time**: 5 minutes  
**First Time Setup**: 15 minutes  
**Ready to Learn**: Let's go! 🚀