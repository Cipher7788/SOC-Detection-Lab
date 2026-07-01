# 🔧 Troubleshooting Guide

Common issues and their solutions.

## Docker & Deployment Issues

### Issue: Splunk Container Won't Start

**Error**: Container exits immediately or doesn't start

**Solutions**:

1. **Check Docker Logs**
```bash
docker logs splunk-soc-lab
```

2. **Insufficient Memory**
```bash
# Check available memory
docker stats

# Increase Docker memory limit
# Mac/Windows: Docker Desktop → Preferences → Resources
# Linux: Check /etc/docker/daemon.json
```

3. **Port Already in Use**
```bash
# Check which process is using port 8000
lsof -i :8000

# Change port in docker-compose.yml
# Change "8000:8000" to "8001:8000"
```

4. **License Issues**
```bash
# Use free license
docker logs splunk-soc-lab | grep -i license
# Ensure SPLUNK_LICENSE_URI: 'Free' in docker-compose.yml
```

### Issue: Can't Access Splunk Web UI

**Error**: Connection refused at http://localhost:8000

**Solutions**:

1. **Wait for Startup**
```bash
# Splunk takes 2-3 minutes to start
docker logs splunk-soc-lab | grep "All is well"
```

2. **Check Container Status**
```bash
docker-compose ps

# Container status should be "Up"
```

3. **Restart Container**
```bash
docker-compose restart splunk
docker logs -f splunk-soc-lab
```

4. **Port Mapping Issue**
```bash
# Verify port mapping
docker port splunk-soc-lab

# Should show: 8000/tcp -> 0.0.0.0:8000
```

### Issue: Persistent Volume Issues

**Error**: Data not persisting between restarts

**Solutions**:

1. **Check Volume Status**
```bash
docker volume ls | grep splunk
docker volume inspect splunk_etc
```

2. **Permissions Issue**
```bash
# Fix permissions on volume mount point
sudo chown -R 41812:41812 /var/lib/docker/volumes/splunk_etc/_data

# 41812 is the UID of the splunk user in container
```

3. **Recreate Volumes**
```bash
docker-compose down -v
docker-compose up -d
```

---

## Data Ingestion Issues

### Issue: No Data Showing in Splunk

**Error**: Indexes are empty, no events

**Solutions**:

1. **Verify HEC is Enabled**
```bash
docker exec splunk-soc-lab curl -k https://localhost:8088/services/collector/event \
  -H "Authorization: Splunk YOUR_HEC_TOKEN" \
  -d '{"event":"test"}'
```

2. **Check Data Generation**
```bash
# Look for generated data files
ls -la data-sources/sample-*.csv

# If empty, run generation
python3 scripts/generate-sample-data.py
```

3. **Manual Data Ingestion Test**
```bash
# Using curl
curl -X POST http://localhost:8088/services/collector \
  -H "Authorization: Splunk 00000000-0000-0000-0000-000000000000" \
  -d '{"event":{"message":"Test event"}}'
```

4. **Check Splunk Logs**
```bash
docker exec splunk-soc-lab tail -f /opt/splunk/var/log/splunk/splunkd.log
docker exec splunk-soc-lab tail -f /opt/splunk/var/log/splunk/metrics.log
```

### Issue: HEC Token Error

**Error**: `401 Unauthorized` when sending data

**Solutions**:

1. **Generate Valid HEC Token**
```bash
# Access Splunk UI → Settings → Data Inputs → HTTP Event Collector
# Create new token or view existing token
```

2. **Token in Environment**
```bash
# Check HEC token in container
docker exec splunk-soc-lab echo $SPLUNK_HEC_TOKEN

# Update in docker-compose.yml and restart
```

3. **Test HEC Token**
```bash
python3 -c "
import requests
url = 'http://localhost:8088/services/collector'
headers = {'Authorization': 'Splunk YOUR_HEC_TOKEN'}
data = {'event': {'test': 'message'}}
r = requests.post(url, json=data, headers=headers)
print(f'Status: {r.status_code}')
print(f'Response: {r.text}')
"
```

### Issue: Data Not Parsing Correctly

**Error**: Fields not extracted, raw data showing

**Solutions**:

1. **Check props.conf**
```bash
docker exec splunk-soc-lab cat /opt/splunk/etc/apps/soc_lab/default/props.conf
```

2. **Verify Source Type**
```spl
index=security | stats count by sourcetype
```

3. **Force Field Extraction**
```spl
index=security | extract
```

4. **Test Regex Pattern**
```bash
python3 -c "
import re
pattern = r'(?<time>\d{4}-\d{2}-\d{2}) (?<level>\w+)'
test_log = '2026-03-10 ERROR Something failed'
match = re.search(pattern, test_log)
if match:
    print(match.groupdict())
else:
    print('No match!')
"
```

---

## Search & Alert Issues

### Issue: Saved Search Not Running

**Error**: Alert doesn't trigger, search shows no results

**Solutions**:

1. **Check Search Syntax**
```spl
# Test in Search UI first
index=security EventID=4625 | stats count
```

2. **Verify Time Range**
```spl
# Check earliest/latest settings
index=security earliest=-24h latest=now | stats count
```

3. **Check Alert Schedule**
```bash
# Navigate to Settings → Alerts → Review schedule
# Verify cron schedule is valid
```

4. **Test Alert Manually**
```bash
docker exec splunk-soc-lab /opt/splunk/bin/splunk search \
  "index=security EventID=4625 | stats count" \
  -auth admin:SocLab@2026
```

### Issue: High False Positive Rate

**Error**: Too many alerts, alert fatigue

**Solutions**:

1. **Adjust Thresholds**
```spl
# Current: 10 failed logins
# Adjust to: 20 failed logins in 5 minutes
index=security EventID=4625 
| stats count as failed_logins by src_ip 
| where failed_logins > 20
```

2. **Add Exclusions**
```ini
# In savedsearches.conf
search = index=security EventID=4625 
  | exclude src_ip IN (approved_scanning_ips)
  | stats count as failed_logins by src_ip
  | where failed_logins > 10
```

3. **Whitelist Known Activity**
```spl
index=security EventID=4625 user!=test_user
| search NOT src_ip IN (test_network_ips)
| stats count by src_ip
```

### Issue: Slow Search Performance

**Error**: Searches take >30 seconds

**Solutions**:

1. **Add Index Restriction**
```spl
# Bad
* | search security AND EventID=4625

# Good
index=security EventID=4625
```

2. **Reduce Search Span**
```spl
# Instead of -30d
index=security earliest=-24h latest=now
```

3. **Use Summary Indexing**
```spl
# Pre-calculate results
index=security EventID=4625
| stats count by src_ip, user
| summarize
```

4. **Optimize Queries**
```spl
# Use stats instead of table when possible
index=security | stats count by user  # Fast
index=security | table * | where user  # Slow
```

---

## Detection Rule Issues

### Issue: Detection Rules Not Firing

**Error**: Known events aren't triggering alerts

**Solutions**:

1. **Verify Rule Configuration**
```bash
docker exec splunk-soc-lab grep -A10 "Brute Force Detection" \
  /opt/splunk/etc/apps/soc_lab/default/savedsearches.conf
```

2. **Check Rule Schedule**
```spl
# In Splunk UI: Settings → Saved Searches
# Verify dispatch schedule exists
```

3. **Test with Known Data**
```bash
# Generate test data
python3 scripts/generate-sample-data.py --scenario brute-force

# Wait 2-3 minutes for alert to fire
# Check Alerts section in Splunk UI
```

4. **Review Alert History**
```spl
# Search for alert events
index=_internal group=search_group search="*Brute Force*"
| table _time, alert_triggered, alert_fired, message
```

### Issue: Correlation Rule Not Working

**Error**: Multi-step detection not triggering

**Solutions**:

1. **Verify Both Conditions**
```spl
# Step 1: Brute force
index=security EventID=4625 | stats count by src_ip | where count > 10

# Step 2: Privilege escalation after brute force
index=security src_ip=* EventID=4672
```

2. **Check Time Correlation**
```spl
# Ensure events occur within correlation window
index=security (EventID=4625 OR EventID=4672) src_ip=*
| transaction src_ip startswith=EventID=4625 endswith=EventID=4672 maxspan=1h
| where eventcount > 1
```

3. **Test Sequencing**
```bash
# Simulate attack sequence
python3 scripts/generate-sample-data.py --scenario brute-force
sleep 300
python3 scripts/generate-sample-data.py --scenario privilege-escalation
```

---

## Performance Issues

### Issue: High CPU Usage

**Error**: Splunk uses excessive CPU

**Solutions**:

1. **Check Running Searches**
```bash
docker exec splunk-soc-lab ps aux | grep splunkd
```

2. **Reduce Real-time Search Load**
```bash
# Lower number of concurrent searches
# Settings → Server Settings → Limits
```

3. **Optimize Scheduled Searches**
```bash
# Spread search schedules
# Don't run multiple searches simultaneously
```

### Issue: High Memory Usage

**Error**: Container crashes with OOM

**Solutions**:

1. **Increase Docker Memory**
```bash
# docker-compose.yml
services:
  splunk:
    mem_limit: 4g  # Increase from default
```

2. **Configure Splunk Memory**
```bash
docker exec splunk-soc-lab sed -i \
  's/SPLUNK_RESERVED_MEMORY = .*/SPLUNK_RESERVED_MEMORY = 512/' \
  /opt/splunk/etc/splunk-launch.conf
```

3. **Monitor Memory**
```bash
docker stats splunk-soc-lab
```

### Issue: Disk Space Issues

**Error**: Splunk stops indexing, "No space left on device"

**Solutions**:

1. **Check Disk Usage**
```bash
docker exec splunk-soc-lab df -h /opt/splunk/var
```

2. **Clean Old Data**
```bash
# Configure index retention
# Settings → Indexes → Edit maxKB value
```

3. **Export and Delete**
```spl
# Export old data to file
index=security earliest=-1y latest=-364d | outputlookup archived_events.csv

# Delete old data manually or wait for retention
```

---

## Network Issues

### Issue: Container Can't Reach External Network

**Error**: Data ingestion from remote sources fails

**Solutions**:

1. **Check Network Configuration**
```bash
docker network ls
docker network inspect soc-lab-network
```

2. **DNS Resolution**
```bash
docker exec splunk-soc-lab nslookup google.com
```

3. **Port Access**
```bash
docker exec splunk-soc-lab telnet external-host 514
```

### Issue: Data Sources Can't Connect to Splunk

**Error**: Firewall/network blocking connections

**Solutions**:

1. **Check Firewall Rules**
```bash
sudo iptables -L -n
```

2. **Allow Port Through Firewall**
```bash
sudo firewall-cmd --add-port=8088/tcp --permanent
sudo firewall-cmd --reload
```

3. **Verify Network Connectivity**
```bash
docker-compose exec splunk curl http://localhost:8088/services/collector/health
```

---

## Configuration Issues

### Issue: Configuration Changes Not Applied

**Error**: Changes to .conf files don't take effect

**Solutions**:

1. **Reload Configuration**
```bash
docker exec splunk-soc-lab /opt/splunk/bin/splunk show config inputs
docker exec splunk-soc-lab /opt/splunk/bin/splunk reload config -auth admin:SocLab@2026
```

2. **Restart Splunk**
```bash
docker-compose restart splunk
```

3. **Check Syntax**
```bash
# Validate .conf file syntax
docker exec splunk-soc-lab /opt/splunk/bin/btool props list --debug
```

### Issue: Dashboards Not Displaying

**Error**: Dashboard returns error or shows no data

**Solutions**:

1. **Verify Dashboard XML**
```bash
docker exec splunk-soc-lab cat /opt/splunk/etc/apps/soc_lab/dashboards/custom.xml
```

2. **Test Dashboard Query**
```spl
# Run the search manually
# Copy search from dashboard XML and test
```

3. **Check Permissions**
```bash
# Ensure user has access to app and dashboard
# Settings → Manage apps → Permissions
```

---

## Reset & Recovery

### Full Lab Reset

```bash
# Stop services
docker-compose down -v

# Remove all data
rm -rf data-sources/sample-*.csv

# Clean Docker
docker system prune -a

# Rebuild
docker-compose build --no-cache
docker-compose up -d
```

### Backup Configuration

```bash
# Backup current configuration
docker cp splunk-soc-lab:/opt/splunk/etc/apps/soc_lab ./backup-soc_lab

# Restore from backup
docker cp ./backup-soc_lab splunk-soc-lab:/opt/splunk/etc/apps/
```

---

## Getting Help

### Enable Debug Logging

```bash
# View Splunk debug logs
docker logs -f splunk-soc-lab 2>&1 | grep -i error

# View application logs
docker exec splunk-soc-lab tail -f /opt/splunk/var/log/splunk/*.log
```

### Collect Diagnostic Bundle

```bash
docker exec splunk-soc-lab /opt/splunk/bin/splunk diag -auth admin:SocLab@2026
docker cp splunk-soc-lab:/opt/splunk/var/log/splunk/splunk_diag_* ./
```

### Common Error Codes

| Code | Meaning | Solution |
|------|---------|----------|
| 401 | Unauthorized | Check credentials/HEC token |
| 403 | Forbidden | Check permissions |
| 500 | Server Error | Check Splunk logs |
| 503 | Service Unavailable | Splunk still starting up |

---

**Troubleshooting Guide Version**: 1.0  
**Last Updated**: 2026-03-10