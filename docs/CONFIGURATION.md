# ⚙️ Configuration Guide

Comprehensive guide to configuring your SOC Detection Lab.

## Data Input Configuration

### 1. HTTP Event Collector (HEC)

HEC is the primary method for ingesting JSON data into Splunk.

**Configuration File**: `splunk/apps/soc_lab/default/inputs.conf`

```ini
[http://soc_lab_hec]
disabled = false
port = 8088
enableSSL = false
token = REPLACE_WITH_HEC_TOKEN

# Receive data without authentication (for lab only)
[http]
disabled = false
port = 8088
```

**Using HEC with Python**:
```python
import requests
import json

url = "http://localhost:8088/services/collector"
headers = {"Authorization": f"Splunk YOUR_HEC_TOKEN"}
event = {
    "time": time.time(),
    "source": "app_name",
    "sourcetype": "json",
    "event": {
        "user": "admin",
        "action": "login",
        "status": "success"
    }
}
response = requests.post(url, json=event, headers=headers)
```

### 2. Syslog Input

For Unix/Linux systems sending syslog format.

**Configuration**:
```ini
[udp://514]
disabled = false
connection_host = dns
sourcetype = syslog
index = main
```

**Test Syslog**:
```bash
echo "<14>Feb 10 10:59:30 myhost INFO Test event" | nc -u -w0 localhost 514
```

### 3. TCP Input

For legacy systems using TCP connections.

**Configuration**:
```ini
[tcp://9997]
disabled = false
connection_host = ip
sourcetype = log
index = security
```

### 4. File Monitoring

Monitor local log files.

**Configuration**:
```ini
[monitor:///data-sources/*.csv]
disabled = false
sourcetype = csv
index = security
```

## Field Extraction Configuration

### Props.conf

Define how Splunk parses and extracts fields.

```ini
[windows_events]
TIMESTAMP_FIELDS = EventTime
TIME_PREFIX = EventTime=
TIME_FORMAT = %Y-%m-%d %H:%M:%S
TRANSFORMS-routing = route_to_security_index
EVAL-severity = case(
    EventID=4625, "high",
    EventID=4720, "medium",
    1=1, "low"
)

[linux_syslog]
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %b %d %H:%M:%S
TRUNCATE = 10000
TRANSFORMS-enrichment = add_host_info

[network_traffic]
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
EVAL-is_suspicious = case(
    dest_port > 50000, 1,
    bytes > 100000000, 1,
    1=1, 0
)
```

### Transforms.conf

Transform and enrich data.

```ini
[route_to_security_index]
REGEX = .
DEST_KEY = _MetaData:Index
FORMAT = security

[add_host_info]
filename = enrichment.csv
match_type = WILDCARD(hostname)
```

## Detection Rule Configuration

### Brute Force Detection

**Search Query**:
```spl
index=security EventID=4625 
| stats count as failed_logins by src_ip, user, dest_ip 
| where failed_logins > 10 
| eval severity="high", rule_name="Brute Force Detected"
```

**Alert Configuration** (savedsearches.conf):
```ini
[Brute Force Detection]
search = index=security EventID=4625 | stats count as failed_logins by src_ip, user, dest_ip | where failed_logins > 10
dispatch.earliest_time = -5m@m
dispatch.latest_time = now
cron_schedule = */5 * * * *
alert_type = always
alert.severity = high
actions = email, webhook
alert.email.to = security@company.com
alert.webhook.url = https://hooks.slack.com/services/YOUR/WEBHOOK
```

### Privilege Escalation Detection

```spl
index=security EventID=4688 
| where NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe" 
| stats count by User, ComputerName, CommandLine 
| where count > 5
```

**Alert Configuration**:
```ini
[Privilege Escalation Detection]
search = index=security EventID=4688 | where NewProcessName="*powershell.exe" OR NewProcessName="*cmd.exe" | stats count by User, ComputerName, CommandLine | where count > 5
dispatch.earliest_time = -10m
dispatch.latest_time = now
cron_schedule = 0 * * * *
alert_type = always
alert.severity = critical
actions = email, webhook, create_ticket
```

### Lateral Movement Detection

```spl
index=security (EventID=4624 OR EventID=4672) 
| where LogonType=3 
| stats count as remote_logins by src_ip, dest_ip, user 
| where remote_logins > 5 AND src_ip != dest_ip
```

### Data Exfiltration Detection

```spl
index=network bytes_out > 1000000000 
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, user, dest_port 
| where total_bytes > 5000000000 
| eval severity="high"
```

### Malware Detection

```spl
index=security (EventID=11 OR EventID=7) 
| where CommandLine="*powershell*" OR CommandLine="*cmd*" 
| eval severity="critical"
```

## Dashboard Configuration

### Creating a Custom Dashboard

**File**: `splunk/apps/soc_lab/dashboards/custom-security.xml`

```xml
<form>
  <label>Custom Security Dashboard</label>
  
  <row>
    <panel>
      <title>Event Count Over Time</title>
      <chart>
        <search>
          <query>index=security | timechart count by event_type</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.axisTitleX.text">Time</option>
        <option name="charting.axisTitleY.text">Count</option>
      </chart>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Top Threat Types</title>
      <table>
        <search>
          <query>index=security | stats count by threat_type | sort - count</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  
  <row>
    <panel>
      <title>Alert Status</title>
      <single>
        <search>
          <query>index=security severity=high | stats count</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
        </search>
      </single>
    </panel>
  </row>
</form>
```

## Alert Actions Configuration

### Email Alerts

```ini
[email_alert_action]
disabled = false
action.email = 1
action.email.to = security-team@company.com
action.email.subject = SOC Alert: $result.alert_name$
action.email.sendresults = 1
action.email.format = html
```

### Webhook Alerts (Slack)

```ini
[webhook_alert_action]
disabled = false
action.webhook = 1
action.webhook.url = https://hooks.slack.com/services/YOUR/WEBHOOK
action.webhook.payload = {"text":"Alert: $result.alert_name$","severity":"$result.severity$"}
```

## Index Configuration

### Creating a Custom Index

**File**: `splunk/apps/soc_lab/default/inputs.conf`

```ini
[security_index]
disabled = false
datatype = event
coldPath = $SPLUNK_DB/security/colddb
homePath = $SPLUNK_DB/security/db
thawedPath = $SPLUNK_DB/security/thaweddb
maxConcurrentOptimizes = 3
maxDataMB = 500
maxHotBuckets = 10
maxMemMB = 20
maxTimeUnreachableBuckets = 2
```

## Performance Tuning

### Optimize Search Performance

```spl
# Good: Uses index restriction and earliest time
index=security earliest=-24h@h latest=now severity=high | stats count by user

# Bad: No index, no time restriction, full table scan
* | search security AND high | table *
```

### Batch Searches for Large Data

```python
# Instead of one big search
search = "index=security | stats count by user"

# Use batch search for better performance
import splunklib.client as client
service = client.connect(host='localhost', port=8089, username='admin', password='password')
job = service.jobs.create(search, mode='normal')
```

## Custom Field Configuration

### Add Custom Fields

**In props.conf**:
```ini
[windows_events]
EVAL-event_category = case(
    EventID >= 4600 AND EventID < 4700, "Account",
    EventID >= 4700 AND EventID < 4800, "Policy",
    EventID >= 4800 AND EventID < 4900, "Detailed",
    1=1, "Other"
)

EVAL-is_critical = if(severity="critical", 1, 0)

EVAL-days_old = round((now()-_time)/86400)
```

## Advanced Configuration

### Correlation Rules

Detect complex attack patterns:

```spl
index=security 
| stats count as failed_logins by src_ip, user 
| where failed_logins > 10 
| join src_ip 
  [search index=security EventID=4672 
   | stats count as privesc by src_ip]
| where privesc > 0 
| eval correlation_score=failed_logins+privesc
```

### Anomaly Detection

```spl
index=security 
| stats count by user, date_hour 
| stats avg(count) as baseline, stdev(count) as std by user 
| where count > baseline + (2*std)
```

### Lookups Configuration

**lookups.conf**:
```ini
[internal_ips]
filename = internal_ips.csv
match_type = WILDCARD(ip)

[known_bad_domains]
filename = known_bad_domains.csv
match_type = WILDCARD(domain)
```

## Regular Maintenance

### Daily Tasks
- Monitor alert trigger rates
- Check index size growth
- Review failed searches

### Weekly Tasks
- Tune slow searches
- Update detection rules
- Review false positives

### Monthly Tasks
- Analyze trends
- Optimize indexes
- Update sample data
- Test disaster recovery

---

**Configuration Guide Version**: 1.0  
**Last Updated**: 2026-03-10