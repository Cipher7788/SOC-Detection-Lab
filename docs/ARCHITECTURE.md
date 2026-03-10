# 🏗️ System Architecture

## Overview Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Environment                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐          ┌──────────────────────────────┐ │
│  │ Data Sources │          │   Splunk Enterprise          │ │
│  ├──────────────┤          ├──────────────────────────────┤ │
│  │ • Windows    │          │  • Web UI (8000)             │ │
│  │ • Linux      │─────────▶│  • HEC (8088)                │ │
│  │ • Network    │          │  • TCP Input (9997)          │ │
│  │ • App Logs   │─────────▶│  • Syslog (514)              │ │
│  └──────────────┘          │                              │ │
│                            │  ┌─────────────────────────┐ │ │
│  ┌──────────────┐          │  │   Detection Rules       │ │ │
│  │ Data         │          │  ├─────────────────────────┤ │ │
│  │ Generator    │─────────▶│  │ • Brute Force          │ │ │
│  └──────────────┘          │  │ • Privilege Escalation │ │ │
│                            │  │ • Lateral Movement     │ │ │
│  ┌──────────────┐          │  │ • Data Exfiltration    │ │ │
│  │ Test Scripts │─────────▶│  │ • Malware Detection    │ │ │
│  └──────────────┘          │  └─────────────────────────┘ │ │
│                            │                              │ │
│                            │  ┌─────────────────────────┐ │ │
│                            │  │   Dashboards            │ │ │
│                            │  ├─────────────────────────┤ │
│                            │  │ • Security Overview     │ │ │
│                            │  │ • Threat Detection      │ │ │
│                            │  │ • User Behavior         │ │ │
│                            │  │ • Network Monitoring    │ │ │
│                            │  │ • Incident Response     │ │ │
│                            │  └─────────────────────────┘ │ │
│                            │                              │ │
│                            │  ┌─────────────────────────┐ │ │
│                            │  │  Alert Engine           │ │ │
│                            │  └─────────────────────────┘ │ │
│                            └──────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │          Persistent Volumes                              │ │
│  ├─────────────────────────────────────────────────────────┤ │
│  │ • splunk_etc: Configuration & Apps                      │ │
│  │ • splunk_var: Data, indexes, logs                       │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Data Sources

#### Windows Event Logs
- Event IDs: 4624 (Logon), 4625 (Failed Logon), 4720 (User Created)
- Focus: Authentication, privilege changes, user management
- Format: CSV with Windows event fields

#### Linux System Logs
- Syslog format (RFC 5424)
- Focus: Process execution, file access, network connections
- Ingested via syslog input on port 514/UDP

#### Network Traffic
- Netflow/sFlow format
- Focus: Data transfers, unusual ports, geographic anomalies
- Includes: src_ip, dest_ip, port, protocol, bytes

#### Application Logs
- Custom format with key security fields
- Focus: Authentication, errors, suspicious activity
- Includes: timestamp, user, action, result, severity

### 2. Data Ingestion Pipeline

```
Raw Data
   │
   ▼
┌─────────────────────┐
│  Input Layer        │
│ • HEC (JSON/HTTP)   │
│ • Syslog (UDP)      │
│ • TCP Input         │
│ • File Monitoring   │
└─────────────────────┘
   │
   ▼
┌─────────────────────┐
│  Parsing (props.conf)│
│ • Field extraction  │
│ • Timestamp parsing │
│ • Source type ID    │
└─────────────────────┘
   │
   ▼
┌─────────────────────┐
│ Transformation      │
│ (transforms.conf)   │
│ • Field masking     │
│ • Enrichment        │
│ • Routing           │
└─────────────────────┘
   │
   ▼
┌─────────────────────┐
│  Index Storage      │
│ • main: General logs│
│ • security: Events  │
│ • network: Traffic  │
└─────────────────────┘
```

### 3. Detection Rules

Each detection rule follows this structure:

```
Detection Rule
├── Trigger: Alert condition (e.g., 10+ failed logins in 5 min)
├── Scope: Search span (real-time, 1 hour, 24 hours)
├── Action: Alert action (email, webhook, incident creation)
├── Severity: critical/high/medium/low
└── Metadata: Rule name, description, CIS mapping
```

### 4. Splunk App Structure

```
soc_lab/
├── default/
│   ├── inputs.conf          # Data inputs
│   ├── props.conf           # Field definitions
│   ├── transforms.conf      # Field transformations
│   ├── savedsearches.conf   # Saved searches & alerts
│   └── eventtypes.conf      # Event categorization
├── local/                   # User customizations
├── metadata/                # App metadata
│   └── default.meta
├── dashboards/              # Dashboard definitions
├── static/                  # Static assets
└── appserver/               # Web UI components
```

### 5. Detection Workflow

```
Event Arrives (via HEC/Syslog)
   │
   ▼
Parsed & Indexed
   │
   ▼
Real-time Alert Rules Run
   │
   ├─ Brute Force Check
   ├─ Privilege Escalation Check
   ├─ Lateral Movement Check
   ├─ Data Exfiltration Check
   ├─ Malware Detection Check
   └─ Suspicious Process Check
   │
   ▼
Alert Triggered?
   │
   ├─ Yes ──▶ Alert Action (Email, Webhook, etc.)
   │         │
   │         ▼
   │      Incident Created
   │         │
   │         ▼
   │      Analyst Notified
   │
   └─ No ──▶ Logged for Future Analysis
```

## Network Architecture

```
┌─ Port 8000   (Splunk Web UI)
│              Users access dashboards, search interface
│
├─ Port 8088   (HTTP Event Collector)
│              Applications send JSON events
│
├─ Port 9997   (TCP Input)
│              Legacy systems send structured logs
│
└─ Port 514    (Syslog/UDP)
               Unix/Linux systems send syslog events
```

## Data Flow

### 1. Sample Data Generation

```
generate-sample-data.py
       │
       ├─ Creates realistic events
       ├─ Applies scenario logic
       │  (brute-force, ransomware, exfiltration)
       │
       ▼
sample-*.csv files
       │
       ├─ Windows logs
       ├─ Linux logs
       ├─ Network traffic
       └─ Auth logs
```

### 2. Data Ingestion

```
ingest-data.py
       │
       ├─ Reads sample data files
       ├─ Formats for HEC
       ├─ Calls Splunk HEC API
       │  (POST to http://splunk:8088/services/collector)
       │
       ▼
Events in Splunk
       │
       ├─ Indexed with metadata
       ├─ Searchable immediately
       └─ Matched against rules
```

### 3. Detection & Response

```
Real-time Search Rules
       │
       ├─ Execute every 5 minutes
       ├─ Check for threat patterns
       │
       ▼
Rule Match?
       │
       ├─ No: Continue monitoring
       │
       └─ Yes: Execute Alert Actions
           │
           ├─ Create alert event
           ├─ Store in alert index
           ├─ Send notifications
           │  (email, webhook, Slack)
           │
           ▼
        Incident Created
           │
           ▼
      Analyst Investigates
           │
           ├─ Search related events
           ├─ Build timeline
           ├─ Correlate data
           │
           ▼
        Respond & Remediate
```

## Storage Architecture

### Splunk Indexes

```
main
├─ Default index
├─ General events
└─ Retention: 30 days (configurable)

security
├─ Security-specific events
├─ Contains alert rules
└─ Retention: 90 days

network
├─ Network traffic data
├─ Netflow/sFlow events
└─ Retention: 30 days

_internal
├─ Splunk system events
├─ Configuration tracking
└─ Retention: 7 days
```

### Volume Management

```
Total Space: 30GB+

Allocation:
├─ OS & Splunk: 10GB
├─ Indexes: 15GB
│  ├─ security: 8GB
│  ├─ main: 4GB
│  └─ network: 3GB
└─ Buffer: 5GB
```

## Security Considerations

### 1. Access Control
- Web UI authentication (admin account)
- API tokens for programmatic access
- Role-based access (optional)

### 2. Data Protection
- Data stored in Docker volumes
- No sensitive data exposed in URLs
- Logs captured for audit trail

### 3. Network Isolation
- Docker network for internal communication
- No external exposure (local use only)
- Firewall rules can be applied

## Performance Metrics

### Typical Performance
- Data ingestion: 1000+ events/second
- Search response: <5 seconds
- Alert evaluation: Real-time (sub-minute latency)
- Dashboard load: <3 seconds

### Resource Usage
```
CPU: 2-4 cores (depends on workload)
RAM: 6-8GB actively used
Disk I/O: Moderate (peaks during searches)
Network: Low (local traffic only)
```

## Extensibility Points

### Add New Data Sources
1. Update `inputs.conf` with new source
2. Create data generation script
3. Add sample data files
4. Configure field extractions

### Add New Detection Rules
1. Create rule in `savedsearches.conf`
2. Define alert conditions
3. Configure alert actions
4. Test with sample data

### Add New Dashboards
1. Create XML dashboard definition
2. Add searches and visualizations
3. Save to app dashboards directory
4. Refresh Splunk UI

### Integrate External Systems
1. Add webhook notifications
2. Integrate with ticketing systems
3. Connect to response platforms
4. Custom alert actions

## Scaling Considerations

### For Large Deployments
- Use separate indexers
- Implement load balancing
- Use distributed search
- Consider indexer clustering

### For Multiple Users
- Add authentication backend
- Implement RBAC
- Configure app permissions
- Monitor concurrent searches

## Backup & Recovery

### Backup Strategy
```
Daily backups of:
├─ Configuration (etc/)
├─ Data (var/)
└─ Custom apps
```

### Recovery Process
```
1. Stop Splunk container
2. Restore volumes from backup
3. Restart container
4. Verify data integrity
```

---

**Architecture Version**: 1.0  
**Last Updated**: 2026-03-10 04:53:02