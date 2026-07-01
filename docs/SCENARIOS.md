# 🎬 Incident Scenarios

Real-world attack scenarios to practice threat detection and incident response.

## Scenario 1: Brute Force Attack

### Objective
Detect and respond to credential stuffing/brute force attacks against user accounts.

### Attack Flow
```
1. Attacker obtains password list
2. Multiple failed login attempts from single IP
3. Eventually succeeds or moves to next target
4. System generates 4625 events (failed logon)
5. Eventually 4624 event (successful logon)
```

### Generate Scenario
```bash
python3 scripts/generate-sample-data.py --scenario brute-force
```

### Expected Events
```
Event ID: 4625 (Failed Logon)
Event ID: 4624 (Successful Logon - after brute force)
Source: attacker_ip = 192.168.1.100
Target: multiple users, single computer
Duration: 30 minutes
Failed attempts: 50+
```

### Detection Query
```spl
index=security EventID=4625
| stats count as failed_logins by src_ip, user, dest_ip
| where failed_logins > 10
| eval severity="high", detection_time=now()
| table src_ip, user, dest_ip, failed_logins, severity, detection_time
```

### Response Checklist
- [ ] Confirm account is compromised
- [ ] Check for successful logon after brute force
- [ ] Lock compromised account
- [ ] Reset user password
- [ ] Check for lateral movement from compromised account
- [ ] Notify user of compromise
- [ ] Block source IP at firewall
- [ ] Monitor account for 48 hours

### Investigation Steps

1. **Identify Attack**
```spl
index=security EventID=4625 src_ip=192.168.1.100
| stats count as attempts by user
| where attempts > 10
```

2. **Find Successful Login**
```spl
index=security (EventID=4625 OR EventID=4624) src_ip=192.168.1.100
| stats count by EventID, user
```

3. **Check Post-Compromise Activity**
```spl
index=security EventID=4624 src_ip=192.168.1.100 user=victim_user
| search earliest=_time latest=+2h
| stats count by EventID
```

4. **Timeline Analysis**
```spl
index=security src_ip=192.168.1.100
| timeline
| table _time, EventID, user, dest_ip
```

---

## Scenario 2: Ransomware Infection

### Objective
Detect and respond to ransomware deployment and file encryption activity.

### Attack Flow
```
1. Malicious email or exploit delivery
2. Malware execution (process creation)
3. Credential access/escalation
4. Lateral movement to file servers
5. Mass file encryption and renaming
6. Ransom note displayed
```

### Generate Scenario
```bash
python3 scripts/generate-sample-data.py --scenario ransomware
```

### Expected Events
```
Process Creation: powershell.exe, wscript.exe
File Operations: Bulk file modifications
Registry Changes: Persistence mechanisms
Network: C2 communication
Event Duration: Hours to days
Affected Systems: Multiple
```

### Detection Queries

**Suspicious Process Execution:**
```spl
index=security EventID=4688
| where CommandLine="*powershell*" OR CommandLine="*wscript*"
| stats count by User, ComputerName, CommandLine
| where count > 5
```

**Bulk File Access:**
```spl
index=security EventID=4663
| stats count as file_accesses by user, ComputerName
| where file_accesses > 1000
```

**Registry Modifications:**
```spl
index=security EventID=4657
| where ObjectName="*HKEY_LOCAL_MACHINE*" AND ObjectValueName="*"
| stats count by SubjectUserName
| where count > 50
```

### Response Checklist
- [ ] Confirm ransomware detection
- [ ] Isolate affected systems immediately
- [ ] Take forensic images
- [ ] Check backup status and integrity
- [ ] Identify patient zero (initial compromise)
- [ ] Check for lateral movement
- [ ] Review logs for month prior
- [ ] Contact law enforcement
- [ ] Do NOT pay ransom
- [ ] Begin restoration from clean backups

### Investigation Steps

1. **Identify Patient Zero**
```spl
index=security EventID=4688 CommandLine="*powershell*"
| earliest creation
| table _time, ComputerName, User, CommandLine
```

2. **Timeline of Execution**
```spl
index=security (EventID=4688 OR EventID=4663 OR EventID=4657) ComputerName=victim
| sort _time
| table _time, EventID, ObjectName, Details
```

3. **Lateral Movement Check**
```spl
index=security EventID=4624 dest_ip=fileserver
| lookup user_to_host user OUTPUT home_computer
| where dest_ip != home_computer
```

4. **Network Communication**
```spl
index=network dest_ip=victim_ip dest_port=443
| stats sum(bytes) by dest_ip | where bytes > 1000000
```

---

## Scenario 3: Data Exfiltration

### Objective
Detect unauthorized data transfer to external networks.

### Attack Flow
```
1. Attacker gains internal access
2. Identifies sensitive data locations
3. Compresses/archives data
4. Transfers to external destination
5. Deletes local copies (sometimes)
6. System generates unusual network events
```

### Generate Scenario
```bash
python3 scripts/generate-sample-data.py --scenario exfiltration
```

### Expected Events
```
Large File Operations: 500MB+ transfers
External Connections: Unusual destinations
Protocol: HTTPS, FTP, DNS tunneling
Time: Often outside business hours
Source: Single internal host
Destination: Multiple external IPs
```

### Detection Queries

**Large Data Transfer to External IP:**
```spl
index=network dest_ip NOT IN (internal_range)
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 1000000000
| eval severity="high"
```

**Unusual Port Usage:**
```spl
index=network dest_port NOT IN (80, 443, 25, 53)
| stats count by dest_port, protocol
| where dest_port > 1024
```

**Off-Hour Data Transfer:**
```spl
index=network bytes_out > 1000000000
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 18
```

### Response Checklist
- [ ] Identify exfiltrated data
- [ ] Determine what was stolen
- [ ] Find data origin location
- [ ] Check for deletion covering tracks
- [ ] Identify attacker destination
- [ ] Preserve evidence
- [ ] Assess breach scope
- [ ] Notify affected parties
- [ ] Update security controls
- [ ] Enhance monitoring

### Investigation Steps

1. **Identify Unusual Traffic**
```spl
index=network bytes_out > 1000000000
| where dest_ip NOT IN (approved_destinations)
| table _time, src_ip, dest_ip, bytes_out, protocol
```

2. **Source System Analysis**
```spl
index=security ComputerName=source_system
| search EventID=4663 (ObjectName="*Documents*" OR ObjectName="*Databases*")
| stats count by SubjectUserName, ObjectName
```

3. **Timeline of Events**
```spl
index=security OR index=network src_ip=attacker_ip
| sort _time
| table _time, EventID, ObjectName, bytes_out, protocol
```

4. **Correlate with File Access**
```spl
index=security EventID=4663 ObjectName="*sensitive*"
| join SubjectUserName
  [search index=network src_ip=* dest_ip=external_ip bytes_out > 1000000]
```

---

## Scenario 4: Privilege Escalation

### Objective
Detect unauthorized elevation of user privileges.

### Attack Flow
```
1. Initial compromise with low privileges
2. Identify privilege escalation vulnerability
3. Execute exploit (UAC bypass, kernel exploit, etc.)
4. Achieve administrative access
5. Create persistence mechanisms
6. Move to next objective
```

### Generate Scenario
```bash
python3 scripts/generate-sample-data.py --scenario privilege-escalation
```

### Expected Events
```
Process Creation: UAC bypass attempts
Token Impersonation: SYSTEM token creation
Registry Modification: Privilege escalation paths
Event ID 4672: Special Privileges Assigned
Event ID 4688: New process with admin rights
Source: Low privilege user
Target: System-level access
```

### Detection Queries

**Special Privileges Assignment:**
```spl
index=security EventID=4672
| where PrivilegeList="*SeDebugPrivilege*" OR PrivilegeList="*SeImpersonatePrivilege*"
| stats count by SubjectUserName, ComputerName
```

**Admin Process Creation:**
```spl
index=security EventID=4688 TokenElevationType=Administrator
| where User NOT IN (admin_accounts)
| stats count by User, ComputerName, NewProcessName
| where count > 1
```

**UAC Bypass Detection:**
```spl
index=security EventID=4688
| where CommandLine="*UAC*" OR CommandLine="*cmd*" AND ParentProcessName="*explorer.exe*"
| table _time, User, ComputerName, CommandLine
```

### Response Checklist
- [ ] Confirm privilege escalation
- [ ] Identify exploit vector used
- [ ] Find initial compromise point
- [ ] Disable compromised account
- [ ] Patch vulnerability
- [ ] Check for persistence
- [ ] Audit admin account usage
- [ ] Implement privilege access workstations
- [ ] Enhanced monitoring on admin accounts

### Investigation Steps

1. **Find Escalation Event**
```spl
index=security EventID=4672 SubjectUserName!=SYSTEM
| stats first(_time) as escalation_time by SubjectUserName
```

2. **Identify Exploit**
```spl
index=security ComputerName=victim earliest=escalation_time-10m latest=escalation_time
| search EventID=4688 OR EventID=4657
| table _time, EventID, ParentProcessName, CommandLine
```

3. **Track Lateral Movement Post-Escalation**
```spl
index=security SubjectUserName=escalated_user
| search EventID=4624 LogonType=3
| stats count by dest_ip | where count > 1
```

---

## Scenario 5: Lateral Movement

### Objective
Detect attacker movement between systems after initial compromise.

### Attack Flow
```
1. Initial system compromised
2. Gather credentials
3. Scan network for targets
4. Move to other systems using credentials
5. Establish persistence on each system
6. Continue to sensitive targets
```

### Generate Scenario
```bash
python3 scripts/generate-sample-data.py --scenario lateral-movement
```

### Expected Events
```
Remote Logons: Event ID 4624 with LogonType=3
SMB Connections: Port 445 connections
Service Installation: New services on multiple hosts
Process Execution: Remote execution tools
Timing: Rapid succession between systems
Pattern: Linear progression through network
```

### Detection Queries

**Remote Logons to Multiple Systems:**
```spl
index=security EventID=4624 LogonType=3
| stats count as remote_logins, values(dest_ip) as targets by src_ip, user
| where remote_logins > 5
```

**Unusual Network Scanning:**
```spl
index=network dest_port IN (135, 139, 445, 3389)
| stats count by src_ip
| where count > 50
```

**Service Installation Across Systems:**
```spl
index=security EventID=7045
| stats count by ComputerName, ServiceName
| where count > 1
```

### Response Checklist
- [ ] Identify compromised accounts
- [ ] Map lateral movement path
- [ ] Find all affected systems
- [ ] Isolate compromised systems
- [ ] Identify target system (final destination)
- [ ] Preserve evidence
- [ ] Reset compromised credentials
- [ ] Patch all systems
- [ ] Enhanced inter-system monitoring
- [ ] Segment network

### Investigation Steps

1. **Build Movement Timeline**
```spl
index=security EventID=4624 LogonType=3 user=compromised_user
| sort _time
| table _time, dest_ip, src_ip, user
```

2. **Identify Attack Pattern**
```spl
index=security (EventID=4624 OR EventID=7045) user=compromised_user
| stats count by dest_ip, EventID
| sort dest_ip
```

3. **Check Services Installed**
```spl
index=security EventID=7045 dest_ip IN (affected_systems)
| table _time, ComputerName, ServiceName, UserName
```

---

## Running Multiple Scenarios

### Sequence Attack
```bash
# Initial compromise
python3 scripts/generate-sample-data.py --scenario brute-force

# Wait 5 minutes, then escalate
python3 scripts/generate-sample-data.py --scenario privilege-escalation

# Wait 10 minutes, then lateral movement
python3 scripts/generate-sample-data.py --scenario lateral-movement

# Final objective
python3 scripts/generate-sample-data.py --scenario data-exfiltration
```

### Competition Setup
```bash
# Run all scenarios simultaneously
for scenario in brute-force privilege-escalation lateral-movement ransomware data-exfiltration; do
  python3 scripts/generate-sample-data.py --scenario $scenario &
done
wait
```

## Performance Metrics

Measure your detection capabilities:

```spl
# Time to detect
index=security severity=high
| stats min(_time) as first_alert, max(_time) as last_alert
| eval detection_time = last_alert - first_alert

# False positive rate
index=security severity=high
| stats count as alerts
| join [search index=security confirmed=true | stats count as confirmed]
| eval false_positive_rate = (alerts - confirmed) / alerts * 100

# Missed alerts
index=security actual_threat=true alert_generated=false
| stats count
```

---

**Scenarios Version**: 1.0  
**Last Updated**: 2026-03-10 04:54:20