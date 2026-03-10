# Attack Scenarios and Detection Queries

## 1. Brute Force Attack
### Scenario:
An attacker attempts multiple login credentials repeatedly in a defined period to gain unauthorized access to accounts.

### Detection Queries:
- Identify multiple failed login attempts from a single IP address.
- Monitor for unusual authentication activity around user accounts.

## 2. Privilege Escalation
### Scenario:
An attacker exploits a vulnerability to gain elevated access to resources that are normally protected from users.

### Detection Queries:
- Alert on changes to user permissions or roles within the system.
- Monitor access to sensitive files and unauthorized changes.

## 3. Lateral Movement
### Scenario:
After initial access, the attacker moves through the network to compromise multiple systems.

### Detection Queries:
- Track unusual user account activity across multiple devices.
- Monitor for unauthorized access attempts between hosts.

## 4. Data Exfiltration
### Scenario:
An attacker transfers sensitive data from the target environment to an external location.

### Detection Queries:
- Detect large file transfers outside the network at unusual times.
- Monitor for unauthorized cloud storage access.

## 5. Malware Detection
### Scenario:
Malicious software is introduced into the environment to perform harmful actions or steal information.

### Detection Queries:
- Utilize antivirus logs to report on malware signatures.
- Monitor endpoint detection systems for suspicious process behavior.

---
*This document is intended to help analysts understand potential attack scenarios and effective detection methods.*