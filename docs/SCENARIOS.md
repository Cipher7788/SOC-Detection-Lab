# Scenarios

Use the command below, changing the scenario name as needed:

```bash
docker compose run --rm data-generator python3 /scripts/generate-sample-data.py \
  --scenario brute-force --events 50 --send-hec
```

| Scenario | Generated signals | Installed detection |
|---|---|---|
| brute-force | Repeated 4625 failures for one source/user, then 4624 success | At least 5 failures per source/user |
| privilege-escalation | Login followed by 4672 sensitive privilege events | Sensitive privilege/group events |
| lateral-movement | 4688 events for PSExec, WMI, WinRS or PowerShell | Matching process names |
| data-exfiltration | File accesses and large outbound transfers | More than 100 MiB per source/destination |
| malware | Malware process events and synthetic beacon-like connections | Known malware process names |

All events are synthetic and fit the last five minutes. Choose at least six
events for the brute-force threshold. Descriptive JSON rules include ideas not
fully implemented by the saved SPL (for example DNS tunneling and automatic
containment). The beacon interval field describes the scenario's nominal cadence;
CLI timestamps are compressed to fit the recent detection window.
