# Architecture

The official Splunk Enterprise container loads the SOC app directly from the host.
The app defines indexes, input monitors, field extraction, scheduled searches and
the security overview dashboard. Docker image defaults provision a shared HEC
token and enable plaintext HEC for the local network.

The one-shot Python generator waits for HEC health, builds synthetic events, and
uses `hec_client.py` to submit batches. Each envelope carries the event, source
host, `security` index, `soc_lab_json` sourcetype, and epoch time. The default flow
does not write monitored files. Optional JSON Lines files use the same sourcetype
and index, so search-time severity extraction works in both paths.

All generated timestamps fit the recent five-minute window. Saved SPL queries
detect brute force, privilege use, lateral movement, large outbound transfers and
known malware process names. The JSON rule catalog contains the same executable
SPL, plus descriptive detection ideas and response playbooks. Those descriptions
are not a separate rule engine or automated firewall/endpoint response system.

Named volumes persist Splunk configuration and indexed data. The source app and
lookup mounts are writable for image initialization and UI edits. App metadata shares searches and views and assigns
scheduled-search ownership to admin. Email/webhook actions require configuration.
