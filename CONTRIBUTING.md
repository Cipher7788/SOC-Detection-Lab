# 🤝 Contributing to SOC Detection Lab

Thank you for your interest! Contributions — new detection rules, attack scenarios, bug fixes, and docs improvements — are all welcome.

---

## Quick Setup for Contributors

```bash
git clone https://github.com/Cipher7788/SOC-Detection-Lab.git
cd SOC-Detection-Lab

# Install dev dependencies
pip install pytest pytest-cov flake8 bandit requests

# Run all tests
make test

# Lint
make lint
```

---

## Project Structure Cheat-Sheet

| Path | What goes here |
|------|----------------|
| `detection-rules/` | JSON detection rule definitions |
| `scripts/` | Python/Bash automation scripts |
| `splunk/apps/soc_lab/default/` | Splunk app `.conf` files |
| `splunk/apps/soc_lab/dashboards/` | Splunk XML dashboards |
| `splunk/lookups/` | CSV enrichment lookup tables |
| `tests/` | Pytest unit tests |
| `docs/` | Extended documentation |

---

## Adding a New Detection Rule

1. Create `detection-rules/<your-rule-name>.json` following this schema:

```json
{
  "rule_name": "Your Rule Name",
  "description": "What this detects",
  "version": "1.0",
  "severity": "high",
  "mitre_attack": {
    "tactic": "...",
    "technique": "T1234",
    "sub_technique": "T1234.001"
  },
  "detection": {
    "event_types": ["..."],
    "windows_event_ids": [1234],
    "rules": [
      {
        "id": "rule_1",
        "description": "...",
        "condition": {}
      }
    ]
  },
  "splunk_query": "index=security ... | stats count by ...",
  "response_actions": [
    { "action": "alert", "method": "email", "priority": 1, "description": "..." }
  ],
  "false_positive_notes": "...",
  "enabled": true,
  "created_at": "2026-07-01T00:00:00Z",
  "author": "your-github-handle"
}
```

2. Add the corresponding alert stanza to `splunk/apps/soc_lab/default/savedsearches.conf`
3. Add tests in `tests/test_detection_rules.py`
4. Update `README.md` detection rules table

---

## Adding a New Attack Scenario

1. Add a generator function in `scripts/generate-sample-data.py`:
   ```python
   def scenario_your_attack(start: datetime, n: int) -> List[dict]:
       ...
   ```
2. Register it in `SCENARIO_MAP`
3. Add unit tests in `tests/test_data_generator.py`
4. Document it in `docs/SCENARIOS.md`

---

## Code Style

- Python: follow PEP 8, max line length 120
- Use `Optional[X]` not `X | None` for Python 3.8 compatibility
- All scripts must pass `flake8` and `bash -n` (for shell scripts)
- No hardcoded secrets — use environment variables or `.env`

---

## Pull Request Checklist

- [ ] All 118+ tests pass (`make test`)
- [ ] Lint passes (`make lint`)
- [ ] No `.env` file committed
- [ ] PR description explains what and why
- [ ] New rules include MITRE ATT&CK reference

---

## Reporting Issues

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) or [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) templates.
