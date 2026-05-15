# Feature mapping

| Proposal feature | Current implementation |
|---|---|
| GUI-based interface | Flask pages in `templates/` |
| Data ingestion | `app/services/ingestion.py` |
| PCAP/log/live traffic | CSV/TXT/LOG/PCAP upload plus demo live monitor |
| Automated attack detection | `app/services/attack_detection.py` |
| Timeline reconstruction | `app/services/timeline.py` |
| Attacker profiling | `app/services/risk.py` |
| Session reconstruction | `app/services/session_reconstruction.py` |
| Credential extraction | `app/services/protocol_analysis.py` |
| Protocol analysis | `app/services/protocol_analysis.py` |
| Risk scoring | `app/services/risk.py` |
| Suspicious IP ranking | `app/services/risk.py` |
| Real-time monitoring | `app/services/live_monitor.py` and `templates/live.html` |
| Structured reports | `templates/report.html` and `app/services/report_service.py` |
| HTML/PDF output | HTML works by default, PDF is optional through WeasyPrint |

## Advanced SOC/DFIR Upgrade Added

This build adds the following working modules without changing the original project title:

- `app/services/mitre_mapping.py` — maps detected attacks and confirmed IOCs to MITRE ATT&CK tactics/techniques.
- `app/services/anomaly_detection.py` — lightweight behavior-anomaly engine using robust statistical scoring.
- `app/services/threat_map.py` — offline-safe threat-map visualization data for public IPs.
- `app/services/rules_scanner.py` — YARA/Sigma-style payload rule matching for credentials, SQLi, traversal, web shell keywords, and suspicious PowerShell.
- `app/services/alerting.py` — critical alert queue and optional webhook sending through `ALERT_WEBHOOK_URL`.
- `app/services/hunting.py` — threat-hunting search endpoint across attacks, timeline, TI results, MITRE mappings, rule findings, and anomalies.

New routes:

- `/hunt?q=<query>` — returns JSON search results from the latest uploaded case.
- `/alerts/send` — sends the top generated alert to the configured webhook when `ALERT_WEBHOOK_URL` is set.

Dashboard additions:

- Alert Queue
- MITRE ATT&CK Coverage
- Threat Map
- Threat Hunting Console
- Behavior Anomaly Engine
- YARA/Sigma-Style Rule Matches

Report additions:

- MITRE ATT&CK Mapping
- Behavior Anomaly Findings
- YARA/Sigma-Style Rule Matches
