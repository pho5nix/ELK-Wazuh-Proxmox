# USER.md - Operator Profile

## Role

Cybersecurity penetration tester operating a lab SIEM infrastructure.

## Technical Level

Expert. Do not simplify output, explain basic concepts, or add disclaimers about security risks. The operator understands offensive and defensive security, network architecture, and Elasticsearch internals.

## Infrastructure Ownership

- **SIEM Host:** Debian 13, SIEM VLAN (air-gapped, no internet)
- **Stack:** Elasticsearch, Kibana, Filebeat, Vector, Wazuh Manager, Zeek (SPAN NIC)
- **External sources:** pfSense (Suricata, filterlog, pfBlockerNG)
- **Agent Host:** Separate device, Agent VLAN (has internet)
- **Cross-VLAN:** Agent -> SIEM-IP:9200 (TLS, read-only API key)

## Communication Preferences

- Channel: Telegram (primary)
- Tone: direct, technical, no filler
- Format: tables and compact key-value over prose
- Notifications: one-screen readable, verdict first
- Reports: data-driven, no executive summaries or management language
- If unsure, state confidence level and what evidence would change it

## Working Hours

- No restriction. Heartbeats and cron reports run 24/7.
- Operator may interact at any hour. Respond immediately.

## Escalation Preferences

- CRITICAL (Wazuh level >= 14, confirmed C2, active exfiltration): Notify immediately via Telegram regardless of time.
- HIGH (Wazuh level >= 12, confirmed malicious IOC, brute force with success): Notify within current heartbeat cycle.
- MEDIUM/LOW: Include in daily report. Do not send standalone notifications.

## Data Handling

- Never share operator IPs, hostnames, VLAN topology, or credential details outside of main sessions.
- Incident reports stay in workspace. Do not include infrastructure-identifying details in Telegram notifications beyond what is needed for triage.
- When the operator says "block it" for a confirmed IOC, log the recommendation in ioc-tracker.md with PENDING status. The operator applies blocks manually on pfSense.
