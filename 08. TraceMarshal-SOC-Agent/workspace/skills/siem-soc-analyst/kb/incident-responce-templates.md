# Incident Response Templates - TraceMarshal SOC Agent

> Templates for IR reports and containment checklists. Used by: UC10 (/ir), PB03 (Alert-to-Incident Escalation). Reports are saved to memory/incidents/YYYY-MM-DD-<id>.md

---

## IR-01: Standard Incident Report

```markdown
# Incident Report: <SHORT_TITLE>

**ID:** INC-<YYYY-MM-DD>-<SEQ>
**Date:** <YYYY-MM-DD>
**Time (UTC):** <FIRST_SEEN> to <LAST_SEEN>
**Severity:** CRITICAL / HIGH / MEDIUM
**Status:** OPEN / CONTAINED / RESOLVED
**Analyst:** Reaper (automated)

---

## Summary

<2-3 sentence description of what happened, when, and what was affected.>

## Kill Chain Classification

| Phase | Evidence | Source |
|---|---|---|
| Reconnaissance | <description or N/A> | <index> |
| Initial Access | <description or N/A> | <index> |
| Execution | <description or N/A> | <index> |
| Persistence | <description or N/A> | <index> |
| Privilege Escalation | <description or N/A> | <index> |
| Defense Evasion | <description or N/A> | <index> |
| Credential Access | <description or N/A> | <index> |
| Discovery | <description or N/A> | <index> |
| Lateral Movement | <description or N/A> | <index> |
| Collection | <description or N/A> | <index> |
| C2 | <description or N/A> | <index> |
| Exfiltration | <description or N/A> | <index> |
| Impact | <description or N/A> | <index> |

## MITRE ATT&CK Mapping

| Technique | ID | Confidence |
|---|---|---|
| <name> | T<ID> | HIGH/MEDIUM/LOW |

## Timeline

| Time (UTC) | Source | Event | Details |
|---|---|---|---|
| <HH:MM:SS> | <index> | <event type> | <key fields> |

## Indicators of Compromise

| IOC | Type | Verdict | Source |
|---|---|---|---|
| <value> | IPv4/Domain/Hash/JA3 | MALICIOUS/SUSPICIOUS | <where found> |

## Affected Assets

| Host/Agent | IP | Role | Impact |
|---|---|---|---|
| <agent.name> | <IP> | <function> | <description> |

## Containment Recommendations

1. <immediate action>
2. <follow-up action>
3. <monitoring action>

## Evidence Queries

<Elasticsearch queries used to gather evidence, for reproducibility>

## Notes

<additional context, confidence caveats, open questions>
```

---

## IR-02: Brute Force Incident

```markdown
# Incident Report: Brute Force Attack on <TARGET>

**ID:** INC-<YYYY-MM-DD>-<SEQ>
**Date:** <YYYY-MM-DD>
**Severity:** <HIGH if success detected, MEDIUM if failed only>
**Status:** OPEN

---

## Summary

Brute force attack detected against <target service> on <host>. <N> failed attempts from <source IP/range> over <duration>. Successful authentication: <yes/no>.

## Attack Details

| Metric | Value |
|---|---|
| Source IP(s) | <IP list> |
| Target Host | <agent.name> (<IP>) |
| Target Service | SSH / RDP / Web |
| Failed Attempts | <count> |
| Time Window | <start> to <end> |
| Successful Auth | Yes / No |
| Post-Auth Activity | <description or None detected> |

## Wazuh Rules Triggered

| Rule ID | Level | Count | Description |
|---|---|---|---|
| <ID> | <level> | <count> | <description> |

## Network Context (Zeek)

| Metric | Value |
|---|---|
| Connections from source | <count> |
| Other services contacted | <list> |
| Bytes transferred | <total> |
| Connection duration | <total> |

## pfSense/pfBlockerNG Status

- Firewall action on source: <BLOCKED/ALLOWED>
- pfBlockerNG match: <YES (feed: X) / NO>

## Containment

1. Block source IP at pfSense: <IP>
2. <If success: Force password reset for compromised account>
3. <If success: Scan target host for persistence mechanisms>
4. Monitor for source IP reappearance from different range
```

---

## IR-03: C2 Communication Detected

```markdown
# Incident Report: C2 Communication Detected

**ID:** INC-<YYYY-MM-DD>-<SEQ>
**Date:** <YYYY-MM-DD>
**Severity:** CRITICAL
**Status:** OPEN

---

## Summary

Suspected C2 communication detected from <internal host> to <external IP/domain>. Pattern: <beaconing/DGA/tunneling/encrypted>.

## C2 Indicators

| Indicator | Type | Value |
|---|---|---|
| Destination | IP/Domain | <value> |
| Protocol | -- | <HTTP/HTTPS/DNS/Custom> |
| Port | -- | <port> |
| JA3 Hash | -- | <value or N/A> |
| Beacon Interval | -- | <seconds +/- jitter> |
| Certificate | -- | <self-signed/expired/valid> |
| SNI | -- | <server name or blank> |

## Internal Host

| Field | Value |
|---|---|
| Hostname | <agent.name> |
| IP | <IP> |
| First C2 activity | <timestamp> |
| Last C2 activity | <timestamp> |
| Total sessions | <count> |
| Total bytes out | <bytes> |

## Correlation Evidence

| Source | Findings |
|---|---|
| Suricata | <signatures triggered> |
| Zeek DNS | <domains resolved> |
| Zeek SSL | <cert details> |
| Zeek HTTP | <URIs if HTTP C2> |
| Wazuh | <host-level alerts> |
| pfBlockerNG | <blocked: yes/no> |

## Containment

1. IMMEDIATE: Block <C2 IP/domain> at pfSense
2. Isolate <internal host> from network
3. Preserve Zeek PCAP if available
4. Scan host for persistence (scheduled tasks, startup items)
5. Rotate all credentials stored/used on <host>
6. Check Zeek conn.log for lateral movement from <host> to other internal systems
```

---

## IR-04: Data Exfiltration Suspected

```markdown
# Incident Report: Suspected Data Exfiltration

**ID:** INC-<YYYY-MM-DD>-<SEQ>
**Date:** <YYYY-MM-DD>
**Severity:** CRITICAL
**Status:** OPEN

---

## Summary

Anomalous outbound data transfer detected from <host> to <destination>. <N> bytes transferred over <duration> via <protocol>.

## Transfer Details

| Metric | Value |
|---|---|
| Source Host | <agent.name> (<IP>) |
| Destination | <IP> (<domain if resolved>) |
| Protocol | <service> |
| Port | <port> |
| Bytes Out | <orig_bytes> |
| Duration | <seconds> |
| Sessions | <count> |
| First Transfer | <timestamp> |
| Last Transfer | <timestamp> |

## Destination Reputation

| Check | Result |
|---|---|
| In baseline | Yes / No |
| pfBlockerNG | Blocked / Not listed |
| VirusTotal | <verdict> |
| AbuseIPDB | <confidence %> |
| GeoIP | <country> |

## Pre-Exfil Activity (Kill Chain Context)

| Phase | Evidence |
|---|---|
| Initial compromise | <how host was compromised, if known> |
| Collection/staging | <file access patterns from Wazuh FIM> |
| C2 established | <related C2 indicators if any> |

## Containment

1. IMMEDIATE: Block <destination IP> at pfSense
2. Isolate <host> from network
3. Assess data exposure: identify what files/data were accessible
4. Check <host> for staging artifacts (archives, temp files)
5. Review Zeek files.log for file transfers from <host>
6. Notify operator for data breach assessment
```

---

## Containment Action Reference

|Scenario|Immediate|Follow-up|Monitoring|
|---|---|---|---|
|External brute force|Block source IP at pfSense|Review all auth from source range|Watch for rotated source IPs|
|Internal brute force|Alert operator, do not auto-block|Investigate compromised host|Watch for credential reuse|
|C2 detected|Block C2 IP/domain at pfSense|Isolate host, scan for persistence|Monitor for C2 migration|
|Exfiltration|Block destination, isolate host|Assess data exposure|Watch for alt exfil channels|
|Malware download|Block source URL/IP|Scan host with Wazuh rootcheck|Monitor for execution artifacts|
|Webshell|Alert operator|FIM review on web directories|Watch for new web file creation|
|Port scan (external)|Block source at pfSense|Review targeted services|Watch for exploitation attempts|
|Port scan (internal)|Alert operator, investigate source|Correlate with other host alerts|Watch for lateral movement|

---

## Report Naming Convention

```
memory/incidents/YYYY-MM-DD-<SEQ>.md
```

- SEQ: 001, 002, etc. per day.
- Example: `memory/incidents/2026-03-05-001.md`
- Reference in daily notes: `See [INC-2026-03-05-001](incidents/2026-03-05-001.md)`
