# MEMORY.md - TraceMarshal Long-Term Memory

> This file is curated knowledge that persists across sessions. Only loaded in main (direct) sessions. Never shared in group contexts. Update when: new baselines established, false positives confirmed, detection gaps found, environment changes noted. Prune when: entries become stale (>90 days without relevance).

---

## Environment Baseline

### Infrastructure

- SIEM Host: Debian 13, SIEM VLAN (no internet)
- Agent Host: separate device, Agent VLAN (has internet)
- Cross-VLAN link: Agent -> SIEM-IP:9200 (TLS, read-only API key)
- Stack: Elasticsearch, Kibana, Filebeat, Vector, Wazuh Manager, Zeek
- External sources: pfSense (Suricata, syslog, pfBlockerNG)

### Index Ingestion Baselines

> Update these after first week of operation with actual values.

|Index|Avg docs/hour|Last updated|
|---|---|---|
|logs-suricata*|TBD|--|
|zeek-*|TBD|--|
|logs-wazuh.alerts*|TBD|--|
|logs-pfsense.filterlog*|TBD|--|
|logs-pfsense.pfblockerng*|TBD|--|

### Normal Traffic Patterns

> Populate after first baseline period (7 days recommended).

- Top internal talkers: TBD
- Expected outbound services: TBD
- Normal DNS query volume/hour: TBD
- Normal Zeek protocol distribution: TBD

---

## Known False Positives

> Add confirmed false positives here so triage skips them. Format: | Source | Signature/Rule | Trigger | Reason | Date Added |

|Source|Signature/Rule|Trigger|Reason|Date Added|
|---|---|---|---|---|
|--|--|--|--|--|

---

## Detection Coverage

### MITRE ATT&CK Tactics Covered

> Updated by /gaps command. Track coverage over time.

|Tactic|Covered Techniques|Gaps Identified|Last Checked|
|---|---|---|---|
|Initial Access|TBD|TBD|--|
|Execution|TBD|TBD|--|
|Persistence|TBD|TBD|--|
|Privilege Escalation|TBD|TBD|--|
|Defense Evasion|TBD|TBD|--|
|Credential Access|TBD|TBD|--|
|Discovery|TBD|TBD|--|
|Lateral Movement|TBD|TBD|--|
|Collection|TBD|TBD|--|
|Command & Control|TBD|TBD|--|
|Exfiltration|TBD|TBD|--|
|Impact|TBD|TBD|--|

---

## Hunt Results Log

> Summary of completed hunts. Details in daily notes. Format: | Date | Hypothesis | Result | Action Taken |

|Date|Hypothesis|Result|Action Taken|
|---|---|---|---|
|--|--|--|--|

---

## IOC Watchlist Summary

> High-level tracker. Full details in memory/ioc-tracker.md.

- Active IOCs tracked: 0
- Last enrichment run: --
- IOCs pending expiration review: 0

---

## Tuning Notes

> Lessons learned, threshold adjustments, environment-specific quirks.

- (none yet -- populate during first operational week)

---

## Feed Quality Scores

> Updated by /feeds command. Format: | Feed | Hit Rate | FP Rate | Last Checked |

|Feed|Hit Rate|FP Rate|Last Checked|
|---|---|---|---|
|--|--|--|--|
