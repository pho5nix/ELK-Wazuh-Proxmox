# Detection Rules Reference - TraceMarshal SOC Agent

> Key Suricata and Wazuh rules relevant to this stack. Used by: UC5 (/gaps), tuning, triage context. Not exhaustive - covers high-priority rules the agent encounters most.

---

## Wazuh Rule Reference

### Authentication Rules

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|5501|3|Login session opened|--|Informational|
|5502|3|Login session closed|--|Informational|
|5503|10|User login failed|T1110|Threshold: 5 in 5 min|
|5551|10|Multiple failed logins|T1110|Cluster: same source|
|5710|10|sshd: Failed auth attempt|T1110|Most common auth alert|
|5712|10|sshd: Multiple failed attempts|T1110.001|Brute force indicator|
|5715|6|sshd: Auth success|T1078|Track for post-brute success|
|5720|12|sshd: Multiple auth failures|T1110|Critical threshold|

### File Integrity Monitoring (FIM)

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|550|7|FIM: File modified|T1565|Check syscheck.path|
|553|7|FIM: File deleted|T1485|Check for mass deletion|
|554|5|FIM: File added|T1105|New file creation|
|100002|7|FIM: Ownership changed|T1222|Permission escalation|
|100003|7|FIM: Permissions changed|T1222|chmod events|

### Rootcheck / System Audit

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|510|7|Host-based anomaly|T1014|Rootcheck findings|
|516|3|Kernel event|--|System-level changes|

### Web Application

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|31101|6|Web 403 Forbidden|T1190|Access attempt|
|31104|6|Web 404 Not Found|T1595|Scanning indicator|
|31108|6|Web 500 Internal Error|T1190|Possible exploit|
|31151|10|Multiple web errors|T1190|Web attack pattern|
|31153|10|SQL injection attempt|T1190|Pattern matching|
|31154|10|XSS attempt|T1189|Pattern matching|
|31164|10|Web shell detected|T1505.003|Webshell indicators|

### Process / Command Monitoring

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|80700|4|New process started|T1059|Sysmon/auditd|
|80705|8|Suspicious process|T1059|Known bad process names|
|80710|12|Potentially dangerous command|T1059|rm -rf, mkfs, dd|
|80780|10|Suspicious Powershell|T1059.001|Encoded commands|

### Account Management

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|5901|8|User account added|T1136|Monitor for unauthorized|
|5902|10|User account deleted|T1531|Account manipulation|
|5903|8|Group membership changed|T1098|Privilege changes|
|5904|8|User password changed|T1098|Check timing/context|

### Firewall / Network

|Rule ID|Level|Description|MITRE|Tuning Notes|
|---|---|---|---|---|
|4101|6|Firewall drop event|--|From system firewall|
|60100|3|Connection from known bad IP|T1071|Threat intel based|
|60122|10|Multiple Windows logon failures|T1110|Windows specific|
|60204|10|RDP brute force|T1110.001|RDP specific|

---

## Suricata Rule Categories

### ET (Emerging Threats) Rules

|Category|SID Range|Description|MITRE|
|---|---|---|---|
|ET MALWARE|2000000-2099999|Known malware signatures|T1071, T1105|
|ET TROJAN|2800000-2899999|Trojan C2 communication|T1071, T1573|
|ET EXPLOIT|2100000-2199999|Exploit attempt signatures|T1190, T1203|
|ET SCAN|2200000-2299999|Scanning/recon activity|T1595, T1046|
|ET DOS|2300000-2399999|Denial of service patterns|T1498, T1499|
|ET WEB_SERVER|2400000-2499999|Web server attacks|T1190, T1505|
|ET WEB_CLIENT|2500000-2599999|Client-side attacks|T1189, T1204|
|ET POLICY|2600000-2699999|Policy violations|--|
|ET INFO|2700000-2799999|Informational|--|
|ET DNS|2900000-2999999|DNS anomalies|T1071.004, T1568|
|ET HUNTING|3000000+|Threat hunting signatures|Various|

### Key Suricata Severity Mapping

|Severity|Priority|Typical Action|
|---|---|---|
|1|Critical|Immediate triage, run PB03|
|2|High|Triage within current cycle|
|3|Medium|Include in daily report|
|4|Low/Info|Trend analysis only|

---

## Rule Gap Analysis Methodology

When running /gaps:

### Step 1: Extract active coverage

```
Wazuh: Aggregate distinct wazuh.rule.mitre.id from logs-wazuh-alerts* (last 30 days)
Suricata: Map active SID ranges to MITRE techniques using category table above
```

### Step 2: Compare against kb/mitre-attack-map.md

For each tactic in the coverage map:

- Mark techniques that have fired (from Step 1) as COVERED.
- Mark techniques that are mappable but have not fired as UNTESTED.
- Mark techniques with no data source as BLIND.

### Step 3: Prioritize gaps

Priority order for gap remediation:

1. C2 (TA0011) -- most critical for detection
2. Lateral Movement (TA0008) -- active compromise indicator
3. Exfiltration (TA0010) -- data loss prevention
4. Initial Access (TA0001) -- perimeter defense
5. Persistence (TA0003) -- long-term compromise

### Step 4: Recommend

For each high-priority gap:

- Can a Suricata rule cover it? (Network-visible technique)
- Can a Wazuh decoder/rule cover it? (Host-visible technique)
- Does it require a new data source? (Log source gap)
- Can a Zeek script/notice cover it? (Protocol-level detection)

---

## Tuning Common False Positives

|Source|Rule/Signature|Common FP Trigger|Tuning Action|
|---|---|---|---|
|Wazuh 5710|SSH failed auth|Service accounts, monitoring probes|Add source IP to known-good in MEMORY.md|
|Wazuh 550|FIM file modified|Package updates, log rotation|Exclude paths in Wazuh ossec.conf|
|Suricata ET POLICY|Policy violation|Legitimate but flagged services|Suppress SID in suricata threshold.config|
|Suricata ET INFO|Informational|Normal traffic patterns|Do not alert, use for enrichment only|
|pfBlockerNG|IP block|CDN IPs, cloud provider ranges|Whitelist in pfBlockerNG config|

**Process:** When the agent identifies a recurring FP:

1. Document in MEMORY.md (Known False Positives table).
2. Recommend tuning action to operator.
3. After operator applies tuning, update MEMORY.md to reflect change.
4. Agent skips this pattern in future triage automatically.
