# MITRE ATT&CK Enterprise - Data Source Coverage Map

> Maps ATT&CK tactics and techniques to the data sources available in this SIEM stack. Used by: UC5 (/gaps), UC4 (/triage), correlation workflows. Reference: MITRE ATT&CK v17 Enterprise Matrix.

---

## Coverage by Tactic

### TA0043 -- Reconnaissance

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Active Scanning|T1595|Suricata, Zeek conn|logs-suricata*, zeek*|Port scans, service probes|
|Search Open Websites|T1593|--|--|Not visible to network sensors|
|Gather Victim Info|T1589|--|--|Pre-compromise, not detectable|

### TA0001 -- Initial Access

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Exploit Public-Facing App|T1190|Suricata, Wazuh|logs-suricata*, logs-wazuh-alerts*|Suricata rules + Wazuh web app rules|
|Phishing|T1566|Wazuh, Zeek http/files|logs-wazuh-alerts*, zeek*|Email gateway logs if forwarded, file downloads|
|External Remote Services|T1133|Zeek conn, pfSense|zeek*, logs-pfsense.filterlog*|VPN/RDP/SSH inbound from unusual sources|
|Valid Accounts|T1078|Wazuh|logs-wazuh-alerts*|Auth success after failures, unusual login times|
|Drive-by Compromise|T1189|Suricata, Zeek http|logs-suricata*, zeek*|Exploit kit signatures, suspicious redirects|

### TA0002 -- Execution

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Command & Scripting Interpreter|T1059|Wazuh|logs-wazuh-alerts*|Sysmon/auditd on endpoints|
|Exploitation for Client Execution|T1203|Suricata|logs-suricata*|Exploit payload signatures|
|User Execution|T1204|Wazuh|logs-wazuh-alerts*|File creation + process execution patterns|
|Scheduled Task/Job|T1053|Wazuh|logs-wazuh-alerts*|Cron/at/schtask creation events|

### TA0003 -- Persistence

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Account Creation|T1136|Wazuh|logs-wazuh-alerts*|User add events|
|Boot/Logon Autostart|T1547|Wazuh|logs-wazuh-alerts*|Registry/startup dir changes (Sysmon)|
|Scheduled Task/Job|T1053|Wazuh|logs-wazuh-alerts*|Cron/schtask persistence|
|Server Software Component|T1505|Wazuh, Zeek http|logs-wazuh-alerts*, zeek*|Webshell indicators|
|Create/Modify System Process|T1543|Wazuh|logs-wazuh-alerts*|Systemd/service creation|

### TA0004 -- Privilege Escalation

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Exploitation for Privilege Escalation|T1068|Wazuh|logs-wazuh-alerts*|Auditd/Sysmon exploit indicators|
|Valid Accounts|T1078|Wazuh|logs-wazuh-alerts*|Privilege elevation events|
|Abuse Elevation Control|T1548|Wazuh|logs-wazuh-alerts*|Sudo/UAC bypass detection|

### TA0005 -- Defense Evasion

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Obfuscated Files|T1027|Suricata, Zeek files|logs-suricata*, zeek*|Encoded payloads, packed binaries|
|Indicator Removal|T1070|Wazuh|logs-wazuh-alerts*|Log clearing, timestomping|
|Masquerading|T1036|Wazuh, Zeek files|logs-wazuh-alerts*, zeek*|Filename/extension mismatch|
|Rootkit|T1014|Wazuh|logs-wazuh-alerts*|FIM + rootcheck|
|Impair Defenses|T1562|Wazuh|logs-wazuh-alerts*|Security tool tampering|

### TA0006 -- Credential Access

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Brute Force|T1110|Wazuh, pfSense|logs-wazuh-alerts*, logs-pfsense.filterlog*|Failed auth clusters|
|Credential Dumping|T1003|Wazuh|logs-wazuh-alerts*|LSASS/shadow file access (Sysmon/auditd)|
|Network Sniffing|T1040|Wazuh|logs-wazuh-alerts*|Promiscuous mode detection|

### TA0007 -- Discovery

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Network Service Discovery|T1046|Suricata, Zeek conn|logs-suricata*, zeek*|Port scans from internal hosts|
|System Info Discovery|T1082|Wazuh|logs-wazuh-alerts*|Recon command execution|
|Account Discovery|T1087|Wazuh|logs-wazuh-alerts*|Enum commands (net user, ldapsearch)|
|Remote System Discovery|T1018|Zeek conn|zeek*|Ping sweeps, ARP scans|

### TA0008 -- Lateral Movement

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Remote Services|T1021|Zeek conn, Wazuh|zeek*, logs-wazuh-alerts*|SMB/RDP/SSH/WinRM between internal hosts|
|Lateral Tool Transfer|T1570|Zeek files, conn|zeek*|Internal file transfers (SMB writes)|
|Exploitation of Remote Services|T1210|Suricata, Wazuh|logs-suricata*, logs-wazuh-alerts*|Internal exploit signatures|

### TA0009 -- Collection

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Data from Local System|T1005|Wazuh|logs-wazuh-alerts*|Mass file access patterns|
|Data Staged|T1074|Wazuh, Zeek files|logs-wazuh-alerts*, zeek*|Archive creation before exfil|
|Screen Capture|T1113|Wazuh|logs-wazuh-alerts*|Screenshot tool execution|

### TA0011 -- Command and Control

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Application Layer Protocol: Web|T1071.001|Zeek http, Suricata|zeek*, logs-suricata*|Beaconing, unusual user agents|
|Application Layer Protocol: DNS|T1071.004|Zeek dns, Suricata|zeek*, logs-suricata*|DNS tunneling, high query volume|
|Encrypted Channel|T1573|Zeek ssl|zeek*|Self-signed certs, unusual JA3|
|Non-Standard Port|T1571|Zeek conn|zeek*|HTTP/HTTPS on non-standard ports|
|Proxy|T1090|Zeek conn, Suricata|zeek*, logs-suricata*|SOCKS/proxy signatures|
|Dynamic Resolution (DGA)|T1568|Zeek dns|zeek*|High-entropy domain queries|
|Ingress Tool Transfer|T1105|Zeek files, Suricata|zeek*, logs-suricata*|Executable downloads|

### TA0010 -- Exfiltration

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Exfil Over C2 Channel|T1041|Zeek conn|zeek*|Large outbound transfers to C2|
|Exfil Over Alternative Protocol|T1048|Zeek conn, dns|zeek*|DNS exfil, ICMP tunneling|
|Exfil Over Web Service|T1567|Zeek http, ssl|zeek*|Uploads to cloud storage|
|Automated Exfiltration|T1020|Zeek conn|zeek*|Periodic large transfers|

### TA0040 -- Impact

|Technique|ID|Detectable By|Index|Notes|
|---|---|---|---|---|
|Data Destruction|T1485|Wazuh|logs-wazuh-alerts*|Mass file deletion/overwrite|
|Service Stop|T1489|Wazuh|logs-wazuh-alerts*|Critical service stopped|
|Resource Hijacking|T1496|Zeek conn, Wazuh|zeek*, logs-wazuh-alerts*|Crypto mining connections|
|Disk Wipe|T1561|Wazuh|logs-wazuh-alerts*|Destructive commands (dd, format)|

---

## Coverage Summary

|Tactic|Techniques Mappable|Primary Source|Secondary Source|
|---|---|---|---|
|Reconnaissance|1 of 10|Suricata, Zeek|--|
|Initial Access|5 of 9|Suricata, Wazuh|Zeek, pfSense|
|Execution|4 of 13|Wazuh|Suricata|
|Persistence|5 of 19|Wazuh|Zeek|
|Privilege Escalation|3 of 13|Wazuh|--|
|Defense Evasion|5 of 42|Wazuh|Suricata, Zeek|
|Credential Access|3 of 17|Wazuh|pfSense|
|Discovery|4 of 30|Zeek, Wazuh|Suricata|
|Lateral Movement|3 of 9|Zeek|Wazuh, Suricata|
|Collection|3 of 17|Wazuh|Zeek|
|C2|7 of 16|Zeek|Suricata|
|Exfiltration|4 of 9|Zeek|--|
|Impact|4 of 13|Wazuh|Zeek|

> Note: Technique counts reflect what is detectable with THIS stack's data sources. Endpoint-heavy techniques (Defense Evasion, Collection) depend on Wazuh agent + Sysmon/auditd depth.
