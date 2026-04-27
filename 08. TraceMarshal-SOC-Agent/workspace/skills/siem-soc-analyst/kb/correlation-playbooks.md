# Correlation Playbooks - TraceMarshal SOC Agent

> Step-by-step cross-source correlation procedures.
> Used by: UC1 (/correlate), UC10 (/ir), UC4 (/triage enrichment).
> Each playbook specifies exact query sequence, field mapping and decision logic.

---

## PB01 - IP Correlation (Full Pivot)

**Trigger:** Suspicious IP identified from any source.
**Token budget:** Max 4 Elasticsearch queries.

### Step 1: Multi-index initial sweep
Use `skills/siem-soc-analyst/kb/es-query-cookbook.md` Pattern 4 (Multi-Index IP Pivot) with the target IP.
Collect: which indices have hits, timestamps, event types.

### Step 2: Suricata context
If IP appears in `logs-suricata*`:
- Note alert signatures, severity, category.
- Record src/dst relationship (is the IP attacker or target?).

### Step 3: Zeek deep dive
If IP appears in `zeek-*`:
- **conn.log:** Duration, bytes transferred, service, connection state.
- **dns.log:** What domains did this IP resolve? Was it resolved by internal hosts?
- **ssl.log:** Certificate info, JA3 hash, validation status.
- **http.log:** URIs accessed, user agents, response codes.
- **files.log:** Any file transfers, MIME types, hashes.

### Step 4: Wazuh host context
If IP appears in `logs-wazuh-alerts*` as `wazuh.data.srcip` or `wazuh.agent.ip`:
- Note rule IDs, levels, MITRE mappings.
- Identify affected host agent name.
- Check for auth failures, process execution, file changes.

### Step 5: pfSense/pfBlockerNG
If IP appears in `logs-pfsense.filterlog*` or `logs-pfsense.pfblockerng*`:
- Was it blocked or allowed?
- Which interface, which rule, which feed?

### Output format:
```
## Correlation: <IP> | <TIMESTAMP_RANGE>
**Verdict:** HIGH/MEDIUM/LOW
**Direction:** Inbound/Outbound/Internal

| Time | Source | Index | Event |
|------|--------|-------|-------|
| ... | ... | ... | ... |

**MITRE mapping:** T<ID> (<Tactic>)
**Affected hosts:** <list>
**Recommendation:** <action>
```

---

## PB02 - Domain Correlation

**Trigger:** Suspicious domain identified from DNS logs or threat intel.
**Token budget:** Max 3 Elasticsearch queries.

### Step 1: DNS resolution history
Use `skills/siem-soc-analyst/kb/es-query-cookbook.md` Pattern 11 (Domain Pivot) to find:
- Which internal hosts queried this domain.
- What IPs it resolved to (answers field).
- Query volume and timespan.

### Step 2: Connection follow-up
Take resolved IPs from Step 1 answers. Run Pattern 4 (Multi-Index IP Pivot) for each resolved IP.
Check Zeek conn.log for actual connections to those IPs.

### Step 3: Cross-reference blocks
Check `logs-pfsense.pfblockerng*` for the domain and resolved IPs.
Was it already blocked? By which feed?

### Output format:
```
## Correlation: <DOMAIN> | <TIMESTAMP_RANGE>
**Resolved to:** <IP list>
**Queried by:** <host list>
**Connections established:** yes/no
**Blocked by pfBlockerNG:** yes/no (feed: <name>)
**Verdict:** HIGH/MEDIUM/LOW
```

---

## PB03 - Alert-to-Incident Escalation

**Trigger:** Wazuh alert with rule.level >= 12 or Suricata alert with severity 1.
**Token budget:** Max 5 Elasticsearch queries.

### Step 1: Alert details
Pull the triggering alert with full context fields.

### Step 2: Host timeline
For the affected host, query all indices for activity in the +/- 30 minute window:
- Wazuh: other alerts on same agent.
- Zeek: outbound connections from host IP.
- Suricata: network alerts involving host IP.
- pfSense: firewall actions involving host IP.

### Step 3: Kill chain classification
Map collected evidence to kill chain phases:
1. **Reconnaissance:** Port scans, service enumeration targeting the host?
2. **Initial access:** Exploit signature, auth success after failures?
3. **Execution:** Process creation, script execution on host?
4. **Persistence:** Account creation, scheduled task, startup modification?
5. **Lateral movement:** Connections to other internal hosts on management ports?
6. **C2:** Outbound beaconing, DNS anomalies, TLS anomalies?
7. **Exfiltration:** Large outbound transfers, DNS tunneling?

### Step 4: Evidence packaging
Compile into incident report using `skills/siem-soc-analyst/kb/incident-response-templates.md` IR-01.

### Step 5: Containment recommendation
Based on kill chain phase:
- Reconnaissance/Initial access: Monitor, add to watchlist.
- Execution/Persistence: Recommend host isolation, credential rotation.
- Lateral movement: Recommend network segmentation enforcement, affected host scan.
- C2/Exfiltration: Recommend immediate IP block at pfSense, host isolation.

---

## PB04 - Brute Force Correlation

**Trigger:** Wazuh rules 5710 (SSH), 5503, 60122, 60204 or high failed auth volume.
**Token budget:** Max 3 Elasticsearch queries.

### Step 1: Auth failure aggregation
Query `logs-wazuh-alerts*` for auth failure rules, aggregate by source IP and target host.

### Step 2: Success check
For the same source IPs, query for successful auth events in the subsequent timeframe.
If success follows failures = **compromised account** (HIGH).

### Step 3: Network context
Check `zeek-*` conn.log for the source IP:
- Is it external or internal?
- What other services did it connect to?
- Any post-auth lateral movement?

Check `logs-pfsense.filterlog*`:
- Was the source ever blocked by firewall?
- Is it in a pfBlockerNG feed?

### Output:
```
## Brute Force Analysis: <SRC_IP> → <TARGET(S)>
**Attempts:** <count> over <duration>
**Successful auth:** yes/no (if yes: CRITICAL)
**Source type:** External/Internal
**Post-auth activity:** <description or none>
**Recommendation:** Block source / Rotate credentials / Monitor
```

---

## PB05 - File Hash Correlation

**Trigger:** Suspicious file hash from Zeek files.log or Wazuh FIM alert.
**Token budget:** Max 2 Elasticsearch queries + 1 web search.

### Step 1: Internal presence
Query `zeek-*` for the hash (md5/sha1/sha256):
- Which hosts downloaded it?
- What was the source URL/IP?
- MIME type and filename?

### Step 2: Wazuh FIM
Query `logs-wazuh-alerts*` for FIM alerts referencing the hash or filename on any agent.

### Step 3: External reputation
Use web search for the hash on VirusTotal/MalwareBazaar.
Record detection ratio and malware family if identified.

### Output:
```
## File Correlation: <HASH>
**Filename:** <name> | **MIME:** <type> | **Size:** <bytes>
**Downloaded by:** <host list>
**Source:** <IP/URL>
**VT detection:** <ratio> | **Family:** <name or unknown>
**FIM alerts:** <count on agents>
**Verdict:** Malicious/Suspicious/Clean
**Recommendation:** <action>
```

---

## Cross-Reference Field Mapping

> Use this table when correlating across indices. Field names differ per source.

| Concept | logs-suricata* | zeek-* | logs-wazuh-alerts* | logs-pfsense.filterlog* | logs-pfsense.pfblockerng* |
|---|---|---|---|---|---|
| Source IP | src_ip | source.address | data.srcip | source.ip | source.ip |
| Dest IP | dest_ip | destination.address | data.dstip | destination.ip | destination.ip |
| Source port | src_port | source.port | data.srcport | source.port | source.port |
| Dest port | dest_port | destination.port | data.dstport | destination.port | destination.port |
| Protocol | proto | network.transport | data.protocol | network.transport | network.transport |
| Hostname | -- | -- | agent.name | observer.hostname | observer.hostname |
| Domain | -- | dns.question.name / url.domain | -- | -- | destination.domain |
| Alert name | alert.signature | -- | rule.description | -- | -- |
| Severity | alert.severity | -- | rule.level | -- | -- |
| MITRE ID | -- | -- | rule.mitre.id | -- | -- |
| Action | -- | -- | -- | event.action | event.action |
| Direction | -- | -- | -- | network.direction | network.direction |
| Feed | -- | -- | -- | -- | pfblocker.feed |
| Block type | -- | -- | -- | -- | pfblocker.type |
| File hash | -- | file.hash.md5 / file.hash.sha1 | syscheck.md5 | -- | -- |
| JA3 | -- | tls.client.ja3 | -- | -- | -- |
| User agent | -- | user_agent.original | -- | -- | -- |
| Conn state | -- | zeek.connection.state | -- | -- | -- |
