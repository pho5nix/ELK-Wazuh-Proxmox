# Log Field Schema Reference - TraceMarshal SOC Agent

> Complete field mappings per index.
> Used by: all UCs, query construction, correlation playbooks.
> Update when: new log sources added, Vector/Filebeat parsing changes.

---

## logs-suricata*

Source: pfSense Suricata via Vector.
Format: JSON (EVE format).

| Field | Type | Description | Example |
|---|---|---|---|
| @timestamp | date | Event time | 2025-03-05T14:23:01.000Z |
| alert.signature | keyword | Rule name | ET MALWARE Trickbot |
| alert.signature_id | long | SID | 2024897 |
| alert.severity | integer | 1=high, 4=low (inverted) | 1 |
| alert.category | keyword | Alert class | A Network Trojan was detected |
| alert.action | keyword | Action taken | allowed / blocked |
| src_ip | ip | Source IP | 10.0.1.42 |
| dest_ip | ip | Destination IP | 203.0.113.50 |
| src_port | integer | Source port | 49152 |
| dest_port | integer | Destination port | 443 |
| proto | keyword | Protocol | TCP |
| flow_id | long | Flow identifier | 1234567890 |
| in_iface | keyword | Interface | em0 |

**Notes:**
- Severity is inverted: 1 = highest priority.
- `alert.action` depends on Suricata mode (IDS vs IPS on pfSense).

---

## zeek-* (conn.log)

Source: Zeek on SPAN NIC via Filebeat Zeek module (ECS mapped).
Index pattern: `zeek-*` (filtered by `event.module: zeek` and `event.dataset: zeek.connection`)

| ECS Field | Type | Description | Zeek Native Field |
|---|---|---|---|
| @timestamp | date | Connection start time | ts |
| source.address | ip | Source IP | id.orig_h |
| source.ip | ip | Source IP | id.orig_h |
| source.port | integer | Source port | id.orig_p |
| destination.address | ip | Destination IP | id.resp_h |
| destination.ip | ip | Destination IP | id.resp_h |
| destination.port | integer | Destination port | id.resp_p |
| network.transport | keyword | Protocol | proto |
| network.protocol | keyword | Detected service | service |
| source.bytes | long | Bytes from originator | orig_bytes |
| destination.bytes | long | Bytes from responder | resp_bytes |
| source.packets | long | Packets from originator | orig_pkts |
| destination.packets | long | Packets from responder | resp_pkts |
| event.duration | long | Connection duration (ns) | duration |
| zeek.connection.state | keyword | Connection state code | conn_state |
| zeek.connection.history | keyword | Connection history | history |
| zeek.connection.missed_bytes | long | Bytes missed | missed_bytes |
| zeek.session_id | keyword | Unique connection ID | uid |
| event.module | keyword | Always "zeek" | -- |
| event.dataset | keyword | Always "zeek.connection" | -- |

**zeek.connection.state codes:**
- SF = Normal close, S0 = SYN no reply, REJ = Rejected, S1 = SYN-ACK no final ACK
- RSTO = Originator reset, RSTOS0 = Responder sent SYN-ACK then originator reset
- OTH = No SYN seen

---

## zeek-* (dns.log)

Index pattern: `zeek-*` (filtered by `event.dataset: zeek.dns`)

| ECS Field | Type | Description | Zeek Native Field |
|---|---|---|---|
| @timestamp | date | Query time | ts |
| source.address | ip | Querying host | id.orig_h |
| destination.address | ip | DNS server | id.resp_h |
| dns.question.name | keyword | Queried domain | query |
| dns.question.type | keyword | Query type name | qtype_name |
| dns.response_code | keyword | Response code name | rcode_name |
| dns.answers.data | keyword | Resolution results | answers |
| zeek.dns.query | keyword | Queried domain (native) | query |
| zeek.dns.qtype | integer | Query type numeric | qtype |
| zeek.dns.qtype_name | keyword | Query type name | qtype_name |
| zeek.dns.rcode | integer | Response code numeric | rcode |
| zeek.dns.rcode_name | keyword | Response code name | rcode_name |
| zeek.dns.answers | keyword (array) | Resolution results | answers |
| zeek.dns.rejected | boolean | Query rejected | rejected |
| zeek.session_id | keyword | Connection UID | uid |
| event.dataset | keyword | Always "zeek.dns" | -- |

**dns.question.type values:** A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV, NULL

---

## zeek-* (http.log)

Index pattern: `zeek-*` (filtered by `event.dataset: zeek.http`)

| ECS Field | Type | Description | Zeek Native Field |
|---|---|---|---|
| @timestamp | date | Request time | ts |
| source.address | ip | Client IP | id.orig_h |
| destination.address | ip | Server IP | id.resp_h |
| destination.port | integer | Server port | id.resp_p |
| zeek.http.uri | keyword | Request URI (native) | uri |
| zeek.http.user_agent | keyword | User agent (native) | user_agent |
| zeek.http.status_code | integer | Response code (native) | status_code |
| http.request.method | keyword | HTTP method | method |
| url.domain | keyword | Host header | host |
| url.original | keyword | Request URI | uri |
| user_agent.original | keyword | User agent string | user_agent |
| http.response.status_code | integer | Response code | status_code |
| zeek.http.resp_mime_types | keyword | Response MIME | resp_mime_types |
| zeek.session_id | keyword | Connection UID | uid |
| event.dataset | keyword | Always "zeek.http" | -- |

---

## zeek-* (ssl.log)

Index pattern: `zeek-*` (filtered by `event.dataset: zeek.ssl`)

| ECS Field | Type | Description | Zeek Native Field |
|---|---|---|---|
| @timestamp | date | Connection time | ts |
| source.address | ip | Client IP | id.orig_h |
| destination.address | ip | Server IP | id.resp_h |
| destination.port | integer | Server port | id.resp_p |
| tls.version | keyword | TLS version | version |
| tls.client.server_name | keyword | SNI | server_name |
| destination.domain | keyword | SNI (ECS) | server_name |
| tls.server.subject | keyword | Certificate subject | subject |
| tls.server.issuer | keyword | Certificate issuer | issuer |
| tls.client.ja3 | keyword | JA3 client fingerprint | ja3 |
| tls.server.ja3s | keyword | JA3S server fingerprint | ja3s |
| zeek.ssl.subject | keyword | Certificate subject (native) | subject |
| zeek.ssl.issuer | keyword | Certificate issuer (native) | issuer |
| zeek.ssl.ja3 | keyword | JA3 (native) | ja3 |
| zeek.ssl.ja3s | keyword | JA3S (native) | ja3s |
| zeek.ssl.server_name | keyword | SNI (native) | server_name |
| zeek.ssl.validation_status | keyword | Cert validation | validation_status |
| zeek.ssl.version | keyword | TLS version (native) | version |
| zeek.ssl.established | boolean | Handshake completed | established |
| zeek.session_id | keyword | Connection UID | uid |
| event.dataset | keyword | Always "zeek.ssl" | -- |

**zeek.ssl.validation_status values:** ok, self signed certificate, certificate has expired, unable to get local issuer certificate

---

## zeek-* (files.log)

Index pattern: `zeek-*` (filtered by `event.dataset: zeek.files`)

| ECS Field | Type | Description | Zeek Native Field |
|---|---|---|---|
| @timestamp | date | File seen time | ts |

| file.mime_type | keyword | MIME type | mime_type |
| file.hash.md5 | keyword | MD5 hash | md5 |
| file.hash.sha1 | keyword | SHA1 hash | sha1 |
| file.hash.sha256 | keyword | SHA256 hash | sha256 |
| file.size | long | File size | total_bytes |
| file.name | keyword | Filename if known | filename |
| zeek.files.filename | keyword | Filename (native) | filename |
| zeek.files.mime_type | keyword | MIME type (native) | mime_type |
| zeek.files.md5 | keyword | MD5 (native) | md5 |
| zeek.files.sha1 | keyword | SHA1 (native) | sha1 |
| zeek.files.sha256 | keyword | SHA256 (native) | sha256 |
| zeek.files.total_bytes | long | File size (native) | total_bytes |
| zeek.files.seen_bytes | long | Bytes captured (native) | seen_bytes |
| zeek.files.missing_bytes | long | Bytes missed (native) | missing_bytes |
| zeek.files.source | keyword | Protocol source | source |
| zeek.session_id | keyword | File UID | fuid |
| event.dataset | keyword | Always "zeek.files" | -- |

---

## logs-wazuh-alerts*

Source: Wazuh Manager via Filebeat/Vector.
Index pattern: `logs-wazuh.alerts*`

| Field | Type | Description | Example |
|---|---|---|---|
| @timestamp | date | Alert time | 2025-03-05T14:23:01.000Z |
| wazuh.rule.id | keyword | Wazuh rule ID | 5710 |
| wazuh.rule.level | integer | Severity 0-15 | 10 |
| wazuh.rule.description | text | Rule description | sshd: Multiple failed... |
| wazuh.rule.groups | keyword (array) | Rule groups | ["syslog","sshd"] |
| wazuh.rule.mitre.id | keyword (array) | MITRE technique IDs | ["T1110"] |
| wazuh.rule.mitre.tactic | keyword (array) | MITRE tactics | ["Credential Access"] |
| wazuh.rule.mitre.technique | keyword (array) | MITRE technique names | ["Brute Force"] |
| wazuh.agent.name | keyword | Host agent name | webserver01 |
| wazuh.agent.id | keyword | Agent ID | 003 |
| wazuh.agent.ip | ip | Agent IP | 10.0.1.10 |
| wazuh.data.srcip | ip | Source IP (if applicable) | 203.0.113.50 |
| wazuh.data.dstip | ip | Dest IP (if applicable) | 10.0.1.10 |
| wazuh.data.srcport | integer | Source port | 49152 |
| wazuh.data.dstport | integer | Dest port | 22 |
| wazuh.data.srcuser | keyword | Source user | root |
| wazuh.data.dstuser | keyword | Dest user | admin |
| wazuh.data.protocol | keyword | Protocol | ssh |
| wazuh.syscheck.path | keyword | FIM file path | /etc/shadow |
| wazuh.syscheck.md5_after | keyword | FIM MD5 after change | d41d8cd... |
| wazuh.syscheck.sha256_after | keyword | FIM SHA256 after change | e3b0c44... |
| wazuh.syscheck.event | keyword | FIM event type | modified |
| wazuh.location | keyword | Log source | /var/log/auth.log |
| wazuh.decoder.name | keyword | Decoder used | sshd |

**Severity levels:**
- 0-3: Low (informational)
- 4-7: Medium (warning)
- 8-11: High (should investigate)
- 12-15: Critical (immediate action)

---

## logs-pfsense.filterlog* (filterlog)

Source: pfSense filterlog via Vector syslog → `pfsense_filterlog` transform.
Data stream: `logs-pfsense.filterlog-default`
Index pattern: `logs-pfsense.filterlog*`

| Field | Type | Description | Example |
|---|---|---|---|
| @timestamp | date | Syslog timestamp | 2025-03-05T14:23:01.000Z |
| source.ip | ip | Source IP | 203.0.113.50 |
| destination.ip | ip | Destination IP | 10.0.1.10 |
| source.port | integer | Source port | 49152 |
| destination.port | integer | Destination port | 443 |
| event.action | keyword | Firewall action (ECS) | pass / block |
| network.direction | keyword | Traffic direction (ECS) | in / out |
| network.transport | keyword | Protocol name | tcp / udp / icmp |
| network.type | keyword | IP version | ipv4 / ipv6 |
| network.bytes | integer | Packet length | 52 |
| network.iana_number | integer | IP version numeric | 4 |
| pfsense.iface | keyword | Firewall interface | em0 |
| pfsense.reason | keyword | Match reason | match |
| pfsense.action | keyword | Raw action string | pass / block |
| pfsense.direction | keyword | Raw direction string | in / out |
| pfsense.rule | integer | Rule number | 42 |
| pfsense.subrule | integer | Sub-rule number | 0 |
| pfsense.ttl | integer | TTL value | 64 |
| pfsense.proto_id | integer | Protocol ID | 6 |
| event.category | keyword[] | ECS category | ["network"] |
| event.type | keyword[] | ECS type | ["connection"] |
| event.kind | keyword | ECS kind | event |
| event.dataset | keyword | Dataset identifier | pfsense.filterlog |
| event.module | keyword | Module | pfsense |
| observer.product | keyword | Product name | pfSense |
| observer.vendor | keyword | Vendor | Netgate |
| observer.hostname | keyword | Firewall hostname | fw01 |
| source.geo.* | object | GeoIP for source | city_name, country_name, location |
| destination.geo.* | object | GeoIP for destination | city_name, country_name, location |
| tags | keyword[] | Source tag | ["source_pfsense"] |

**Notes:**
- Use `event.action` (ECS, lowercased) for queries. `pfsense.action` retains original case.
- Use `network.direction` (ECS, lowercased) for queries. `pfsense.direction` retains original case.
- `source.geo.*` and `destination.geo.*` only populated for routable IPs (GeoIP enrichment).
- Raw syslog fields (`message`, `appname`, `facility`, `severity`, `procid`) are removed after parsing.

---

## logs-pfsense.pfblockerng* (IP blocks + DNSBL)

Source: pfBlockerNG via Vector syslog → `pfblocker_parse` transform.
Data stream: `logs-pfsense.pfblockerng-default`
Index pattern: `logs-pfsense.pfblockerng*`

### Common Fields (Both IP and DNSBL)

| Field | Type | Description | Example |
|---|---|---|---|
| @timestamp | date | Block time (from pfBlockerNG unix timestamp) | 2025-03-05T14:23:01.000Z |
| event.action | keyword | Action taken | block / match |
| event.kind | keyword | ECS kind | alert |
| event.dataset | keyword | Dataset identifier | pfsense.pfblockerng |
| event.module | keyword | Module | pfsense |
| event.category | keyword[] | ECS categories | ["network","intrusion_detection"] |
| pfblocker.type | keyword | Block type | ip / dnsbl |
| pfblocker.feed | keyword | Feed name that matched | PRI1_Threats |
| source.ip | ip | Source IP | 203.0.113.50 |
| source.port | integer | Source port (if present) | 49152 |
| observer.product | keyword | Product name | pfBlockerNG |
| observer.vendor | keyword | Vendor | Netgate |
| observer.hostname | keyword | Firewall hostname | fw01 |
| source.geo.* | object | GeoIP for source | city_name, country_name, location |
| destination.geo.* | object | GeoIP for destination | city_name, country_name, location |
| tags | keyword[] | Source tag | ["source_pfblockerng"] |

### IP Block Fields (pfblocker.type == "ip")

| Field | Type | Description | Example |
|---|---|---|---|
| destination.ip | ip | Destination IP | 10.0.1.10 |
| destination.port | integer | Destination port | 443 |
| network.direction | keyword | Traffic direction | inbound / outbound |
| network.transport | keyword | Protocol | tcp / udp |
| network.type | keyword | IP version | ipv4 / ipv6 |
| pfblocker.group | keyword | pfBlockerNG group | pfB_PRI1_v4 |
| pfblocker.country_raw | keyword | Country string from feed | CN |
| source.as.number | integer | ASN number | 4134 |
| source.as.organization.name | keyword | ASN org name | CHINANET |
| observer.interface.name | keyword | Interface | WAN |

### DNSBL Fields (pfblocker.type == "dnsbl")

| Field | Type | Description | Example |
|---|---|---|---|
| destination.domain | keyword | Blocked domain | evil.example.com |
| pfblocker.category | keyword | DNSBL category | DNSBL_ADs |

**Notes:**
- Use `pfblocker.feed` (not `feed_name`) for feed validation queries. This is the canonical field.
- For IP blocks, the blocked entity is in `source.ip` or `destination.ip` depending on direction.
- For DNSBL blocks, the blocked domain is in `destination.domain`.
- Use `pfblocker.type` to distinguish IP blocks from DNSBL blocks in queries.
- Raw syslog fields are removed after parsing.
