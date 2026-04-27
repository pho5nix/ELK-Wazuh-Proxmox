# Threat Hunt Library - TraceMarshal SOC Agent

> Pre-built hunt hypotheses with ready-to-use ES queries.
> Used by: UC2 (/hunt), HEARTBEAT rotation.
> Each hunt includes: hypothesis, MITRE mapping, Elasticsearch query, verdict criteria, token budget.

---

## H01 - DNS Beaconing

**Hypothesis:** A compromised host is beaconing to a C2 domain via periodic DNS queries.
**MITRE:** T1071.004 (Application Layer Protocol: DNS)
**Data source:** Zeek dns.log (`zeek-*`, dataset: zeek.dns)
**Token budget:** 1 Elasticsearch query (aggregation)

```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"exists": {"field": "dns.question.name"}}
      ],
      "must_not": [
        {"terms": {"query": ["localhost","wpad","isatap","_ldap","_kerberos"]}}
      ]
    }
  },
  "aggs": {
    "by_host_domain": {
      "composite": {
        "size": 50,
        "sources": [
          {"host": {"terms": {"field": "source.address"}}},
          {"domain": {"terms": {"field": "dns.question.name"}}}
        ]
      },
      "aggs": {
        "count": {"value_count": {"field": "@timestamp"}}
      }
    }
  }
}
```

**Verdict criteria:**
- HIGH: >100 queries to single domain from single host in 1 hour
- MEDIUM: 50-100 queries with consistent interval
- LOW: 30-50 queries, review manually
- Exclude: internal DNS zones, known CDN domains, NTP pools

---

## H02 - C2 Jitter Detection

**Hypothesis:** Outbound connections to a single destination exhibit periodic timing consistent with C2 callback intervals.
**MITRE:** T1071.001 (Application Layer Protocol: Web), T1573 (Encrypted Channel)
**Data source:** Zeek conn.log (`zeek-*`, dataset: zeek.connection)
**Token budget:** 1 Elasticsearch query (aggregation)

```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-4h"}}},
        {"range": {"event.duration": {"gte": 0}}},
        {"exists": {"field": "destination.address"}}
      ],
      "must_not": [
        {"terms": {"destination.port": [53, 123, 5353]}}
      ]
    }
  },
  "aggs": {
    "by_pair": {
      "composite": {
        "size": 50,
        "sources": [
          {"src": {"terms": {"field": "source.address"}}},
          {"dst": {"terms": {"field": "destination.address"}}},
          {"port": {"terms": {"field": "destination.port"}}}
        ]
      },
      "aggs": {
        "session_count": {"value_count": {"field": "@timestamp"}},
        "time_stats": {"stats": {"field": "@timestamp"}}
      }
    }
  }
}
```

**Verdict criteria:**
- Flag pairs with >20 connections in 4 hours with consistent intervals
- Calculate interval stddev from timestamps. Low stddev (<10% of mean interval) = HIGH
- Exclude: known update services, monitoring endpoints, internal infrastructure

---

## H03 - Lateral Movement

**Hypothesis:** An internal host is performing lateral movement via SMB, RDP, WinRM, or SSH after initial compromise.
**MITRE:** T1021 (Remote Services), T1110 (Brute Force)
**Data source:** Wazuh alerts + Zeek conn.log
**Token budget:** 2 Elasticsearch queries

**Query 1: Failed auth clusters (Wazuh)**
```json
GET logs-wazuh-alerts*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-2h"}}},
        {"terms": {"wazuh.rule.id": ["5710","5503","5551","60122","60204","18100","18101"]}}
      ]
    }
  },
  "aggs": {
    "by_src": {
      "terms": {"field": "wazub.data.srcip", "size": 20},
      "aggs": {
        "targets": {"terms": {"field": "wazuh.agent.name", "size": 10}},
        "count": {"value_count": {"field": "@timestamp"}}
      }
    }
  }
}
```

**Query 2: Internal SMB/RDP/SSH connections (Zeek)**
```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-2h"}}},
        {"terms": {"destination.port": [445, 3389, 22, 5985, 5986]}},
        {"wildcard": {"source.address": "10.*"}}
      ]
    }
  },
  "aggs": {
    "by_src": {
      "terms": {"field": "source.address", "size": 20},
      "aggs": {
        "targets": {"terms": {"field": "destination.address", "size": 10}}
      }
    }
  }
}
```

**Verdict criteria:**
- HIGH: Same source IP appears in both Wazuh failed auth AND Zeek lateral connections to multiple targets
- MEDIUM: >5 failed auth attempts from single source to multiple targets
- Correlate: Check if source IP has any Suricata alerts in same timeframe

---

## H04 -- Data Exfiltration

**Hypothesis:** A compromised host is exfiltrating data via large outbound transfers.
**MITRE:** T1041 (Exfil Over C2), T1048 (Exfil Over Alt Protocol)
**Data source:** Zeek conn.log (`zeek-*`, dataset: zeek.connection)
**Token budget:** 1 ES query

```json
GET /zeek-*/_search
{
  "size": 20,
  "_source": ["source.address","destination.address","destination.port","network.protocol","source.bytes","event.duration","@timestamp"],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"range": {"source.bytes": {"gte": 52428800}}}
      ],
      "must_not": [
        {"terms": {"destination.port": [53, 123, 5353]}},
        {"wildcard": {"destination.address": "10.*"}}
      ]
    }
  },
  "sort": [{"source.bytes": {"order": "desc"}}]
}
```

**Verdict criteria:**
- HIGH: >50MB to single external destination from internal host, not in baseline
- MEDIUM: >10MB to unusual destination or using non-standard service
- Exclude: known backup endpoints, update servers, cloud storage in baseline

---

## H05 - DGA Detection

**Hypothesis:** Malware on an internal host is generating algorithmically created domain names.
**MITRE:** T1568 (Dynamic Resolution)
**Data source:** Zeek dns.log (`zeek-*`, dataset: zeek.dns)
**Token budget:** 1 Elasticsearch query

```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-4h"}}},
        {"term": {"zeek.dns.rcode_name": "NXDOMAIN"}}
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": {"field": "source.address", "size": 20},
      "aggs": {
        "nxdomain_count": {"value_count": {"field": "@timestamp"}},
        "unique_queries": {"cardinality": {"field": "dns.question.name"}},
        "sample_queries": {"terms": {"field": "dns.question.name", "size": 5}}
      }
    }
  }
}
```

**Verdict criteria:**
- HIGH: >50 NXDOMAIN responses for single host with high unique query count
- Inspect sample queries: long random strings, unusual TLDs = DGA indicators
- MEDIUM: 20-50 NXDOMAIN with diverse query patterns
- Exclude: typo domains, dev environments with test DNS

---

## H06 - TLS Anomalies

**Hypothesis:** C2 communications using TLS with self-signed, expired, or unusual certificates.
**MITRE:** T1573 (Encrypted Channel)
**Data source:** Zeek ssl.log (`zeek-*`, dataset: zeek.ssl)
**Token budget:** 1 Elasticsearch query

```json
GET /zeek-*/_search
{
  "size": 20,
  "_source": ["source.address","destination.address","destination.port","zeek.ssl.server.name","tls.server.issuer","tls.server.subject","zeek.ssl.validation_status","tls.client.ja3","tls.server.ja3s","@timestamp"],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ],
      "should": [
        {"term": {"zeek.ssl.validation_status": "self signed certificate"}},
        {"term": {"zeek.ssl.validation_status": "certificate has expired"}},
        {"term": {"zeek.ssl.validation_status": "unable to get local issuer certificate"}}
      ],
      "minimum_should_match": 1,
      "must_not": [
        {"wildcard": {"destination.address": "10.*"}}
      ]
    }
  }
}
```

**Verdict criteria:**
- HIGH: Self-signed cert to external IP on non-standard port
- MEDIUM: Expired cert or unknown issuer to external destination
- Cross-reference JA3 hashes against known malicious JA3 lists
- Exclude: internal CAs, dev/test environments with known self-signed certs

---

## H07 - DNS Tunneling

**Hypothesis:** Data exfiltration or C2 via DNS TXT/CNAME record abuse.
**MITRE:** T1071.004 (DNS), T1048 (Exfil Over Alt Protocol)
**Data source:** Zeek dns.log (`zeek-*`, dataset: zeek.dns)
**Token budget:** 1 Elasticsearch query

```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-4h"}}},
        {"terms": {"zeek.dns.qtype_name": ["TXT","CNAME","MX","NULL"]}}
      ]
    }
  },
  "aggs": {
    "by_host_domain": {
      "composite": {
        "size": 50,
        "sources": [
          {"host": {"terms": {"field": "source.address"}}},
          {"domain": {"terms": {"field": "dns.question.name"}}}
        ]
      },
      "aggs": {
        "count": {"value_count": {"field": "@timestamp"}},
        "query_types": {"terms": {"field": "dns.question.type"}}
      }
    }
  }
}
```

**Verdict criteria:**
- HIGH: >50 TXT/NULL queries to single domain from single host
- Inspect query subdomains: base64-like strings = tunneling indicator
- MEDIUM: High TXT query volume to unusual TLDs
- Exclude: SPF/DKIM validation queries, known SaaS services

---

## H08 - Port Scan Detection (Internal)

**Hypothesis:** A compromised internal host is scanning the network for services.
**MITRE:** T1046 (Network Service Discovery)
**Data source:** Zeek conn.log (`zeek-*`, dataset: zeek.connection)
**Token budget:** 1 Elasticsearch query

```json
GET /zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"wildcard": {"source.address": "10.*"}},
        {"terms": {"zeek.connection.state": ["S0","REJ","RSTO"]}}
      ]
    }
  },
  "aggs": {
    "by_scanner": {
      "terms": {"field": "source.address", "size": 10},
      "aggs": {
        "unique_targets": {"cardinality": {"field": "destination.address"}},
        "unique_ports": {"cardinality": {"field": "destination.port"}},
        "top_ports": {"terms": {"field": "destination.port", "size": 10}}
      }
    }
  }
}
```

**Verdict criteria:**
- HIGH: Single host connecting to >20 unique targets OR >50 unique ports in 1 hour
- MEDIUM: 10-20 unique targets with rejected/reset connections
- Correlate with Suricata scan-related signatures

---

## Hunt Rotation Schedule

| Rotation | Hunt | Frequency |
|---|---|---|
| 1 | H01: DNS Beaconing | Every 2 heartbeats |
| 2 | H02: C2 Jitter | Every 3 heartbeats |
| 3 | H03: Lateral Movement | Every 2 heartbeats |
| 4 | H04: Data Exfiltration | Every 4 heartbeats |
| 5 | H05: DGA Detection | Every 3 heartbeats |
| 6 | H06: TLS Anomalies | Every 4 heartbeats |
| 7 | H07: DNS Tunneling | Every 3 heartbeats |
| 8 | H08: Internal Port Scan | Every 2 heartbeats |
