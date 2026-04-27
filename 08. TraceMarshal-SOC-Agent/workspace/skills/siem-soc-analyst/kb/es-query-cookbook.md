# Elasticsearch Query Cookbook - TraceMarshal SOC Agent

> Reusable query patterns. Use these instead of constructing queries from scratch.
> All queries use _source filtering and size limits for token efficiency.

---

## Pattern 1: Count by Field (Cheapest Query)

```json
GET /<INDEX>/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "top": {"terms": {"field": "<FIELD>", "size": <N>}}
  }
}
```
Use: Top talkers, most common signatures, alert distribution.

---

## Pattern 2: Count by Two Fields (Composite)

```json
GET /<INDEX>/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "grouped": {
      "composite": {
        "size": 50,
        "sources": [
          {"field1": {"terms": {"field": "<FIELD1>"}}},
          {"field2": {"terms": {"field": "<FIELD2>"}}}
        ]
      },
      "aggs": {
        "count": {"value_count": {"field": "@timestamp"}}
      }
    }
  }
}
```
Use: Host+domain pairs, IP+port combos, agent+rule combos.

---

## Pattern 3: Time-Bucketed Trend

```json
GET /<INDEX>/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "over_time": {
      "date_histogram": {"field": "@timestamp", "fixed_interval": "<INTERVAL>"},
      "aggs": {"count": {"value_count": {"field": "_id"}}}
    }
  }
}
```
Use: Alert volume trends, ingestion rate monitoring, pattern identification.

---

## Pattern 4: Multi-Index IP Pivot

```json
GET /logs-suricata*,zeek-*,logs-wazuh-alerts*,logs-pfsense.filterlog*,logs-pfsense.pfblockerng*/_search
{
  "size": 20,
  "_source": ["src_ip","dest_ip","source.ip","destination.ip","source.address","destination.address","alert.signature","wazuh.rule.description","event.action","pfblocker.feed","@timestamp"],
  "query": {
    "bool": {
      "should": [
        {"term": {"src_ip": "<IP>"}},
        {"term": {"dest_ip": "<IP>"}},
        {"term": {"source.ip": "<IP>"}},
        {"term": {"destination.ip": "<IP>"}},
        {"term": {"source.address": "<IP>"}},
        {"term": {"destination.address": "<IP>"}},
        {"term": {"wazuh.data.srcip": "<IP>"}}
      ],
      "minimum_should_match": 1,
      "filter": [
        {"range": {"@timestamp": {"gte": "now-<RANGE>"}}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```
Use: Cross-source correlation for a specific IP. Single query across all indices.

---

## Pattern 5: Filtered Document Pull

```json
GET /<INDEX>/_search
{
  "size": 20,
  "_source": ["<FIELD1>","<FIELD2>","<FIELD3>","@timestamp"],
  "query": {
    "bool": {
      "must": [
        {"match": {"<FIELD>": "<VALUE>"}},
        {"range": {"@timestamp": {"gte": "now-<RANGE>"}}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```
Use: Pull specific events matching criteria. Always specify _source.

---

## Pattern 6: Cardinality (Unique Count)

```json
GET /<INDEX>/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "unique_count": {"cardinality": {"field": "<FIELD>"}}
  }
}
```
Use: Unique IPs, unique domains, unique signatures in a time window.

---

## Pattern 7: Pipeline Health Check (All Indices)

```json
GET /logs-suricata*,zeek-*,logs-wazuh-alerts*,logs-pfsense.filterlog*,logs-pfsense.pfblockerng*/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
  "aggs": {
    "by_index": {
      "terms": {"field": "_index", "size": 20},
      "aggs": {
        "doc_count": {"value_count": {"field": "_id"}}
      }
    }
  }
}
```
Use: UC9 heartbeat health check. Single query for all source health.

---

## Pattern 8: Wazuh High-Severity Triage

```json
GET /logs-wazuh-alerts*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
        {"range": {"wazuh.rule.level": {"gte": <MIN_LEVEL>}}}
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": {"field": "wazuh.rule.id", "size": 10},
      "aggs": {
        "description": {"terms": {"field": "wazuh.rule.description.keyword", "size": 1}},
        "agents": {"terms": {"field": "wazuh.agent.name", "size": 5}},
        "mitre": {"terms": {"field": "wazuh.rule.mitre.id", "size": 5}}
      }
    }
  }
}
```
Use: UC4 triage. Get rule clusters with affected hosts and MITRE mapping.

---

## Pattern 9: Suricata Alert Summary

```json
GET /logs-suricata*/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "by_signature": {
      "terms": {"field": "alert.signature.keyword", "size": 10},
      "aggs": {
        "severity": {"terms": {"field": "alert.severity", "size": 1}},
        "top_src": {"terms": {"field": "src_ip", "size": 3}},
        "top_dst": {"terms": {"field": "dest_ip", "size": 3}}
      }
    }
  }
}
```
Use: Top Suricata signatures with source/destination context.

---

## Pattern 10: pfBlockerNG Feed Analysis

```json
GET /logs-pfsense.pfblockerng*/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
  "aggs": {
    "by_feed": {
      "terms": {"field": "pfblocker.feed.keyword", "size": 10},
      "aggs": {
        "block_count": {"value_count": {"field": "_id"}},
        "by_type": {"terms": {"field": "pfblocker.type", "size": 2}},
        "unique_src": {"cardinality": {"field": "source.ip"}},
        "top_src": {"terms": {"field": "source.ip", "size": 5}}
      }
    }
  }
}
```
Use: UC3 feed validation. Feed-level block distribution with type breakdown.

---

## Pattern 11: Domain Pivot via Zeek DNS

```json
GET /zeek-*/_search
{
  "size": 20,
  "_source": ["source.address","dns.question.name","zeek.dns.answers","zeek.dns.qtype_name","zeek.dns.rcode_name","@timestamp"],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-<RANGE>"}}},
        {"wildcard": {"dns.question.name": "*<DOMAIN>*"}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "asc"}}]
}
```
Use: Find all hosts that resolved a specific domain.

---

## Pattern 12: MITRE Coverage Extraction

```json
GET /logs-wazuh-alerts*/_search
{
  "size": 0,
  "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
  "aggs": {
    "tactics": {
      "terms": {"field": "wazuh.rule.mitre.tactic.keyword", "size": 50},
      "aggs": {
        "techniques": {"terms": {"field": "wazuh.rule.mitre.id", "size": 50}}
      }
    }
  }
}
```
Use: UC5 /gaps. Extract which MITRE techniques have fired in last 30 days.

---

## Query Rules

1. Always replace `<PLACEHOLDERS>` before executing.
2. Time ranges: use `now-30m` for heartbeat, `now-4h` for triage, `now-24h` for hunts, `now-30d` for gap analysis.
3. `size: 0` = aggregation only, cheapest query.
4. `size: 20` = max doc pull unless operator requests more.
5. Always include `_source` on doc pulls.
6. Use `term` for exact match (keyword fields), `match` for analyzed text.
7. Adjust internal IP patterns (`10.*`, `192.168.*`, `172.16.*`) to match your actual network ranges.
