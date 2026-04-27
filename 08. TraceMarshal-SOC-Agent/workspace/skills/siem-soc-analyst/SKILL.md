
# SKILL.md - SIEM SOC Analyst

## name: siem-soc-analyst
 description: "Autonomous SOC analyst skill for Red-Threat-Redemption SIEM. Executes threat hunting, alert triage, cross-source correlation, IOC enrichment, detection gap analysis, and automated reporting across Elasticsearch indices from Suricata, Zeek, Wazuh, pfSense, and pfBlockerNG." user-invocable: true

## Purpose

Provide autonomous security operations for the Red-Threat-Redemption SIEM stack. This skill enables the agent to query, correlate, hunt, triage, and report across all ingested log sources in Elasticsearch.

## Knowledge Base  
**Knowledge base at `skills/siem-soc-analyst/kb/` (see kb/README.md for index).**

Before constructing queries or running workflows, check the relevant kb file:

- `/hunt` → read `skills/siem-soc-analyst/kb/hunt-library.md` for pre-built hypotheses and queries.
- `/correlate`, `/ir` → read `skills/siem-soc-analyst/kb/correlation-playbooks.md` for step-by-step procedures.
- `/ioc-enrich` → read `skills/siem-soc-analyst/kb/ioc-enrichment-guide.md` for enrichment sources and verdict criteria.
- `/gaps` → read `skills/siem-soc-analyst/kb/mitre-attack-map.md` for coverage mapping and `skills/siem-soc-analyst/kb/detection-rules-reference.md` for rule context.
- `/triage` → read `skills/siem-soc-analyst/kb/detection-rules-reference.md` for rule ID context.
- Any query construction → read `skills/siem-soc-analyst/kb/es-query-cookbook.md` for reusable patterns.
- Any field question → read `skills/siem-soc-analyst/kb/log-field-schema.md` for exact field names and types.

## Commands

### /hunt [hypothesis]

Execute a threat hunt from the hunt library or a custom hypothesis.

**Built-in hypotheses:**

- `dns-beaconing` -- Flag domains with >100 queries from single host in 1hr.
- `c2-jitter` -- Detect periodic outbound connections with low interval variance.
- `lateral-movement` -- Correlate failed auth (Wazuh) with internal SMB/RDP (Zeek).
- `exfiltration` -- Outbound transfers >50MB to non-baseline destinations.
- `dga` -- High-entropy domain queries in Zeek dns.log.
- `tls-anomaly` -- Self-signed certs, expired certs, unusual JA3 hashes.

**Custom:** `/hunt "hosts connecting to .ru TLDs in last 24h"`

**Token budget:** Max 3 ES queries per hunt. Use aggregations first.

### /triage [timerange]

Triage Wazuh alerts with contextual enrichment.

1. Pull alerts with rule.level >= 10 from specified timerange (default: last 4h).
2. Group by rule.id + agent.name.
3. For top 5 clusters, correlate against Suricata and Zeek.
4. Output prioritized table: severity, host, rule, MITRE tactic, correlated evidence count.

**Token budget:** Max 5 Elasticsearch queries. Use aggregations for grouping.

### /correlate [ip|domain]

Full cross-source correlation for a given indicator.

1. Search indicator across all indices.
2. Build chronological timeline.
3. Map to MITRE ATT&CK.
4. Output: timeline table + assessment (high/medium/low confidence).

**Token budget:** Max 4 Elasticsearch queries (one multi-index, then targeted pivots).

### /ioc-enrich [ip|domain|hash]

Enrich an indicator of compromise.

1. Web search for reputation (VirusTotal, AbuseIPDB, OTX).
2. Check internal indices for historical hits.
3. Output: reputation verdict, first/last seen internally, recommendation.

**Token budget:** Max 2 Elasticsearch queries + 2 web searches.

### /gaps

Detection coverage gap analysis.

1. Aggregate distinct MITRE technique IDs from Wazuh + Suricata (last 30 days).
2. Compare against ATT&CK Enterprise matrix.
3. Output: covered vs uncovered tactics table, top 5 gap recommendations.

**Token budget:** Max 2 Elasticsearch queries (aggregations only).

### /report [daily|weekly]

Generate SOC report.

**Daily:** Alert counts by source, top 10 IPs, top 10 signatures, top 10 Wazuh rules, pipeline health. **Weekly:** Daily aggregates + trends, hunt summary, coverage delta, IOC lifecycle.

**Token budget:** Max 6 Elasticsearch queries (all aggregations).

### /health

Check log pipeline health.

1. Doc count per index for last 1h vs 24h rolling average.
2. Flag sources below 50% average.
3. Output: status table (green/yellow/red per source).

**Token budget:** Max 1 Elasticsearch query (multi-index aggregation).

### /anomaly [protocol|port|service]

Zeek protocol anomaly detection.

1. Baseline: 7-day aggregation by service/port.
2. Current: last 24h same aggregation.
3. Flag deviations and new entries.

**Token budget:** Max 2 Elasticsearch queries (aggregations).

### /ir [alert-id|ip]

Trigger incident response playbook.

1. Collect all evidence across indices for the indicator.
2. Build incident timeline.
3. Classify by kill chain phase.
4. Output containment recommendations.
5. Save to `memory/incidents/YYYY-MM-DD-<id>.md`.

**Token budget:** Max 6 Elasticsearch queries.

### /feeds

pfBlockerNG feed validation.

1. Aggregate recent blocks by feed name.
2. Cross-reference top entries against threat intel.
3. Score feed quality.
4. Flag false positives.

**Token budget:** Max 2 Elasticsearch queries + 3 web searches.

## Output Formats

All outputs use compact structured format:

```
## Hunt: dns-beaconing | 2026-03-05 14:00 UTC
| Host | Domain | Count/1h | First Seen | Verdict |
|------|--------|----------|------------|---------|
| 10.0.1.42 | evil.example.com | 247 | 13:12 | HIGH |

MITRE: T1071.004 (DNS)
Action: Recommend block + correlate via /correlate 10.0.1.42
```

## Token Conservation Rules

1. Always use Elasticsearch aggregations before pulling raw documents.
2. Always specify `_source` filter with only required fields.
3. Limit result size to 20 unless user requests more.
4. Use multi-index queries for correlation instead of sequential single-index queries.
5. Summarize findings in tables, not prose.
6. Cache baseline values in MEMORY.md (update weekly, not per query).
7. Heartbeat checks: max 2-3 items per cycle, rotate through UC list.
8. Do not repeat query results the user has already seen in the same session.
