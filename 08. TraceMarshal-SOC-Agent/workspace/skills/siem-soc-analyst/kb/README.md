# Knowledge Base Index - TraceMarshal SOC Agent

> Static reference material. Read from here instead of burning tokens on web searches or rediscovering patterns. Files in this directory are loaded on-demand by the agent when a relevant use case is triggered. Do not modify during sessions. Update manually when infrastructure changes.

## Files

|File|Purpose|Referenced By|
|---|---|---|
|`skills/siem-soc-analyst/kb/mitre-attack-map.md`|MITRE ATT&CK Enterprise tactics/techniques mapped to stack data sources|UC4, UC5, /gaps, /triage|
|`skills/siem-soc-analyst/kb/hunt-library.md`|Threat hunt hypotheses with Elasticsearch query templates|UC2, /hunt, HEARTBEAT|
|`skills/siem-soc-analyst/kb/es-query-cookbook.md`|Reusable Elasticsearch query patterns for all indices|All UCs|
|`skills/siem-soc-analyst/kb/correlation-playbooks.md`|Step-by-step cross-source correlation procedures|UC1, UC10, /correlate, /ir|
|`skills/siem-soc-analyst/kb/ioc-enrichment-guide.md`|IOC types, enrichment sources, verdict criteria|UC7, /ioc-enrich|
|`skills/siem-soc-analyst/kb/log-field-schema.md`|Complete field mappings per index with ECS alignment|All UCs|
|`skills/siem-soc-analyst/kb/detection-rules-reference.md`|Suricata + Wazuh rule references and tuning notes|UC5, /gaps|
|`skills/siem-soc-analyst/kb/incident-response-templates.md`|IR report templates and containment checklists|UC10, /ir|

## Usage Rules

- Agent reads the specific kb file relevant to the current task, not the entire kb directory.
- If a query pattern exists in `skills/siem-soc-analyst/kb/es-query-cookbook.md`, use it instead of constructing from scratch.
- If a hunt hypothesis exists in `skills/siem-soc-analyst/kb/hunt-library.md`, use it instead of improvising.
- When running /gaps, cross-reference `skills/siem-soc-analyst/kb/mitre-attack-map.md` against live Elasticsearch data.
- When running /ir, use templates from `skills/siem-soc-analyst/kb/incident-response-templates.md`.
