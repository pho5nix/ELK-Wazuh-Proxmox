# HEARTBEAT.md - TraceMarshal Autonomous Checklist

> Checked every heartbeat cycle (default: 30 minutes). Pick 2-3 items per cycle. Rotate through the list. If nothing actionable, respond HEARTBEAT_OK. Token budget per heartbeat: max 4 ES queries total.

---

## Priority 1 (Every Cycle)

- [ ] **Pipeline Health (UC9):** Query doc count per index for last 30 min. Compare against baselines in MEMORY.md. Alert immediately if any source drops below 50% of average.

## Priority 2 (Rotate, 2-3x per day)

- [ ] **High-Severity Triage (UC4):** Query logs-wazuh-alerts-* for wazuh.rule.level >= 12 in last 30 min. If found, run quick correlation against Suricata and Zeek for the affected host. Alert with summary.
    
- [ ] **Threat Hunt (UC2):** Run next hypothesis from rotation. Refer to `skills/siem-soc-analyst/kb/hunt-library.md` for queries. Current rotation order:
    
    1. DNS beaconing (Zeek dns)
    2. C2 jitter detection (Zeek conn)
    3. Lateral movement (Wazuh + Zeek conn)
    4. Data exfiltration (Zeek conn, outbound >50MB)
    5. DGA detection (Zeek dns, high entropy)
    6. TLS anomaly (Zeek ssl, self-signed/expired)
    
    - Last completed: - (update after each run)
    - Next in rotation: 1
- [ ] **IOC Check (UC7):** Extract new IOCs from high-confidence alerts in last 30 min. If new IOCs found, queue for enrichment in next main session (web search needed).
    

## Priority 3 (1-2x per day)

- [ ] **pfBlockerNG Validation (UC3):** Aggregate blocks from last 4 hours by feed. Flag any feed with >80% of total blocks (possible false positive storm). Flag any new IPs/domains not seen before.
    
- [ ] **Protocol Anomaly (UC8):** Quick check Zeek conn.log for services not in baseline (MEMORY.md). Flag new protocols, unusual ports, or connections >1hr duration.
    

## Priority 4 (Weekly via cron, not heartbeat)

- [ ] **Detection Gap Analysis (UC5):** Run monthly via cron. Not a heartbeat task.
- [ ] **Reporting (UC6):** Daily/weekly via cron. Not a heartbeat task.

---

## Heartbeat Rules

1. Pipeline health (UC9) runs every cycle. Non-negotiable.
2. Remaining slots: pick 1-2 from Priority 2 or Priority 3, rotating.
3. If a Priority 2 check finds something actionable, skip Priority 3 for this cycle and focus on the finding.
4. If high-severity triage (UC4) finds alerts, that takes precedence over hunts.
5. IOC enrichment requiring web search: note the IOC in memory/ioc-tracker.md and enrich during next interactive session or cron run (heartbeat should not burn tokens on web searches).
6. Log what was checked and what was found in memory/YYYY-MM-DD.md after each heartbeat.
7. If all checks are clean, respond HEARTBEAT_OK. Do not generate filler.

---

## Rotation Tracker

|Cycle|Date|Time|Checks Run|Findings|
|---|---|---|---|---|
|--|--|--|--|--|
