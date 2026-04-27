# IOC Tracker - TraceMarshal SOC Agent

> Active indicator of compromise tracking. Updated by: UC7 (/ioc-enrich), heartbeat IOC checks, incident response. Lifecycle states: EXTRACTED → ENRICHED → ACTIVE → EXPIRING → EXPIRED See skills/siem-soc-analyst/kb/ioc-enrichment-guide.md for verdict criteria and lifecycle rules.

---

## Active IOCs

|IOC|Type|Verdict|First Seen|Last Seen|Hit Count|State|Feed Action|Notes|
|---|---|---|---|---|---|---|---|---|
|--|--|--|--|--|--|--|--|--|

## Expiring IOCs (No hits >30 days)

|IOC|Type|Verdict|First Seen|Last Seen|Hit Count|State|Days Inactive|Action|
|---|---|---|---|---|---|---|---|---|
|--|--|--|--|--|--|--|--|--|

## Recently Expired (Last 30 days, for reference)

|IOC|Type|Original Verdict|Expired Date|Reason|
|---|---|---|---|---|
|--|--|--|--|--|

---

## Enrichment Queue

> IOCs extracted during heartbeat that need web search enrichment in next interactive session.

|IOC|Type|Source Alert|Extraction Date|Priority|
|---|---|---|---|---|
|--|--|--|--|--|

---

## Feed Recommendations Pending

> IOCs confirmed malicious, recommended for pfBlockerNG but not yet added by operator.

|IOC|Type|Verdict|Recommended Date|Target Feed|Operator Action|
|---|---|---|---|---|---|
|--|--|--|--|--|PENDING|

---

## Statistics

|Metric|Value|Last Updated|
|---|---|---|
|Total active IOCs|0|--|
|Total enrichment queue|0|--|
|Total expired (all time)|0|--|
|Pending feed recommendations|0|--|
|Last full lifecycle review|--|--|
