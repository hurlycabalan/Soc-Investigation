# Exercise 06 — Port Scan Detection & Threshold Tuning

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%) | D1 Defender XDR (25–30%)  
**Rule:** `Lab Stage E2 - Port Scan Detection (Palo Alto)`  
**Difficulty:** Beginner | **Status:** ✅ Complete

---

## What This Exercise Covers

A detection rule that fires on everything is worse than no rule — alert fatigue will bury real threats. This exercise covers **threshold tuning** for a port scan detection rule: establish a baseline from real data, choose a statistically informed threshold, and enrich the alert with context fields that help analysts triage faster. Threshold tuning is one of the most common day-to-day SOC analyst tasks in a mature environment.

---

## Attack Context

**MITRE T1046 — Network Service Discovery**

In the lab attack chain, the attacker scans the internal network after establishing a C2 channel (Stage 3.5), looking for lateral movement targets. Palo Alto logs denied connections with actions `drop`, `deny`, or `reset-both`. When `ApplicationProtocol == "incomplete"`, the session never completed — a strong indicator of scanning vs. legitimate traffic (legitimate applications complete their protocol handshake).

---

## Lab Steps Completed

### Step 1 — Establish a Baseline

Before setting any threshold, measured normal port diversity in the environment.

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Palo Alto Networks"
| where Activity in ("drop", "deny", "reset-both")
| where ApplicationProtocol == "incomplete"
| summarize DistinctPorts = dcount(DestinationPort) by SourceIP, DestinationIP
| summarize
    avg_ports = avg(DistinctPorts),
    p50 = percentile(DistinctPorts, 50),
    p90 = percentile(DistinctPorts, 90),
    p95 = percentile(DistinctPorts, 95),
    p99 = percentile(DistinctPorts, 99),
    max_ports = max(DistinctPorts)
```

> ⚠️ **Lab-level KQL** — uses `percentile()` which is beyond SC-200 exam scope. **SC-200 relevance:** the `dcount()` aggregation and threshold reasoning (`where DistinctPorts > X`) are core exam concepts.

**Baseline interpretation:**

| Percentile | Meaning | Threshold Decision |
|------------|---------|-------------------|
| p50 | Median behaviour = "normal" | Ignore — too low, every scanner triggers |
| p90 / p95 | Common higher-end activity | Start here for noisy environments |
| p99 | Rare but still observed | Good starting point for most environments |
| max_ports | Most extreme case | Don't use — one event becomes your threshold |

**Threshold selection rule:**

| p99 value | Start with threshold |
|-----------|---------------------|
| 10 or lower | `> 15` |
| 11–20 | `> 20` |
| Above 20 | p99 + 20%, rounded up |

**Threshold used in this lab:** `> 20`

📸 *[Screenshot — baseline query results showing percentile distribution of DistinctPorts]*

---

### Step 2 — Update the Rule with the Tuned Detection Query

Opened: Defender portal → Hunting → Custom detection rules → `Lab Stage E2 - Port Scan Detection (Palo Alto)` → Edit

Replaced the query with the tuned and enriched version:

```kql
CommonSecurityLog
| where TimeGenerated > ago(4h)
| where DeviceVendor == "Palo Alto Networks"
| where Activity in ("drop", "deny", "reset-both")
| where ApplicationProtocol == "incomplete"
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DistinctPorts = dcount(DestinationPort),
    PortList = make_set(DestinationPort, 25),
    EventCount = count()
    by SourceIP, DestinationIP, SourceHostName, SourceUserName
| extend ScanDurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| extend PortsPerMinute = iff(
    ScanDurationMinutes > 0,
    todouble(DistinctPorts) / todouble(ScanDurationMinutes),
    todouble(DistinctPorts)
)
| where DistinctPorts > 20
| project
    FirstSeen,
    LastSeen,
    SourceIP,
    DestinationIP,
    DistinctPorts,
    EventCount,
    ScanDurationMinutes,
    PortsPerMinute,
    PortList,
    SourceHostName,
    SourceUserName
| extend
    TimeGenerated = FirstSeen,
    AccountUpn = SourceUserName,
    DeviceName = SourceHostName,
    RemoteIP = DestinationIP,
    ReportId = tostring(hash_sha256(strcat(SourceIP, DestinationIP, tostring(DistinctPorts))))
```

> ⚠️ **Lab-level KQL** — uses `extend`, `iff()`, `todouble()`, `datetime_diff()`, `make_set()`, `hash_sha256()`. Beyond SC-200 exam scope. **SC-200 relevance:** `dcount()`, `summarize`, `where DistinctPorts > 20`, and `Activity in (...)` are all core exam-level operators.

📸 *[Screenshot — tuned query in Advanced Hunting editor with results showing enrichment fields]*

---

### Step 3 — Validate the Results

Post-update validation checklist:

- ✅ Query returns realistic scan candidates (not empty, not flooding)
- ✅ Alert volume is manageable (not overwhelming the incident queue)
- ✅ `PortList` and `DistinctPorts` visible in output — analyst can immediately see scope
- ✅ `PortsPerMinute` adds triage context — fast scan (>10/min) more likely adversarial
- ✅ No obvious FPs from legitimate multi-port services (load balancers, monitoring agents)

📸 *[Screenshot — validation query results showing scan candidates with PortsPerMinute context]*

---

## Enrichment Fields Explained — Why Each One Matters

| Field | What It Shows | Analyst Use |
|-------|--------------|-------------|
| `DistinctPorts` | Unique ports targeted | Scope of scan — more ports = more systematic |
| `PortList` | Which specific ports | Identifies scan type (SMB ports → lateral movement prep, web ports → service discovery) |
| `EventCount` | Total denied connections | Volume indicator — 20 distinct ports vs. 2000 packets are different stories |
| `ScanDurationMinutes` | How long the scan ran | Burst (60 sec) vs. slow scan (30 min) — slow scans evade threshold triggers |
| `PortsPerMinute` | Scan speed | >10/min → aggressive, likely automated. <1/min → slow scan, may be manual/stealthy |

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| `dcount()` for distinct value counting | D3 Sentinel | KQL aggregation functions |
| Threshold-based detection (`where > N`) | D3 Sentinel | Detection rule logic |
| `Activity in (...)` multi-value filter | D3 Sentinel | KQL operators |
| Custom detection rule editing | D1 Defender XDR | Rule modification |
| Lookback alignment (4h query, 1h schedule) | D1 Defender XDR | Rule schedule and frequency |

**Key exam rule:** Lookback period must be ≥ (schedule frequency × buffer factor). For a rule running every 1 hour with a 4-hour lookback, there's a 4× overlap. This prevents missed events between runs but creates some alert duplication — acceptable tradeoff for coverage.

---

## MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Network Service Discovery | T1046 | Adversary scanning network to find open services before lateral movement |

---

## Key Takeaways

- **Measure before you tune** — running a baseline query first prevents setting thresholds too low (noise) or too high (misses)
- `dcount()` is the go-to function for detecting anomalous diversity — distinct ports, distinct users, distinct countries
- `make_set()` provides analyst context in the alert — seeing *which* ports were scanned is more useful than just the count
- `ApplicationProtocol == "incomplete"` is the key filter for scan traffic in Palo Alto — completed sessions are legitimate traffic
- Threshold tuning is iterative — start at p99 + buffer, review FPs after 1 week, adjust as needed
- A scan that's **slow** (low PortsPerMinute) might still exceed the DistinctPorts threshold — time-based enrichment catches what count-only thresholds miss
