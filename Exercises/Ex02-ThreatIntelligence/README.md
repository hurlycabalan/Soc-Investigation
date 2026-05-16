# Exercise 02 — Threat Intelligence: Microsoft Defender Threat Intelligence (MDTI)

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%)  
**Difficulty:** Beginner | **Status:** ✅ Complete

---

## What This Exercise Covers

Threat intelligence turns raw IOCs into actionable detections. This exercise covers enabling the **MDTI data connector**, querying the `ThreatIntelIndicators` table, and correlating TI indicators against live telemetry using `join`. In a real SOC, TI matching is how you instantly know if a connection is to a **known-malicious IP** — before you even open the incident.

---

## Data Sources Used

| Table | Source | Purpose |
|-------|--------|---------|
| `ThreatIntelIndicators` | MDTI connector | Microsoft-curated IOC feed (IPs, domains, hashes) |
| `CommonSecurityLog` | Palo Alto NGFW | Firewall traffic to match against TI IPs |
| `AWSCloudTrail` | AWS | Cloud API calls to match against TI IPs |

---

## Lab Steps Completed

### Step 1 — Install the Threat Intelligence Solution and Enable MDTI Connector

Installed the **Threat Intelligence (NEW)** solution from Content Hub, then enabled the MDTI data connector.

**Navigation path:**  
Microsoft Sentinel → Content management → Content hub → Search "Threat Intelligence" → Install/Update

Then:  
Microsoft Sentinel → Configuration → Data connectors → Search "Microsoft Defender Threat Intelligence" → Open connector page → **Connect**

📸 *[Screenshot — Content Hub showing Threat Intelligence (NEW) solution installed]*  
📸 *[Screenshot — MDTI connector status showing "Connected"]*

> **Lab note:** Table name is `ThreatIntelIndicators` — NOT the legacy `ThreatIntelligenceIndicator`. This is a common exam and lab trap. Always use the current table name.

---

### Step 2 — Verify Indicator Ingestion

Confirmed indicators were flowing into the workspace after connector activation.

```kql
ThreatIntelIndicators
| summarize IndicatorCount = count() by ObservableKey
| sort by IndicatorCount desc
```

Expected observable types: `ipv4-addr`, `domain-name`, `url`, file hash patterns.

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    ObservableKey,
    ObservableValue,
    Confidence,
    IsActive,
    ValidFrom,
    ValidUntil
| sort by TimeGenerated desc
| take 20
```

📸 *[Screenshot — ThreatIntelIndicators query results showing ObservableKey distribution]*

---

### Step 3 — Understand the ThreatIntelIndicators Schema

Key columns used in detection queries:

| Column | Description | Example |
|--------|-------------|---------|
| `ObservableKey` | IOC type | `ipv4-addr`, `domain-name` |
| `ObservableValue` | Actual IOC value | `198.51.100.42` |
| `Confidence` | Confidence score (0–100) | `85` |
| `IsActive` | Currently active indicator | `true` |
| `ValidFrom` / `ValidUntil` | Validity window | Datetime |

**Best practice filters for production use:**  
Always add `| where IsActive == true` and `| where Confidence > 50` — this eliminates stale and low-quality indicators that drive false positives.

---

### Step 4 — Match TI Indicators Against Firewall Telemetry

Joined active TI IP indicators against Palo Alto firewall logs to detect connections to known-malicious infrastructure.

```kql
let ti_ips = ThreatIntelIndicators
| where IsActive == true
| where ObservableKey == "ipv4-addr"
| where Confidence > 50
| project ObservableValue, Confidence;
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| join kind=inner ti_ips on $left.DestinationIP == $right.ObservableValue
| project
    TimeGenerated,
    SourceIP,
    DestinationIP,
    DeviceAction,
    TI_Confidence = Confidence
| sort by TimeGenerated desc
```

**Result in lab environment:** Query returned empty results — expected. The lab uses synthetic IP addresses that do not appear in Microsoft's real-world TI feed.

> **Key learning:** Empty results ≠ broken query. In a production environment with real traffic, this `join kind=inner` pattern is exactly how you detect connections to known-bad IPs. The pattern is what matters, not the result count.

Also ran the same join against AWS CloudTrail:

```kql
let ti_ips = ThreatIntelIndicators
| where IsActive == true
| where ObservableKey == "ipv4-addr"
| where Confidence > 50
| project ObservableValue, Confidence;
AWSCloudTrail
| join kind=inner ti_ips on $left.SourceIpAddress == $right.ObservableValue
| project
    TimeGenerated,
    UserIdentityUserName,
    EventName,
    SourceIpAddress,
    TI_Confidence = Confidence
| sort by TimeGenerated desc
```

📸 *[Screenshot — TI join query against CommonSecurityLog, showing empty result with query correct]*

---

### Step 5 — Explore TI Coverage Statistics

Reviewed indicator coverage by type and age distribution.

```kql
ThreatIntelIndicators
| where IsActive == true
| summarize
    TotalIndicators = count(),
    AvgConfidence = avg(Confidence)
    by ObservableKey
| sort by TotalIndicators desc
```

📸 *[Screenshot — TI coverage summary showing indicator count and avg confidence by type]*

---

### Step 6 — Review the Threat Intelligence Blade

Navigated to the TI blade for the UI view of ingested indicators.

**Navigation path:**  
Microsoft Sentinel → Threat management → Threat intelligence

Reviewed indicator details including associated threat actors, campaigns, and confidence scores.

📸 *[Screenshot — Threat Intelligence blade showing ingested indicators with filter options]*

---

## MailGuard TI Correlation (Lab Extension)

The lab also contains `MailGuard365_Threats_CL` with phishing sender IPs. Cross-reference against TI:

```kql
let ti_ips = ThreatIntelIndicators
| where IsActive == true
| where ObservableKey == "ipv4-addr"
| where Confidence > 50
| project TI_IP = ObservableValue, Confidence;
MailGuard365_Threats_CL
| summarize MailCount = count() by SenderIP
| join kind=inner ti_ips on $left.SenderIP == $right.TI_IP
| project SenderIP, MailCount, TI_Confidence = Confidence
| sort by MailCount desc
```

**Why this matters:** If the phishing sender IP matches a TI indicator, that's an immediate High/Critical severity escalation — you have both behavioural evidence AND external validation.

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| Enabling MDTI data connector | D3 Sentinel | Data connector configuration |
| `ThreatIntelIndicators` table | D3 Sentinel | TI table schema and queries |
| `join kind=inner` for TI matching | D3 Sentinel | KQL join operations |
| `IsActive`, `Confidence` filters | D3 Sentinel | TI indicator quality filtering |
| Threat Intelligence blade | D3 Sentinel | Sentinel UI navigation |

**Key exam distinction:** `ThreatIntelIndicators` is the **current** MDTI table. `ThreatIntelligenceIndicator` is the **legacy** table from older connectors. The exam tests both — know which connector uses which table.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|-----------|----|-----------|
| Indicator Removal / Defense Evasion | T1562 | TI helps detect when known-bad actors try to blend in |
| Command and Control | T1071 | Domain-based TI indicators detect C2 beaconing |
| Phishing | T1566 | Email sender IP TI matching |

---

## Key Takeaways

- MDTI is **free** with Microsoft Sentinel — no additional licence required
- Always filter `IsActive == true` AND `Confidence > 50` before joining TI against telemetry
- `join kind=inner` = only show rows where TI match exists. Use `join kind=leftouter` if you want all events + TI enrichment where available
- Empty results in the lab are expected — the pattern is what you're learning, not the hit count
- The TI blade in Sentinel provides a UI for browsing indicators — useful for analyst investigation, not just KQL
- Watchlist (Ex08) and TI are both lookup enrichment mechanisms — key difference: TI is external threat data, watchlists are internal business context
