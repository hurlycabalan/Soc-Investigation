# Exercise 01 — Exploration: Hunting Across Your Data

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%) | D1 Defender XDR (25–30%)  
**Difficulty:** Beginner | **Status:** ✅ Complete

---

## What This Exercise Covers

Before building detections, a SOC analyst's first job is to understand the data — what tables exist, what events they contain, and what patterns are worth alerting on. This exercise covers **Advanced Hunting** data exploration across six data sources and converts a hunting query into a **custom detection rule**. This is the most foundational Sentinel skill: you can't detect what you haven't explored.

---

## Data Sources Explored

| Table | Source | Data Type |
|-------|--------|-----------|
| `CrowdStrikeAlerts` | CrowdStrike EDR | Endpoint alerts with MITRE tactic mapping |
| `CrowdStrikeDetections` | CrowdStrike EDR | Raw detection events |
| `CommonSecurityLog` | Palo Alto NGFW | Firewall traffic (allow/deny/drop) |
| `OktaV2_CL` | Okta IdP | Identity and authentication events |
| `AWSCloudTrail` | AWS | Cloud API call audit log |
| `MailGuard365_Threats_CL` | MailGuard | Email threat telemetry |

---

## Lab Steps Completed

### Step 1 — Discover Available Tables

Ran `search *` to inventory all tables with data and event counts.

```kql
search *
| summarize EventCount = count() by $table
| sort by EventCount desc
```

**Why this query:** Fastest way to see the entire data landscape. `$table` is a special column that returns the source table name — it only works with `search *`. This is the SOC equivalent of opening a new case file and checking what evidence you have.

📸 *[Screenshot — table discovery results showing EventCount by table]*

---

### Step 2 — Explore CrowdStrike Endpoint Alerts

Summarised alerts by tactic to understand the attack's MITRE footprint.

```kql
CrowdStrikeAlerts
| summarize AlertCount = count() by Name, SeverityName, Tactic
| sort by AlertCount desc
```

**Key insight:** Multiple MITRE tactics visible (Initial Access → Credential Access → Lateral Movement) on the same device = multi-stage compromise. Single-tactic alerts can be noise. Multi-tactic on one host is a high-confidence TP signal.

📸 *[Screenshot — CrowdStrikeAlerts summarised by Tactic, showing multi-stage pattern]*

---

### Step 3 — Explore Palo Alto Firewall Traffic

Identified blocked connections and potential reconnaissance traffic.

```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where Activity in ("drop", "deny", "reset-both")
| summarize
    BlockedConnections = count(),
    TargetedPorts = dcount(DestinationPort)
    by SourceIP
| sort by BlockedConnections desc
| take 10
```

**Why `Activity in (...)`:** Palo Alto uses multiple action values for blocked traffic. The `in` operator checks all three in a single filter — cleaner than chaining `or` conditions. On the SC-200 exam, `in` is a key operator for multi-value filtering.

📸 *[Screenshot — top source IPs by blocked connections, highlighting scanner candidates]*

---

### Step 4 — Explore Okta Identity Events

Checked for failed login patterns and MFA-related events.

```kql
OktaV2_CL
| where OriginalOutcomeResult == "FAILURE"
| summarize
    FailedAttempts = count(),
    DistinctIPs = dcount(SrcIpAddr),
    Countries = make_set(SrcGeoCountry)
    by ActorUsername
| sort by FailedAttempts desc
```

**Lab note:** Table is `OktaV2_CL` — NOT `OktaSystemLogs`. The `_CL` suffix indicates a custom log table ingested via the Okta connector. This distinction matters in the lab and on the exam.

📸 *[Screenshot — Okta failed login summary by user, showing DistinctIPs and Countries]*

---

### Step 5 — Explore AWS CloudTrail

Looked for failed API calls indicating reconnaissance or privilege escalation attempts.

```kql
AWSCloudTrail
| where isnotempty(ErrorCode)
| summarize
    FailedCalls = count(),
    ErrorCodes = make_set(ErrorCode)
    by UserIdentityUserName, EventName
| sort by FailedCalls desc
```

**Why error codes matter:** `AccessDenied` errors on privileged API calls (e.g., `ListBuckets`, `GetSecretValue`) are classic signs of an attacker probing permissions boundaries.

📸 *[Screenshot — AWS failed API calls showing ErrorCode distribution]*

---

### Step 6 — Build a Cross-Source Timeline

Combined signals from CrowdStrike, Palo Alto, Okta, and AWS into a single chronological view.

```kql
union
    (CrowdStrikeAlerts
    | where SeverityName in ("Critical", "High")
    | project TimeGenerated, Source = "CrowdStrike", Activity = Name, Severity = SeverityName),
    (CommonSecurityLog
    | where DeviceVendor == "Palo Alto Networks"
    | where DeviceEventClassID == "THREAT"
    | project TimeGenerated, Source = "Palo Alto", Activity = Activity, Severity = LogSeverity),
    (OktaV2_CL
    | where EventOriginalType has "mfa" or EventOriginalType has "deactivate"
    | project TimeGenerated, Source = "Okta", Activity = EventOriginalType, Severity = EventSeverity),
    (AWSCloudTrail
    | where EventName in ("CreateUser", "AttachUserPolicy", "CreateAccessKey", "StopLogging")
    | project TimeGenerated, Source = "AWS", Activity = EventName, Severity = "High")
| sort by TimeGenerated asc
```

**Why this matters:** The `union` operator is the multi-source foundation of all kill-chain investigations. You normalize each source into matching columns (`TimeGenerated`, `Source`, `Activity`, `Severity`), then sort by time. This IS the investigation timeline.

📸 *[Screenshot — unified timeline showing multi-source attack sequence in chronological order]*

---

### Step 7 — Write the Detection Query

Query to detect endpoints with CrowdStrike alerts spanning ≥3 MITRE ATT&CK tactics within 4 hours — a strong compromise indicator.

```kql
CrowdStrikeAlerts
| where TimeGenerated > ago(4h)
| where SeverityName in ("Critical", "High")
| summarize
    TacticCount = dcount(Tactic),
    Tactics = make_set(Tactic),
    AlertNames = make_set(Name, 10),
    AlertCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName = tostring(split(DisplayName, " on ")[-1]), AgentId
| where TacticCount >= 3
| project
    TimeGenerated = FirstSeen,
    DeviceName,
    TacticCount,
    Tactics,
    AlertNames,
    AlertCount,
    FirstSeen,
    LastSeen
```

> ⚠️ **Lab-level KQL** — uses `dcount()`, `make_set()`, `tostring()`, `split()`, and array indexing which are beyond SC-200 exam scope. **SC-200 exam relevance:** the `where TacticCount >= 3` threshold logic and `summarize` aggregation pattern are core exam concepts.

📸 *[Screenshot — query results showing compromised device with TacticCount ≥ 3]*

---

### Step 8 — Create the Custom Detection Rule

Converted the hunting query into a scheduled detection rule.

**Rule configuration:**

| Field | Value |
|-------|-------|
| **Name** | `Lab Stage E1 - Multi-Tactic Compromise on Single Device` |
| **Severity** | High |
| **Frequency** | Every 1 hour |
| **Lookback** | 4 hours |
| **Entity mapping** | Device → `DeviceName` |

📸 *[Screenshot — custom detection rule creation wizard with settings filled in]*

---

### Step 9 — Verify the Rule Fires

Navigated to Hunting → Custom detection rules → ran the rule manually → confirmed it appears in Triggered alerts.

📸 *[Screenshot — rule appearing in Custom Detection Rules list with Enabled status]*  
📸 *[Screenshot — Triggered alerts showing rule fired with correct entity]*

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| `search *` for data discovery | D3 Sentinel | Advanced Hunting exploration |
| `summarize` with aggregation | D3 Sentinel | KQL fundamentals |
| `union` for multi-source queries | D3 Sentinel | Cross-table hunting |
| `in` operator for multi-value filter | D3 Sentinel | KQL operators |
| Custom detection rule creation | D1 Defender XDR | Custom detections |
| Schedule, lookback, entity mapping | D1 Defender XDR | Rule configuration |

**Key exam distinction:** Custom detection rules live in **Microsoft Defender portal → Advanced Hunting** and produce **Alerts**. Sentinel analytics rules live in **Sentinel → Analytics** and produce **Incidents**. Know which UI, which output.

---

## MITRE ATT&CK

| Technique | ID | Detection Logic |
|-----------|----|-----------------|
| Multi-stage attack pattern | Multiple | TacticCount ≥ 3 on single device |
| Network Service Discovery | T1046 | Port scan detection in Palo Alto |
| Credential Access | T1003 | CrowdStrike alert tactic classification |

---

## Key Takeaways

- `search *` is the fastest table discovery tool — use it first when unfamiliar with a workspace
- `dcount()` counts **distinct** values — use it to detect diversity (distinct ports, distinct tactics, distinct countries)
- `union` normalizes multiple tables into a single timeline — the foundation of all multi-source investigations
- A good detection combines **aggregation** (`summarize`) with a **threshold** (`where TacticCount >= 3`)
- Custom detection rules require `TimeGenerated` and `ReportId` in the output — missing these will cause the rule creation to fail
- Always test hunt queries before converting to a rule — validate they return results first
