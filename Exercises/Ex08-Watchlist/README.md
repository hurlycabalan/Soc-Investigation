# Exercise 08 — Watchlist Integration

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%)  
**Rule:** `Lab Stage E4 - Console Login Without MFA (AWS)`  
**Difficulty:** Intermediate | **Status:** ✅ Complete

---

## What This Exercise Covers

A raw detection rule for "AWS console login without MFA" fires for every non-MFA login, regardless of which service was accessed. An IAM console login without MFA is very different from a KMS console login without MFA — one manages access permissions, the other manages encryption keys for the entire organisation. **Watchlists** add business context that log data alone cannot provide, letting you prioritise alerts based on what actually matters to the business. This is how SOC analysts move from alert volume to alert quality.

---

## What is a Watchlist?

A **Sentinel watchlist** is a named CSV lookup table stored in the workspace. Once uploaded, it becomes queryable in any KQL expression via:

```kql
_GetWatchlist('WatchlistAlias')
```

No joins to external databases, no API calls — the data is pre-loaded and indexed.

**Watchlist vs. Threat Intelligence (`ThreatIntelIndicators`):**

| | Watchlist | ThreatIntelIndicators |
|--|-----------|----------------------|
| **Source** | Internal — you upload the data | External — Microsoft/MDTI feed |
| **Content** | Business context (VIP users, critical systems, departments) | Threat IOCs (malicious IPs, domains, hashes) |
| **Update frequency** | Manual (refreshes every 12 days) | Continuous (MDTI connector) |
| **Use case** | Enrich alerts with business knowledge | Match against known-bad indicators |

---

## Lab Steps Completed

### Step 1 — Create the Watchlist CSV

Created `BusinessCriticalAWS.csv` mapping AWS API event sources to service names and criticality.

```csv
EventSource,ServiceName,Criticality
iam.amazonaws.com,IAM,Critical
s3.amazonaws.com,S3,High
ec2.amazonaws.com,EC2,High
lambda.amazonaws.com,Lambda,Medium
kms.amazonaws.com,KMS,Critical
sts.amazonaws.com,STS,Critical
organizations.amazonaws.com,Organizations,Critical
cloudtrail.amazonaws.com,CloudTrail,High
```

**Criticality rationale:**

| Service | Criticality | Why |
|---------|------------|-----|
| IAM | Critical | Controls all access permissions — full blast radius if compromised |
| KMS | Critical | Manages encryption keys — attacker access = data exposure |
| STS | Critical | Issues temporary credentials — pivot point for lateral movement |
| Organizations | Critical | Manages the entire AWS account hierarchy |
| S3 | High | Primary data store — exfiltration risk |
| EC2 | High | Compute — ransomware and cryptomining target |
| CloudTrail | High | Audit log — attacker would want to stop logging here |
| Lambda | Medium | Serverless functions — lower immediate blast radius |

📸 *[Screenshot — BusinessCriticalAWS.csv file created with all 8 service entries]*

---

### Step 2 — Upload the Watchlist to Sentinel

**Navigation path:**  
Microsoft Sentinel → Configuration → Watchlist → + New

**Watchlist configuration:**

| Field | Value |
|-------|-------|
| **Name** | `BusinessCriticalAWS` |
| **Alias** | `BusinessCriticalAWS` |
| **Description** | Business-critical AWS services for detection enrichment |
| **Source type** | Local file |
| **File** | `BusinessCriticalAWS.csv` |
| **SearchKey** | `EventSource` |

Clicked **Create** → waited 1–2 minutes for availability.

📸 *[Screenshot — Watchlist creation wizard showing all fields filled in]*  
📸 *[Screenshot — Watchlist appearing in the Watchlist list as "BusinessCriticalAWS" with 8 items]*

---

### Step 3 — Verify the Watchlist in Advanced Hunting

Confirmed the watchlist was accessible via `_GetWatchlist()`.

```kql
_GetWatchlist('BusinessCriticalAWS')
| project EventSource, ServiceName, Criticality
```

**Expected output:** 8 rows — one per service entry from the CSV.

📸 *[Screenshot — _GetWatchlist query returning all 8 rows from BusinessCriticalAWS watchlist]*

---

### Step 4 — Modify the Detection Rule Query

Opened `Lab Stage E4 - Console Login Without MFA (AWS)` → Edit → replaced query with watchlist-enriched version.

```kql
let critical_services = _GetWatchlist('BusinessCriticalAWS')
    | project EventSource, ServiceName, Criticality;
AWSCloudTrail
| where TimeGenerated > ago(4h)
| where EventName == "ConsoleLogin"
| where SessionMfaAuthenticated != "true"
| lookup kind=leftouter critical_services on EventSource
| extend
    ServiceName = coalesce(ServiceName, "Unknown"),
    Criticality = coalesce(Criticality, "Low")
| project
    TimeGenerated,
    UserIdentityUserName,
    SourceIpAddress,
    AWSRegion,
    EventName,
    EventSource,
    ServiceName,
    Criticality,
    MfaAuthenticated = SessionMfaAuthenticated
| extend
    AccountUpn = UserIdentityUserName,
    RemoteIP = SourceIpAddress,
    ReportId = tostring(hash_sha256(strcat(
        UserIdentityUserName, SourceIpAddress, tostring(TimeGenerated))))
```

> ⚠️ **Lab-level KQL** — uses `let`, `lookup`, `coalesce()`, `hash_sha256()`. Beyond SC-200 exam scope. **SC-200 relevance:** `_GetWatchlist()`, `where SessionMfaAuthenticated != "true"`, and the join concept are exam-adjacent topics.

📸 *[Screenshot — modified detection query in Advanced Hunting showing ServiceName and Criticality in results]*

---

### Key Query Changes Explained

| Change | Purpose |
|--------|---------|
| `_GetWatchlist('BusinessCriticalAWS')` | Loads watchlist into a KQL variable |
| `lookup kind=leftouter` | Joins watchlist — events without a match STILL appear (vs. `join kind=inner` which would drop them) |
| `coalesce(Criticality, "Low")` | Default "Low" for unmatched services — no orphan rows |
| `ServiceName`, `Criticality` in output | Alert now shows "KMS - Critical" not just "kms.amazonaws.com" |

**`lookup` vs. `join`:**
- `lookup kind=leftouter` — optimised for enrichment lookups. The left table drives results; right table adds columns. Missing matches get null/default.
- `join kind=inner` — only returns rows where both sides have a match. Use this for TI matching where you ONLY want hits.

---

### Alternative: Filter to Critical Only (Higher Precision)

If alert volume is still too high, filter to only Critical-tier services:

```kql
AWSCloudTrail
| where TimeGenerated > ago(4h)
| where EventName == "ConsoleLogin"
| where SessionMfaAuthenticated != "true"
| where EventSource in (
    (_GetWatchlist('BusinessCriticalAWS')
    | where Criticality == "Critical"
    | project SearchKey)
)
```

**Tradeoff:** Higher precision (fewer FPs) but reduced coverage — S3 and EC2 logins without MFA no longer alert.

---

### Step 5 — Update the Alert Title

Updated the alert title to include business context:

```
Console login without MFA by {{UserIdentityUserName}} — {{Criticality}} service
```

📸 *[Screenshot — alert title configuration showing dynamic field references]*

---

### Step 6 — Enable and Verify

Saved the query, enabled the rule, confirmed alerts now include `ServiceName` and `Criticality` enrichment.

📸 *[Screenshot — triggered alert showing "KMS - Critical" in the ServiceName and Criticality fields]*

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| Watchlist creation and upload | D3 Sentinel | Watchlist management |
| `_GetWatchlist()` function | D3 Sentinel | KQL watchlist integration |
| `lookup kind=leftouter` for enrichment | D3 Sentinel | KQL joins |
| Alert enrichment with business context | D3 Sentinel | Incident enrichment |
| AWS MFA detection logic | D3 Sentinel | Cloud threat detection |
| `_GetWatchlist` with `in` for filtering | D3 Sentinel | Watchlist filter pattern |

**High-frequency exam question pattern:**  
*"You want to prioritise alerts for VIP user accounts — what Sentinel feature do you use?"* → Watchlist. Upload a CSV of VIP users, join via `_GetWatchlist()`, add a priority tag or severity escalation.

---

## Watchlist Limitations (Know for Exam and Production)

| Limitation | Detail |
|-----------|--------|
| Local file upload limit | 3.8 MB max |
| Azure Storage upload limit | 500 MB max |
| Refresh frequency | Watchlists update every 12 days — plan updates accordingly |
| Schema changes | If CSV column names change, queries break — version your watchlists |

---

## MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Valid Accounts: Cloud Accounts | T1078.004 | Attacker using valid AWS credentials without MFA |
| Defense Evasion | T1562.008 | Disabling CloudTrail to avoid detection (separate but related) |

---

## Key Takeaways

- Watchlists add **business context that log data doesn't have** — criticality, ownership, department, risk tier
- `lookup kind=leftouter` = enrich without filtering. Every event appears; matched rows get extra columns. Use for enrichment.
- `join kind=inner` = filter to matches only. Use for TI matching where you only want hits.
- `coalesce()` handles null values from unmatched lookups — always include it when using `leftouter`
- `SearchKey` in watchlist creation is the indexed column used for lookups — always set it to the join column
- Watchlists + automation rules = powerful combination: watchlist identifies Critical service → automation rule escalates severity → analyst sees "KMS - Critical" without manual triage steps
