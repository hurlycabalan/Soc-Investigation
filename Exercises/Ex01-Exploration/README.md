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
