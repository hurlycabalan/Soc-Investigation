# 🔐 KQL Security Drills — SC-200 Reference Guide

> **Platform:** Microsoft Sentinel (Azure AD / Entra ID)  
> **Version:** SC-200 Exam Aligned  
> **Author:** Hurly Cabalan  
> **GitHub:** [github.com/hurlycabalan](https://github.com/hurlycabalan)

---

## 📋 Table of Contents

| Drill | Topic | Difficulty |
|---|---|---|
| [Drill 1](#drill-1) | Failed Login Count by User | 🟢 Beginner |
| [Drill 2](#drill-2) | Failed Logins by IP Address | 🟢 Beginner |
| [Drill 3](#drill-3) | Phishing — Sender vs Reply-To Mismatch | 🟢 Beginner |
| [Drill 4](#drill-4) | Brute Force + Successful Login Correlation | 🟠 Intermediate |
| [Drill 5](#drill-5) | Login Failure Trend Over Time | 🟡 Moderate |
| [Drill 6](#drill-6) | First & Last Login per User | 🟡 Moderate |
| [Drill 7](#drill-7) | Lateral Movement Detection | 🟡 Moderate |
| [Drill 8](#drill-8) | MFA Fatigue Detection | 🟠 Intermediate |
| [Drill 9](#drill-9) | C2 Beaconing Detection | 🟠 Intermediate |
| [Drill 10](#drill-10) | Full Incident Correlation | 🔴 Advanced |

---

## Drill 1

### 🟢 Failed Login Count by User

**Scenario:** Identify which accounts have the highest number of failed authentication attempts. This is a first-response query when a brute force alert is triggered.

**What to look for:**
- Accounts with unusually high failure counts
- Service accounts being targeted
- Accounts that don't normally generate failures

**SC-200 Relevance:** Covers alert triage and initial investigation of authentication-based incidents.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailedCount = count() by UserPrincipalName
| sort by FailedCount desc
```

---

## Drill 2

### 🟢 Failed Logins by IP Address

**Scenario:** Identify which IP addresses are generating the most authentication failures. Helps determine if the attack is coming from a single source or distributed.

**What to look for:**
- Single IP with very high failure count = targeted brute force
- Multiple IPs with moderate counts = password spray attack
- Known malicious IP ranges

**SC-200 Relevance:** Supports threat hunting and network-based IOC identification.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailedCount = count() by IPAddress
| sort by FailedCount desc
```

---

## Drill 3

### 🟢 Phishing — Sender vs Reply-To Mismatch

**Scenario:** Detect emails where the sender address and reply-to address do not match — a common indicator of phishing and business email compromise (BEC).

**What to look for:**
- Legitimate-looking sender with suspicious reply-to domain
- Reply-to pointing to free email providers (gmail, yahoo, hotmail)
- Executive impersonation patterns

**SC-200 Relevance:** Covers email threat detection and phishing investigation workflows in Microsoft Defender for Office 365.

```kql
EmailEvents
| where SenderFromAddress != ReplyToAddress
| project Timestamp, SenderFromAddress, ReplyToAddress, Subject, RecipientEmailAddress
| sort by Timestamp desc
```

---

## Drill 4

### 🟠 Brute Force + Successful Login Correlation

**Scenario:** Correlate accounts that had multiple failed login attempts followed by a successful authentication — a strong indicator of a successful account compromise.

**What to look for:**
- Accounts that failed 5+ times then succeeded
- Same IP address for both failures and success
- Success occurring shortly after the failure spike

**SC-200 Relevance:** Core incident investigation skill — correlating multiple event types to confirm compromise. Uses `let` statements and `join` operator.

```kql
let FailedLogins =
    SigninLogs
    | where ResultType != "0"
    | summarize FailedCount = count() by UserPrincipalName
    | where FailedCount >= 5;
let SuccessLogins =
    SigninLogs
    | where ResultType == "0"
    | summarize LastSuccess = max(TimeGenerated) by UserPrincipalName;
FailedLogins
| join kind=inner SuccessLogins on UserPrincipalName
| project UserPrincipalName, FailedCount, LastSuccess
| sort by FailedCount desc
```

---

## Drill 5

### 🟡 Login Failure Trend Over Time

**Scenario:** Visualize authentication failures over time using 1-hour bins to identify attack windows and spikes in malicious activity.

**What to look for:**
- Sudden spike in failures at unusual hours
- Sustained high failure rate over several hours
- Pattern that correlates with known attack timeframes

**SC-200 Relevance:** Time-series analysis using `bin()` — essential for identifying attack windows and building detection timelines.

```kql
SigninLogs
| where ResultType != "0"
| summarize FailedLogins = count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

---

## Drill 6

### 🟡 First & Last Login per User

**Scenario:** Establish a baseline of normal login behavior by identifying the first and most recent successful login for each user account.

**What to look for:**
- New accounts with no login history (potential ghost accounts)
- Accounts with unusually old last login (dormant accounts being reactivated)
- Accounts logging in outside normal business hours

**SC-200 Relevance:** Baseline and anomaly detection using `min()` and `max()` aggregation functions.

```kql
SigninLogs
| where ResultType == "0"
| summarize FirstLogin = min(TimeGenerated),
            LastLogin = max(TimeGenerated) by UserPrincipalName
| sort by FirstLogin asc
```

---

## Drill 7

### 🟡 Lateral Movement Detection

**Scenario:** Identify accounts authenticating from multiple geographic locations — a key indicator of lateral movement or impossible travel scenarios.

**What to look for:**
- Users logging in from 3+ distinct locations
- Geographically impossible login sequences
- Service accounts authenticating from user locations

**SC-200 Relevance:** MITRE ATT&CK Lateral Movement (TA0008) detection using `dcount()` for distinct value counting.

```kql
SigninLogs
| where ResultType == "0"
| summarize LoginCount = count(),
            Locations = dcount(Location) by UserPrincipalName
| where Locations > 2
| sort by Locations desc
```

---

## Drill 8

### 🟠 MFA Fatigue Detection

**Scenario:** Identify accounts receiving excessive MFA push notifications — a sign of MFA fatigue attacks where the attacker repeatedly triggers MFA prompts hoping the user will approve out of frustration.

**What to look for:**
- 10+ MFA failures from same user and IP
- Failures occurring in short rapid bursts
- Activity outside normal business hours

**SC-200 Relevance:** Modern identity attack detection — MFA fatigue is a key technique used in recent high-profile breaches (MITRE T1621).

```kql
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType != "0"
| summarize MFAFailures = count(),
            LastAttempt = max(TimeGenerated) by UserPrincipalName, IPAddress
| where MFAFailures >= 10
| sort by MFAFailures desc
```

---

## Drill 9

### 🟠 C2 Beaconing Detection

**Scenario:** Identify devices making repeated outbound connections to the same external IP — a pattern consistent with Command and Control (C2) beaconing behavior.

**What to look for:**
- High connection count to a single external IP
- Regular interval connections (consistent beaconing pattern)
- Connections on standard ports (443, 80) to mask traffic
- Long duration between first and last seen

**SC-200 Relevance:** Network-based threat detection — MITRE ATT&CK Command and Control (TA0011). Uses `DeviceNetworkEvents` and `extend` for calculated fields.

```kql
DeviceNetworkEvents
| where RemotePort in (443, 80, 8080)
| summarize ConnectionCount = count(),
            BytesSent = sum(SentBytes),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated) by DeviceName, RemoteIP
| where ConnectionCount >= 100
| extend Duration = LastSeen - FirstSeen
| sort by ConnectionCount desc
```

---

## Drill 10

### 🔴 Full Incident Correlation

**Scenario:** Full end-to-end incident correlation combining brute force detection, successful login confirmation, and threat intelligence enrichment — the complete L2 SOC investigation workflow.

**What to look for:**
- Accounts that were brute forced AND successfully compromised
- Source IPs matching active threat intelligence indicators
- Geographic anomalies in the successful login location
- ThreatType field indicating known malicious actor classification

**SC-200 Relevance:** Advanced multi-table correlation using multiple `let` statements, `inner join`, and `leftouter join`. Represents the highest complexity query type tested in SC-200 and used in real L2 SOC investigations.

```kql
let FailedLogins =
    SigninLogs
    | where ResultType != "0"
    | summarize FailedCount = count() by UserPrincipalName, IPAddress
    | where FailedCount >= 5;
let SuccessLogins =
    SigninLogs
    | where ResultType == "0"
    | summarize LastSuccess = max(TimeGenerated),
                Location = any(Location) by UserPrincipalName, IPAddress;
let SuspiciousIP =
    ThreatIntelligenceIndicator
    | where Active == true
    | project IPAddress = NetworkIP, ThreatType;
FailedLogins
| join kind=inner SuccessLogins on UserPrincipalName, IPAddress
| join kind=leftouter SuspiciousIP on IPAddress
| project UserPrincipalName, IPAddress, FailedCount, LastSuccess, Location, ThreatType
| sort by FailedCount desc
```

---

## 🧠 Key Concepts Summary

| Operator | Purpose | Used In |
|---|---|---|
| `where` | Filter rows | All drills |
| `summarize` | Aggregate data | All drills |
| `sort` | Order results | All drills |
| `bin()` | Time bucketing | Drill 5 |
| `min() / max()` | First/last values | Drill 6 |
| `dcount()` | Count distinct values | Drill 7 |
| `let` | Store query as variable | Drills 4, 10 |
| `join kind=inner` | Match records in both tables | Drills 4, 10 |
| `join kind=leftouter` | Keep all + enrich with matches | Drill 10 |
| `extend` | Add calculated column | Drill 9 |
| `any()` | Return any value from group | Drill 10 |

---

## 📚 References

- [Microsoft SC-200 Exam](https://learn.microsoft.com/en-us/credentials/certifications/security-operations-analyst/)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)

---

*Documentation by Hurly Cabalan | SOC Investigation Portfolio*  
*github.com/hurlycabalan/Soc-Investigation*
