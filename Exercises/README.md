# Microsoft Sentinel Training Lab — Exercises Portfolio

**Lab:** Microsoft Sentinel Training Lab (Azure/Azure-Sentinel)
**Portfolio:** [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)
**Environment:** Microsoft Defender Portal → Microsoft Sentinel
**Status:** Week 1 — In Progress

---

## 📋 Exercise Index

| # | Exercise | Topic | Difficulty | Status |
|---|----------|--------|------------|--------|
| [Ex01](#ex01--exploration-hunting-across-multi-vendor-data) | Exploration | Advanced Hunting + Custom Detection Rule | Beginner | ⬜ |
| [Ex02](#ex02--threat-intelligence-mdti) | Threat Intelligence | MDTI Connector + IOC Matching | Beginner | ⬜ |
| [Ex03](#ex03--mitre-attck-coverage) | MITRE ATT&CK Coverage | Heat Map + Gap Analysis | Beginner | ⬜ |
| [Ex04](#ex04--automation-rules) | Automation Rules | No-Code SOC Workflow | Beginner | ⬜ |
| [Ex05](#ex05--cross-platform-response-skipped) | Cross-Platform Response | Device Isolation via MDE | Intermediate | ⏭️ Skipped |
| [Ex06](#ex06--port-scan-detection--threshold-tuning) | Port Scan Detection | Baseline + Threshold Tuning | Beginner | ⬜ |
| [Ex07](#ex07--okta-mfa-factor-manipulation) | Okta MFA Manipulation | Identity Detection + Geo Context | Intermediate | ⬜ |
| [Ex08](#ex08--watchlist-integration) | Watchlist Integration | Business Context Enrichment | Intermediate | ⬜ |

---

## Data Sources Active in Lab

| Vendor | Table | Data Type |
|--------|-------|-----------|
| CrowdStrike | `CrowdStrikeAlerts`, `CrowdStrikeDetections` | EDR alerts |
| Palo Alto | `CommonSecurityLog` | Firewall traffic |
| Okta | `OktaV2_CL` | Identity events |
| AWS | `AWSCloudTrail` | Cloud API calls |
| GCP | `GCPAuditLogs` | Cloud audit logs |
| MailGuard | `MailGuard365_Threats_CL` | Email threat events |

---

---

## Ex01 — Exploration: Hunting Across Multi-Vendor Data

**MITRE:** T1046, T1071.001, T1078.004, T1003.001, T1566
**Data Sources:** CrowdStrikeAlerts, CommonSecurityLog, OktaV2_CL, AWSCloudTrail

### Objective
Get familiar with all ingested data sources. Run KQL queries across six vendors, understand schemas, build a cross-source timeline, and create a custom detection rule for multi-tactic endpoint compromise.

### What This Exercise Teaches
- `search *` — fastest way to discover populated tables in a new workspace
- `dcount()` — detecting anomalous diversity (distinct tactics, ports, IPs)
- `union` — correlating events across vendors into one chronological timeline
- `make_set()` — collecting distinct values for alert enrichment
- Rule creation — turning a hunting query into a scheduled detection rule

### Steps Completed

**Step 1 — Table Discovery**
Ran `search * | summarize EventCount = count() by $table | sort by EventCount desc` to inventory all data sources.

**Step 2 — CrowdStrike Endpoint Data**
Queried `CrowdStrikeAlerts` for alert types, severity distribution, and MITRE tactic spread per device. Devices with alerts spanning multiple tactics = likely compromised pivot point.

**Step 3 — Palo Alto Firewall Traffic**
Used `CommonSecurityLog` (DeviceVendor = "Palo Alto Networks") to see traffic overview. Filtered `drop`/`deny`/`reset-both` actions to surface blocked attack traffic.

**Step 4 — Okta Identity Events**
Queried `OktaV2_CL` for event types and failed login attempts. `dcount(SrcIpAddr)` per ActorUsername detects credential stuffing patterns.

**Step 5 — AWS Cloud Activity**
Explored `AWSCloudTrail` for API call volume and failed operations. `isnotempty(ErrorCode)` = attacker recon or failed privilege escalation.

**Step 6 — Cross-Source Timeline**
Built `union` query combining CrowdStrike High/Critical alerts + Palo Alto THREAT events + Okta MFA/deactivate events + AWS high-risk API calls into a single chronological timeline.

**Steps 7–9 — Custom Detection Rule**
Created rule `Lab Stage E1 - Multi-Tactic Compromise on Single Device`:
- Logic: Devices with CrowdStrike alerts spanning 3+ distinct MITRE tactics within 4 hours
- Threshold: `TacticCount >= 3`
- Schedule: Every 1 hour / 4-hour lookback
- Entity mapping: Device → `DeviceName`

### Key KQL Queries

```kql
// Table discovery
search *
| summarize EventCount = count() by $table
| sort by EventCount desc

// Multi-tactic device detection (core rule logic)
CrowdStrikeAlerts
| where TimeGenerated > ago(4h)
| where SeverityName in ("Critical", "High")
| summarize
    TacticCount = dcount(Tactic),
    Tactics = make_set(Tactic),
    AlertCount = count()
    by DeviceName, AgentId
| where TacticCount >= 3

// Cross-source attack timeline
union
    (CrowdStrikeAlerts | where SeverityName in ("Critical","High")
     | project TimeGenerated, Source="CrowdStrike", Activity=Name, Severity=SeverityName),
    (CommonSecurityLog | where DeviceVendor=="Palo Alto Networks" | where DeviceEventClassID=="THREAT"
     | project TimeGenerated, Source="Palo Alto", Activity, Severity=LogSeverity),
    (OktaV2_CL | where EventOriginalType has "mfa" or EventOriginalType has "deactivate"
     | project TimeGenerated, Source="Okta", Activity=EventOriginalType, Severity=EventSeverity),
    (AWSCloudTrail | where EventName in ("CreateUser","AttachUserPolicy","CreateAccessKey","StopLogging")
     | project TimeGenerated, Source="AWS", Activity=EventName, Severity="High")
| sort by TimeGenerated asc
```

### Key Takeaways
- `search *` first — always; don't assume which tables have data
- A single device with alerts spanning 3+ tactics = multi-stage compromise, not a noisy rule
- `union` + `sort by TimeGenerated` = analyst-ready attack timeline from raw vendor logs
- Detection rule = aggregation + threshold + enrichment fields for triage

### Screenshots
| File | Content |
|------|---------|
| `ex01-01-table-discovery.png` | `search *` output showing all populated tables |
| `ex01-02-crowdstrike-tactics.png` | Alert summary by tactic per device |
| `ex01-03-cross-source-timeline.png` | Union query output — multi-vendor timeline |
| `ex01-04-rule-creation.png` | Custom detection rule wizard |
| `ex01-05-rule-verified.png` | Rule in Custom detection rules list |

### Lab Notes
```
Session date:
Duration:
Table discovery — top tables by event count:
  1.
  2.
  3.
Multi-tactic rule fired? Y/N
Devices flagged:
One failed query / confusion point:
One thing I'll remember:
```

---

---

## Ex02 — Threat Intelligence: MDTI

**MITRE:** T1566 (phishing IOC), T1071.001 (C2 IP matching)
**Data Sources:** ThreatIntelIndicators, CommonSecurityLog, AWSCloudTrail, MailGuard365_Threats_CL

### Objective
Enable the Microsoft Defender Threat Intelligence (MDTI) data connector, verify indicator ingestion into `ThreatIntelIndicators`, and match IOCs against lab telemetry using `join kind=inner`. Add MailGuard phishing sender IP correlation as a bonus enrichment layer.

### What This Exercise Teaches
- MDTI connector setup via Content Hub (Threat Intelligence NEW solution)
- `ThreatIntelIndicators` table schema — ObservableKey, ObservableValue, Confidence, IsActive
- `join kind=inner` — IOC matching against firewall and cloud logs
- Empty results = expected in lab (synthetic IPs won't match real TI feed); the pattern matters
- MailGuard bonus: matching phishing sender IPs against the TI table

### Steps Completed

**Step 1 — Install Solution & Enable Connector**
Sentinel → Content hub → "Threat Intelligence (NEW)" (Featured) → Install/Update.
Configuration → Data connectors → "Microsoft Defender Threat Intelligence" → Connect.
Status = Connected ✅. First indicators appeared within ~15 minutes.

**Step 2 — Verify Indicator Ingestion**
Ran count by ObservableKey — confirmed `ipv4-addr`, `domain-name`, `url`, file hash types present.

**Step 3 — Schema Exploration**
Key columns: `ObservableKey` (IOC type), `ObservableValue` (actual IOC), `Confidence` (0–100), `IsActive` (bool), `Pattern` (STIX pattern), `Data` (dynamic JSON with threat actor/campaign context).

**Step 4 — IOC Matching**
Matched active, high-confidence IPv4 indicators against Palo Alto `DestinationIP` and AWS `SourceIpAddress`. Empty results in lab = expected — synthetic IPs won't match live Microsoft TI feed. Pattern confirmed working.

**Step 5 — Indicator Statistics**
Coverage overview: total indicators by type, avg confidence, age distribution (Last 7/30/90 days, Older than 90 days). Stale indicators (>90 days) should be reviewed for relevance.

**Step 6 — Threat Intelligence Blade**
Sentinel → Threat management → Threat intelligence. Reviewed indicator details, threat actor context, campaign associations.

**BONUS — MailGuard Phishing IP vs TI Matching**
Correlated phishing sender IPs from `MailGuard365_Threats_CL` against `ThreatIntelIndicators`:

```kql
let phishing_ips = MailGuard365_Threats_CL
| where TimeGenerated > ago(7d)
| where isnotempty(SenderIP_s)
| project SenderIP = SenderIP_s, Subject = Subject_s, Sender = SenderAddress_s;
ThreatIntelIndicators
| where IsActive == true
| where ObservableKey == "ipv4-addr"
| where Confidence > 50
| join kind=inner phishing_ips on $left.ObservableValue == $right.SenderIP
| project TimeGenerated, SenderIP, Sender, Subject, Confidence
| sort by Confidence desc
```

### Key KQL Queries

```kql
// Verify ingestion
ThreatIntelIndicators
| summarize IndicatorCount = count() by ObservableKey
| sort by IndicatorCount desc

// IOC matching — firewall logs
let ti_ips = ThreatIntelIndicators
| where IsActive == true
| where ObservableKey == "ipv4-addr"
| where Confidence > 50
| project ObservableValue, Confidence;
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| join kind=inner ti_ips on $left.DestinationIP == $right.ObservableValue
| project TimeGenerated, SourceIP, DestinationIP, DeviceAction, TI_Confidence = Confidence
```

### Key Takeaways
- Table name is `ThreatIntelIndicators` NOT `ThreatIntelligenceIndicator` — common SC-200 trap
- Always filter: `IsActive == true` AND `Confidence > 50` for actionable results
- `join kind=inner` = only show matches (IOC found in telemetry)
- Empty results = expected in lab; the join *pattern* is what the exam tests
- MDTI is free — included with Microsoft Sentinel licence

### Screenshots
| File | Content |
|------|---------|
| `ex02-01-content-hub.png` | Threat Intelligence (NEW) solution in Content Hub |
| `ex02-02-connector-connected.png` | MDTI connector status = Connected |
| `ex02-03-indicator-count.png` | ThreatIntelIndicators count by ObservableKey |
| `ex02-04-ti-blade.png` | Threat intelligence blade in Sentinel |
| `ex02-05-mailguard-bonus.png` | MailGuard phishing IP vs TI join (bonus) |

### Lab Notes
```
Session date:
Duration:
Connector status when enabled:
Minutes until first indicators appeared:
Total indicators — ipv4-addr:    domain-name:    url:
IOC match vs Palo Alto: Empty/Results
IOC match vs AWS: Empty/Results
MailGuard bonus — results? Y/N
One failed query / confusion point:
One thing I'll remember:
```

---

---

## Ex03 — MITRE ATT&CK Coverage

**MITRE:** 10 tactics, 15+ techniques (no raw log queries — analytics rule metadata)
**Portal:** Sentinel → Threat management → MITRE ATT&CK

### Objective
Use the Sentinel MITRE ATT&CK page to visualise detection coverage across 22 deployed analytics rules, identify coverage gaps, trace the full 10-stage lab attack chain, and practice detection engineering thinking.

### What This Exercise Teaches
- Reading the ATT&CK heat map — blue = rule coverage, grey = gap
- Gap analysis — why gaps exist and how to prioritise closing them
- Stage rules (always enabled) vs Exercise rules (disabled by default)
- Translating a coverage gap into a KQL detection idea

### Steps Completed

**Step 1 — Open MITRE ATT&CK Page**
Defender portal → Sentinel → Threat management → MITRE ATT&CK.
Matrix shows colour-coded cells: blue = at least one active analytics rule, grey = no coverage. Number in cell = rule count for that technique.

**Step 2 — Filter to Active Analytics Rules Only**
Filters → Simulated = deselect all → Active = Analytics rules only.
Matrix now reflects only deployed scheduled detection rules.

**Step 3 — Explore a Covered Technique (T1046)**
Clicked T1046 (Network Service Discovery) → side panel showed:
- `Lab Stage 3.5 - Internal Port Scan Detected (Palo Alto)` (always enabled)
- `Lab Stage E2 - Port Scan Detection (Palo Alto)` (exercise rule, disabled by default)

**Step 4 — Gap Analysis**

| Tactic | Missing Technique | Reason |
|--------|------------------|--------|
| Lateral Movement | T1021 — Remote Services | No east-west movement telemetry in lab |
| Collection | T1560 — Archive Collected Data | Exfiltration detected at network level only |
| Resource Development | T1583 — Acquire Infrastructure | Pre-attack, out of SOC scope |

**Step 5 — Full 10-Stage Attack Chain Mapped**

| Stage | Tactic | Technique | Data Source |
|-------|--------|-----------|-------------|
| S1 | Initial Access | T1566.001, T1566.002 | MailGuard365_Threats_CL |
| S2 | Execution | T1204.002 | CrowdStrikeAlerts |
| S3 | Credential Access | T1003.001 | CrowdStrikeAlerts |
| S3.5 | Discovery | T1046 | CommonSecurityLog |
| S4 | Privilege Escalation | T1078.004, T1098 | OktaV2_CL |
| S6 | Exfiltration | T1041 | CommonSecurityLog |
| S7 | Impact | T1078, T1098, T1496, T1562.008 | AWSCloudTrail |
| S8 | Persistence | T1136.003, T1078.004 | AWSCloudTrail |
| S9 | Privilege Escalation | T1136.003, T1098, T1496, T1562.008 | GCPAuditLogs |
| S10 | Initial Access | T1566.001, T1566.002 | MailGuard365_Threats_CL |

**Step 6 — Detection Engineering: Closing a Gap (T1110.003)**
Designed KQL for Okta password spray — single IP failing auth against 5+ distinct users within 4 hours. Assigns T1110.003 under Credential Access. Would appear as a new blue cell on matrix once deployed.

### Key Takeaways
- The MITRE page is a live reflection of your deployed analytics rules — not theoretical coverage
- Coverage gaps ≠ risk; they reflect available data sources and detection priority decisions
- Stage rules vs Exercise rules distinction is important — know which is always-on vs student-practice
- Every analytics rule should have at least one MITRE technique ID assigned
- MITRE IDs are the language of detection engineering — learn to speak it fluently

### Screenshots
| File | Content |
|------|---------|
| `ex03-01-matrix-overview.png` | Full ATT&CK matrix with heat map |
| `ex03-02-filtered-analytics.png` | Matrix filtered to active analytics rules only |
| `ex03-03-t1046-side-panel.png` | T1046 technique detail with mapped rules |
| `ex03-04-gap-areas.png` | Grey (uncovered) cells highlighted |

### Lab Notes
```
Session date:
Duration:
Total blue cells observed (approx):
Tactic with most coverage:
Biggest gap tactic:
T1046 rules in side panel:
  1.
  2.
One technique NOT covered that I expected:
One thing I'll remember:
```

---

---

## Ex04 — Automation Rules

**MITRE:** T1562.008 (log tampering auto-escalation), T1078 (cloud threat tagging)
**Portal:** Sentinel → Configuration → Automation

### Objective
Create two automation rules that automatically enrich incidents without a playbook (Logic App). Rule 1 tags AWS incidents; Rule 2 escalates log-cleared events to Critical. No code required.

### What This Exercise Teaches
- Automation rules vs Playbooks — no-code triage vs code-based response actions
- Trigger types: When incident is created (most common) vs When incident is updated
- Condition types: Analytic rule name Contains, entity attribute, incident severity
- Action types: Add tags, Change severity, Assign owner, Change status, Run playbook, Add task
- Priority ordering: lower number = higher priority, sequential execution

### Steps Completed

**Step 1 — Review Existing Incidents**
Sentinel → Incidents. Found lab incidents from: Port scan, data exfiltration, Okta account takeover rules.

**Step 2 — Rule 1: Tag AWS Threat Incidents**

| Config | Value |
|--------|-------|
| Name | `Tag AWS threat incidents` |
| Trigger | When incident is created |
| Condition | Analytic rule name **Contains** `AWS` |
| Action 1 | Add tag: `cloud-threat` |
| Action 2 | Add tag: `aws` |
| Order | 1 — Enabled |

Single `Contains` condition catches both `AWS Config Service Resource Deletion Attempts` and `Suspicious AWS CLI Command Execution`.

**Step 3 — Rule 2: Escalate Log Cleared Events**

| Config | Value |
|--------|-------|
| Name | `Escalate log cleared events` |
| Trigger | When incident is created |
| Condition | Analytic rule name **Contains** `Security Event log cleared` |
| Action 1 | Add tag: `defense-evasion` |
| Action 2 | Add tag: `log-tampering` |
| Action 3 | Change severity → **Critical** |
| Order | 2 — Enabled |

**Step 4 — Rule Ordering Summary**

| Order | Rule | Condition | Actions |
|-------|------|-----------|---------|
| 1 | Tag AWS threats | Rule name contains "AWS" | Tags: cloud-threat, aws |
| 2 | Escalate log cleared | Rule name contains "Security Event log cleared" | Tags: defense-evasion, log-tampering + Severity → Critical |

**Step 5 — Verified**
Triggered rules via Hunting → Custom detection rules → Run. Incident showed expected tags and Critical severity. ✅

### Automation vs Playbook Decision Matrix

| Action Needed | Use |
|--------------|-----|
| Add tags | Automation rule |
| Change severity | Automation rule |
| Assign to owner | Automation rule |
| Auto-close known FP | Automation rule |
| Send Teams notification | Playbook (Logic App) |
| Isolate a device | Playbook (Logic App) |
| Block IP at firewall | Playbook (Logic App) |
| Suspend Okta user | Playbook (Logic App) |

**SC-200 exam key:** Automation rules = no-code triage. Playbooks = code-based response requiring external API calls.

### Key Takeaways
- Automation rules need zero code — configured entirely in the portal UI
- Priority order matters — low number executes first; multiple rules can fire on same incident
- `Contains` on rule name is flexible — one condition covers multiple analytics rules
- Tags enable filtering, dashboards, SLA tracking, and SOC reporting
- Automation rules vs Playbooks distinction = near-certain SC-200 exam question

### Screenshots
| File | Content |
|------|---------|
| `ex04-01-automation-list.png` | Both rules in automation rules list |
| `ex04-02-rule1-config.png` | Tag AWS incidents rule configuration |
| `ex04-03-rule2-config.png` | Escalate log cleared rule configuration |
| `ex04-04-incident-tags.png` | Incident showing auto-applied tags |
| `ex04-05-severity-escalated.png` | Log cleared incident showing Critical severity |

### Lab Notes
```
Session date:
Duration:
Rule 1 applied tags? Y/N
Rule 2 escalated severity? Y/N
How I verified (ran rule manually? waited for new incident?):
One thing I got wrong first time:
One thing I'll remember:
```

---

---

## Ex05 — Cross-Platform Response (Skipped)

**Reason skipped:** Requires Microsoft Defender for Endpoint (MDE) live device — not available in this lab environment.
**What it covers:** Device isolation via MDE, cross-platform response actions from Sentinel incidents.
**Revisit:** If MDE devices are available in a future lab environment.

---

---

## Ex06 — Port Scan Detection & Threshold Tuning

**Rule:** `Lab Stage E2 - Port Scan Detection (Palo Alto)`
**MITRE:** T1046 — Network Service Discovery
**Data Sources:** CommonSecurityLog (Palo Alto Networks)

### Objective
Tune a port scan detection rule to reduce false positives. Establish a statistical baseline using percentile analysis, select a data-driven threshold, and enrich the detection with context fields that accelerate analyst triage.

### What This Exercise Teaches
- Detection tuning philosophy — measure first, threshold second; never guess
- Percentile analysis — p50 = normal, p90/95 = elevated, p99 = rare, max = extreme
- `ApplicationProtocol == "incomplete"` — key filter for scans vs legitimate traffic (session never completed)
- `make_set(DestinationPort)` — tells analyst *which* ports, not just how many
- `PortsPerMinute` — distinguishes automated scans (fast) from slow manual recon
- Lookback alignment: lookback window must be ≥ 4× rule frequency

### Steps Completed

**Step 1 — Establish Baseline**
Ran percentile query to understand normal port diversity in the environment:

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Palo Alto Networks"
| where Activity in ("drop", "deny", "reset-both")
| where ApplicationProtocol == "incomplete"
| summarize DistinctPorts = dcount(DestinationPort) by SourceIP, DestinationIP
| summarize
    p50 = percentile(DistinctPorts, 50),
    p90 = percentile(DistinctPorts, 90),
    p95 = percentile(DistinctPorts, 95),
    p99 = percentile(DistinctPorts, 99),
    max_ports = max(DistinctPorts)
```

Threshold selection: if p99 ≤ 10 → use `> 15`. If p99 11–20 → use `> 20`. If p99 > 20 → use p99 × 1.2 rounded up.

**Observed baseline:**

| Metric | Value |
|--------|-------|
| p50 | ___ |
| p99 | ___ |
| Chosen threshold | > ___ |

**Step 2 — Updated Detection Query**
Replaced rule query with enriched version: added `FirstSeen`/`LastSeen`, `PortList = make_set(DestinationPort, 25)`, `ScanDurationMinutes`, `PortsPerMinute`. Applied tuned threshold.

**Step 3 — Validated**
Manual run confirmed expected output, correct enrichment fields, manageable alert volume. ✅

### Key KQL Queries

```kql
// Enriched detection rule (tuned version)
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
| where DistinctPorts > 20
| project FirstSeen, LastSeen, SourceIP, DestinationIP, DistinctPorts, EventCount, PortList
```

### Enrichment Field Reference

| Field | Analyst Value |
|-------|--------------|
| `DistinctPorts` | Breadth of scan |
| `PortList` | Which ports — reveals scan type and intent |
| `EventCount` | Volume of blocked connections |
| `ScanDurationMinutes` | Burst vs slow scan |
| `PortsPerMinute` | >10/min = automated/aggressive |

### Key Takeaways
- Never pick a threshold without a baseline — always measure first
- `ApplicationProtocol == "incomplete"` is the definitive scan filter in Palo Alto logs
- `make_set()` in alert output is more useful than a count — it shows *which* ports
- `PortsPerMinute` differentiates automated scanners from manual recon
- Attack chain context: S3.5 — attacker already has C2, now mapping internal network for lateral movement targets

### Screenshots
| File | Content |
|------|---------|
| `ex06-01-baseline-query.png` | Percentile analysis results |
| `ex06-02-original-rule.png` | Original rule before tuning |
| `ex06-03-updated-query.png` | Enriched query with PortList and PortsPerMinute |
| `ex06-04-alert-output.png` | Alert output showing enrichment fields |
| `ex06-05-rule-enabled.png` | Rule enabled in Custom detection rules |

### Lab Notes
```
Session date:
Duration:
Baseline results — p50:    p95:    p99:    max:
Chosen threshold: >
Reasoning for threshold:
Alert fired? Y/N
PortList visible in output? Y/N
One failed query / confusion:
One thing I'll remember:
```

---

---

## Ex07 — Okta MFA Factor Manipulation

**Rule:** `Lab Stage E3 - MFA Factor Manipulation (Okta)`
**MITRE:** T1556.006 — Modify Authentication Process: MFA
**Data Sources:** OktaV2_CL

### Objective
Detect when an attacker manipulates MFA factors after compromising an Okta account. Build a time-window correlation linking a foreign login to a subsequent MFA change within 30 minutes — raising fidelity from Medium to High.

### What This Exercise Teaches
- MFA lifecycle events in Okta: `deactivate`, `reset_all`, `update`
- `OriginalOutcomeResult == "SUCCESS"` filter — failed attempts are noise in this context
- `SrcGeoCountry` as a signal — foreign-origin MFA changes = high suspicion
- `between (LoginTime .. LoginTime + 30m)` — time-window correlation linking attack stages
- `OktaV2_CL` is the correct table (NOT `OktaSystemLogs`) — ASIM-normalised

### Steps Completed

**Step 1 — Verify Data Availability**
Re-ran `.\Scripts\IngestCSV.ps1` to ensure MFA manipulation events are present.
Verified: `OktaV2_CL | where EventOriginalType has "mfa"` returned events. ✅

**Step 2 — Base Detection Query**
Existing rule filters for 3 event types on `SUCCESS` only. Maps `ActorUsername` → `AccountUpn` for entity correlation.

**Step 3 — Time-Window Correlation (Challenge)**
Upgraded to correlate a **foreign login** followed by **MFA change within 30 minutes from the same IP**:

```kql
let mfa_events = OktaV2_CL
| where TimeGenerated > ago(4h)
| where EventOriginalType in ("user.mfa.factor.deactivate",
    "user.mfa.factor.reset_all", "user.mfa.factor.update")
| where OriginalOutcomeResult == "SUCCESS"
| project MfaTime = TimeGenerated, ActorUsername, SrcIpAddr, EventOriginalType;
let foreign_logins = OktaV2_CL
| where TimeGenerated > ago(4h)
| where EventOriginalType == "user.session.start"
| where OriginalOutcomeResult == "SUCCESS"
| where SrcGeoCountry != "AU"
| project LoginTime = TimeGenerated, ActorUsername, SrcIpAddr, SrcGeoCountry;
mfa_events
| join kind=inner foreign_logins on ActorUsername, SrcIpAddr
| where MfaTime between (LoginTime .. LoginTime + 30m)
| project LoginTime, MfaTime, ActorUsername, SrcIpAddr, SrcGeoCountry, MfaAction = EventOriginalType
```

**Step 4 — Enabled and Verified**
Rule enabled, alert fires with correct entity mapping (AccountUpn, RemoteIP). ✅

### Relevant Okta Event Types

| Event Type | Priority | Why |
|-----------|----------|-----|
| `user.mfa.factor.deactivate` | 🔴 High | Attacker removing your 2FA |
| `user.mfa.factor.reset_all` | 🔴 Critical | Complete MFA wipe |
| `user.mfa.factor.update` | 🟡 Medium | May be legitimate self-service |

### Alert Fidelity Comparison

| Query | Fidelity |
|-------|---------|
| MFA events only | 🟡 Medium — includes legitimate IT ops |
| SUCCESS filter added | 🟠 Medium-High — less noise |
| Foreign login + MFA within 30m (same IP, same user) | 🔴 High — very specific attacker pattern |

### Key Takeaways
- Filter on `SUCCESS` for MFA changes — failures are noise, not signal
- `OktaV2_CL` = correct table (NOT `OktaSystemLogs`) — confirmed in this lab environment
- `SrcGeoCountry != "AU"` = foreign origin proxy; adjust to your org's home country
- `between (LoginTime .. LoginTime + 30m)` links two events across time — this is what separates junior from senior analyst thinking
- Attack context: happens right after S4 (account takeover); attacker wipes MFA to ensure persistent access

### Screenshots
| File | Content |
|------|---------|
| `ex07-01-mfa-events-verify.png` | OktaV2_CL MFA events verification query |
| `ex07-02-base-query.png` | Base detection query in rule editor |
| `ex07-03-correlated-query.png` | Time-window correlation query results |
| `ex07-04-rule-enabled.png` | Rule enabled with entity mapping |
| `ex07-05-alert-fired.png` | Alert with AccountUpn and RemoteIP populated |

### Lab Notes
```
Session date:
Duration:
MFA events found in OktaV2_CL? Y/N
Re-ingestion required? Y/N
Correlated query returned results? Y/N
Foreign countries in SrcGeoCountry:
Entity mapping correct — AccountUpn: Y/N   RemoteIP: Y/N
One failed query / confusion:
One thing I'll remember:
```

---

---

## Ex08 — Watchlist Integration

**Rule:** `Lab Stage E4 - Console Login Without MFA (AWS)`
**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts
**Data Sources:** AWSCloudTrail, `_GetWatchlist('BusinessCriticalAWS')`

### Objective
Create a Sentinel watchlist mapping AWS services to business criticality, then integrate it into the AWS MFA detection rule. Transform a noisy "all non-MFA logins" alert into a prioritised, business-context-enriched detection using `_GetWatchlist()` and `lookup kind=leftouter`.

### What This Exercise Teaches
- Watchlists — named CSV lookup tables queryable via `_GetWatchlist('alias')` in any KQL query
- `lookup kind=leftouter` — enriches without filtering; all events appear, unmatched get defaults
- `coalesce()` — handles null from unmatched lookups; assigns "Unknown" or "Low" as defaults
- `in` vs `lookup` — filter (show only matching) vs enrich (show all, add context)
- Dynamic alert titles with `{{FieldName}}` syntax
- SearchKey = the join column; choosing it correctly optimises performance

### Steps Completed

**Step 1 — Create Watchlist CSV**

`BusinessCriticalAWS.csv`:
```
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

**Step 2 — Upload to Sentinel**
Sentinel → Configuration → Watchlist → + New.
Name: `BusinessCriticalAWS` | Alias: `BusinessCriticalAWS` | SearchKey: `EventSource`. Waited ~2 minutes.

**Step 3 — Verified Watchlist**
`_GetWatchlist('BusinessCriticalAWS') | project EventSource, ServiceName, Criticality` — all rows returned. ✅

**Step 4 — Modified Detection Query**

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
    TimeGenerated, UserIdentityUserName, SourceIpAddress,
    AWSRegion, EventSource, ServiceName, Criticality,
    MfaAuthenticated = SessionMfaAuthenticated
```

**Step 5 — Updated Alert Title**
`Console login without MFA by {{UserIdentityUserName}} — {{Criticality}} service`

**Step 6 — Enabled and Verified**
Alert now shows ServiceName and Criticality enrichment. ✅

### Key Design Decisions

| Decision | Reason |
|----------|--------|
| `lookup kind=leftouter` not `join kind=inner` | Keep all AWS events — don't miss non-listed services |
| `coalesce(Criticality, "Low")` | Graceful default for new/unknown services; no null in output |
| SearchKey = `EventSource` | Optimises lookup performance; Sentinel indexes on this column |
| Alias matches exactly | `_GetWatchlist('BusinessCriticalAWS')` must match alias; case-sensitive |

### Common Watchlist Use Cases

| Watchlist | Contents | Use |
|-----------|----------|-----|
| BusinessCriticalAWS | AWS services + criticality | Prioritise cloud alerts |
| VIPUsers | Executive usernames | Escalate any VIP alert |
| TrustedIPRanges | Corporate office IPs | Suppress FPs |
| TerminatedEmployees | Former staff accounts | Alert immediately on any activity |
| KnownBadHashes | Malware hashes | Match against CrowdStrike detections |

### Key Takeaways
- Watchlists inject business knowledge that raw logs don't have — criticality, ownership, sensitivity
- `_GetWatchlist('alias')` is just KQL — filter, project, join it like any table
- `lookup kind=leftouter` for enrichment; `in` with watchlist subquery for filtering
- Always use `coalesce()` when `lookup kind=leftouter` may produce nulls
- Watchlists refresh every 12 days — plan updates for fast-changing data (e.g. terminated employees)
- Attack context: S7-S8 — attacker creates backdoor IAM accounts; watchlist immediately tells SOC this login hit KMS (Critical) not Lambda (Medium) — changes escalation priority completely

### Screenshots
| File | Content |
|------|---------|
| `ex08-01-watchlist-upload.png` | Watchlist creation form with CSV |
| `ex08-02-watchlist-verify.png` | `_GetWatchlist()` showing all rows |
| `ex08-03-original-rule.png` | Rule before watchlist integration |
| `ex08-04-enriched-query.png` | Updated query with lookup and coalesce |
| `ex08-05-enriched-alert.png` | Alert showing ServiceName=IAM, Criticality=Critical |

### Lab Notes
```
Session date:
Duration:
Watchlist available after upload — wait time: ___ mins
Verify query returned all 8 rows? Y/N
Rule updated successfully? Y/N
Alert showed Criticality field? Y/N
Most common EventSource in non-MFA logins:
Any Critical-tier services in alerts? Y/N
One failed query / confusion:
One thing I'll remember:
```

---

---

## 📊 Exercises Summary

| Exercise | Core KQL Concept | MITRE Technique | SC-200 Relevance |
|----------|-----------------|----------------|-----------------|
| Ex01 | `union` + `dcount` + custom rule | T1046, T1566 | D3 Sentinel — rule creation |
| Ex02 | `join kind=inner` + TI matching | T1566, T1071.001 | D3 Sentinel — TI integration |
| Ex03 | MITRE page + gap analysis | All 10 tactics | D3 Sentinel — coverage review |
| Ex04 | Automation rules + conditions | T1562.008, T1078 | D3 Sentinel — automation vs playbook |
| Ex05 | *(Skipped — MDE required)* | — | D1 Defender XDR |
| Ex06 | `percentile` + threshold tuning | T1046 | D3 Sentinel — detection tuning |
| Ex07 | `between` + time-window correlation | T1556.006 | D3 Sentinel — identity detection |
| Ex08 | `_GetWatchlist` + `lookup leftouter` | T1078.004 | D3 Sentinel — enrichment |

---

*Portfolio: [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)*
