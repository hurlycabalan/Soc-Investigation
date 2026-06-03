> ⚠️ **CONSTRUCTED SCENARIO** — Sentinel Training Lab data expired June 3, 2026 before this lab session could be executed. All KQL queries, MITRE mappings, and investigation logic are based on the documented run sheet. No live screenshots available. This is consistent with the rest of the TL series (TL-01 through TL-04) which were also constructed due to schema/data availability constraints.

---
# TL-05 Run Sheet — Full Kill Chain (All 6 Vendors)
**Saturday 9-Hour Boss Fight**  
**Chain: MailGuard → Okta → CrowdStrike → PaloAlto → AWS → GCP**  
**⚠️ AWS + GCP expected 0 data — document as detection gap, not failure**

---

## ⚠️ PRE-FLIGHT — First 30 Minutes

### Step 1 — Verify all tables (run each, screenshot ONE result)
```kql
MailGuard365_Threats_CL | take 1
```
```kql
OktaV2_CL | take 1
```
```kql
CrowdStrikeDetections | take 1
```
```kql
CrowdStrikeAlerts | take 1
```
```kql
CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" | take 1
```
```kql
GCPAuditLogs | take 1
```
```kql
AWSCloudTrail | take 1
```

**Document results:**
| Table | Has Data? | Notes |
|---|---|---|
| MailGuard365_Threats_CL | ☐ Yes / ☐ No | |
| OktaV2_CL | ☐ Yes / ☐ No | |
| CrowdStrikeDetections | ☐ Yes / ☐ No | |
| CrowdStrikeAlerts | ☐ Yes / ☐ No | |
| CommonSecurityLog (Palo) | ☐ Yes / ☐ No | |
| GCPAuditLogs | ☐ Yes / ☐ No | Expected 0 |
| AWSCloudTrail | ☐ Yes / ☐ No | Expected 0 |

### Step 2 — Grab anchor values (fill these in, use throughout)
```kql
MailGuard365_Threats_CL
| summarize count() by SenderAddress
| sort by count_ desc
| take 5
```
```kql
OktaV2_CL
| summarize count() by actor_alternateId_s
| sort by count_ desc
| take 5
```
```kql
CrowdStrikeDetections
| summarize count() by DeviceName
| sort by count_ desc
| take 5
```

**Fill in your anchors:**
- Attacker email/sender: `_______________________`
- Victim user (Okta): `_______________________`
- Affected endpoint: `_______________________`
- Endpoint IP: `_______________________`

---

## PHASE 1 — Initial Access via Phishing (MailGuard)

### Screenshot 01 — Phishing Email Detection
**Save as:** `01-mailguard-phishing.png`

```kql
MailGuard365_Threats_CL
| where TimeGenerated > ago(7d)
| where Classification contains "Phish"
    or Classification contains "Malware"
    or Classification contains "Spam"
| project TimeGenerated, SenderAddress, RecipientAddress,
          Subject, Classification, Action
| sort by TimeGenerated asc
```
**Screenshot when:** Email row visible with Classification and Action columns.  
**Note the RecipientAddress — this becomes your victim user for Okta pivot.**

### Screenshot 02 — Threat Intel Match (MailGuard sender vs TI)
**Save as:** `02-mailguard-ti-match.png`

```kql
let phish_sender = "REPLACE-WITH-SENDER-IP-OR-DOMAIN";
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where NetworkIP == phish_sender
    or DomainName contains phish_sender
| project TimeGenerated, NetworkIP, DomainName,
          ThreatType, ConfidenceScore, ExpirationDateTime
| sort by ConfidenceScore desc
```
**Screenshot when:** TI match row visible = external corroboration of phishing.  
**If 0 results:** Screenshot anyway — note "sender not in TI feed, IOC may be novel."

---

## PHASE 2 — Identity Compromise (Okta)

### Screenshot 03 — Okta: Account Login After Phishing
**Save as:** `03-okta-login-post-phish.png`

```kql
let victim = "REPLACE-WITH-VICTIM-EMAIL";
OktaV2_CL
| where TimeGenerated > ago(7d)
| where actor_alternateId_s == victim
| where eventType_s == "user.session.start"
| project TimeGenerated, actor_alternateId_s,
          client_ipAddress_s, client_geographicalContext_country_s,
          outcome_result_s, client_device_s
| sort by TimeGenerated asc
```
**Screenshot when:** Login rows visible — look for SUCCESS from unusual country/IP.

### Screenshot 04 — Okta: MFA Events (Bypass Attempt)
**Save as:** `04-okta-mfa-events.png`

```kql
let victim = "REPLACE-WITH-VICTIM-EMAIL";
OktaV2_CL
| where TimeGenerated > ago(7d)
| where actor_alternateId_s == victim
| where eventType_s contains "mfa" or eventType_s contains "factor"
| project TimeGenerated, actor_alternateId_s,
          eventType_s, outcome_result_s, client_ipAddress_s
| sort by TimeGenerated asc
```
**Screenshot when:** MFA rows visible — FAILURE = bypass attempt, SUCCESS = compromised.

### Screenshot 05 — SigninLogs: Azure IdP Corroboration
**Save as:** `05-signinlogs-corroboration.png`

```kql
let victim = "REPLACE-WITH-VICTIM-EMAIL";
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == victim
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, AppDisplayName, RiskLevelDuringSignIn, ResultType
| sort by TimeGenerated asc
```
**Screenshot when:** Same IP from Okta appears here = strong cross-IdP corroboration.

---

## PHASE 3 — Endpoint Compromise (CrowdStrike)

### Screenshot 06 — CrowdStrike: Malware/Execution on Endpoint
**Save as:** `06-crowdstrike-endpoint-detection.png`

```kql
let endpoint = "REPLACE-WITH-DEVICE-NAME";
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| where DeviceName == endpoint
| project TimeGenerated, DeviceName, UserName,
          FileName, CommandLine, Tactic, Technique
| sort by TimeGenerated asc
```
**Screenshot when:** Detection row with Tactic visible.

### Screenshot 07 — CrowdStrike: Alert Severity
**Save as:** `07-crowdstrike-alert-severity.png`

```kql
let endpoint = "REPLACE-WITH-DEVICE-NAME";
CrowdStrikeAlerts
| where TimeGenerated > ago(7d)
| where DeviceName == endpoint
| project TimeGenerated, DeviceName, Severity, Name, Status
| sort by TimeGenerated asc
```
**Screenshot when:** Severity column visible.

---

## PHASE 4 — Network C2 + Lateral Movement (PaloAlto)

### Screenshot 08 — PaloAlto: C2 Outbound Traffic
**Save as:** `08-paloalto-c2-outbound.png`

```kql
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == endpoint_ip
| where DeviceAction == "allow"
| project TimeGenerated, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol, DeviceAction
| sort by TimeGenerated asc
```
**Screenshot when:** Outbound connections visible — note unusual ports/IPs.

### Screenshot 09 — PaloAlto: East-West Lateral Movement
**Save as:** `09-paloalto-lateral-movement.png`

```kql
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == endpoint_ip
| where DestinationIP startswith "10."
    or DestinationIP startswith "192.168."
    or DestinationIP startswith "172."
| project TimeGenerated, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol
| sort by TimeGenerated asc
```
**Screenshot when:** Internal IPs in DestinationIP = lateral movement confirmed.

---

## PHASE 5 — Cloud Abuse Attempt (AWS + GCP)

### Screenshot 10 — AWS CloudTrail: IAM Enumeration
**Save as:** `10-aws-cloudtrail.png`

```kql
AWSCloudTrail
| where TimeGenerated > ago(7d)
| where eventName_s in ("ListUsers", "ListRoles",
        "CreateAccessKey", "AttachUserPolicy")
| project TimeGenerated, eventName_s, userIdentity_userName_s,
          sourceIPAddress_s, requestParameters_s
| sort by TimeGenerated asc
```
**If 0 results:** Screenshot the empty result.  
Document: *"AWS CloudTrail returned 0 results — cloud logging connector not configured. Detection gap identified."*

### Screenshot 11 — GCPAuditLogs: Service Account Abuse
**Save as:** `11-gcp-audit.png`

```kql
GCPAuditLogs
| where TimeGenerated > ago(7d)
| where protoPayload_methodName_s in (
    "google.iam.admin.v1.CreateServiceAccountKey",
    "bigquery.datasets.get",
    "storage.objects.list")
| project TimeGenerated, protoPayload_methodName_s,
          protoPayload_authenticationInfo_principalEmail_s,
          protoPayload_requestMetadata_callerIp_s
| sort by TimeGenerated asc
```
**If 0 results:** Screenshot the empty result.  
Document: *"GCPAuditLogs returned 0 results — GCP logging connector not configured. Detection gap identified."*

---

## PHASE 6 — Blast Radius Assessment

### Screenshot 12 — Affected Users
**Save as:** `12-blast-radius-users.png`

```kql
OktaV2_CL
| where TimeGenerated > ago(7d)
| where client_ipAddress_s == "REPLACE-WITH-ATTACKER-IP"
| summarize count() by actor_alternateId_s
| sort by count_ desc
```
**Screenshot when:** Multiple users = wider blast radius.

### Screenshot 13 — Affected Endpoints
**Save as:** `13-blast-radius-endpoints.png`

```kql
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| where Tactic contains "Credential" or Tactic contains "Lateral"
| summarize count() by DeviceName
| sort by count_ desc
```
**Screenshot when:** Multiple devices = lateral spread confirmed.

---

## PHASE 7 — Mega Timeline (Money Shot)

### Screenshot 14 — Full 6-Vendor Kill Chain
**Save as:** `14-mega-timeline-full-chain.png`

```kql
let victim = "REPLACE-WITH-VICTIM-EMAIL";
let endpoint = "REPLACE-WITH-DEVICE-NAME";
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
MailGuard365_Threats_CL
| where TimeGenerated > ago(7d)
| where RecipientAddress == victim
| project TimeGenerated, Source="MailGuard",
          Event=Classification, Detail=SenderAddress
| union (
    OktaV2_CL
    | where TimeGenerated > ago(7d)
    | where actor_alternateId_s == victim
    | project TimeGenerated, Source="Okta",
              Event=eventType_s, Detail=client_ipAddress_s
)
| union (
    CrowdStrikeDetections
    | where TimeGenerated > ago(7d)
    | where DeviceName == endpoint
    | project TimeGenerated, Source="CrowdStrike",
              Event=Technique, Detail=FileName
)
| union (
    CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceVendor == "Palo Alto Networks"
    | where SourceIP == endpoint_ip
    | project TimeGenerated, Source="PaloAlto",
              Event=ApplicationProtocol, Detail=DestinationIP
)
| sort by TimeGenerated asc
```
**⚠️ This is your portfolio centrepiece.**  
**Screenshot when:** All 4 confirmed vendors visible in Source column.  
Add note in README: AWS + GCP absent = detection gap finding, not missing data.

---

## Master Checklist

| # | File | Done |
|---|---|---|
| Pre | All tables verified | ☐ |
| Pre | Anchors filled in | ☐ |
| 01 | 01-mailguard-phishing.png | ☐ |
| 02 | 02-mailguard-ti-match.png | ☐ |
| 03 | 03-okta-login-post-phish.png | ☐ |
| 04 | 04-okta-mfa-events.png | ☐ |
| 05 | 05-signinlogs-corroboration.png | ☐ |
| 06 | 06-crowdstrike-endpoint-detection.png | ☐ |
| 07 | 07-crowdstrike-alert-severity.png | ☐ |
| 08 | 08-paloalto-c2-outbound.png | ☐ |
| 09 | 09-paloalto-lateral-movement.png | ☐ |
| 10 | 10-aws-cloudtrail.png | ☐ |
| 11 | 11-gcp-audit.png | ☐ |
| 12 | 12-blast-radius-users.png | ☐ |
| 13 | 13-blast-radius-endpoints.png | ☐ |
| 14 | 14-mega-timeline-full-chain.png | ☐ |

---

## Saturday Time Budget (9 Hours)

| Time | Task |
|---|---|
| Hr 1 | Pre-flight + table verification + anchor values |
| Hr 2 | Screenshots 01–02 (MailGuard phase) |
| Hr 3 | Screenshots 03–05 (Okta + SigninLogs phase) |
| Hr 4 | Screenshots 06–07 (CrowdStrike phase) |
| Hr 5 | Screenshots 08–09 (PaloAlto phase) |
| Hr 6 | Screenshots 10–11 (AWS + GCP — even if 0 results) |
| Hr 7 | Screenshots 12–14 (Blast Radius + Mega Timeline) |
| Hr 8 | Fill README while lab still open |
| Hr 9 | GitHub push everything + verify all images load |

---

## Imperfect Reality Layer (Fill during lab)

- **False assumption I made:** _________________________
- **Failed query (exact KQL):** _________________________
- **Uncertainty moment:** _________________________
- **Schema field that was wrong:** _________________________

---

## MITRE Minimum 6 — Pre-filled (verify against your actual findings)

| # | Tactic | Technique | ID | Source |
|---|---|---|---|---|
| 1 | Initial Access | Phishing | T1566 | MailGuard |
| 2 | Credential Access | Valid Accounts | T1078 | Okta |
| 3 | Defense Evasion | MFA Bypass | T1556 | Okta MFA events |
| 4 | Execution | Malicious File | T1204 | CrowdStrike |
| 5 | Command & Control | App Layer Protocol | T1071 | PaloAlto outbound |
| 6 | Lateral Movement | Remote Services | T1021 | PaloAlto east-west |
| 7 | Collection | Data from Cloud | T1530 | GCP (detection gap) |
| 8 | Persistence | Cloud Account | T1098 | AWS (detection gap) |

---

## Detection Gaps — Pre-written for README

```
AWS CloudTrail: 0 results — AWSCloudTrail connector not configured.
GCPAuditLogs: 0 results — GCP Audit connector not configured.
Impact: Cloud persistence and data exfiltration unverifiable.
Recommendation: Enable AWS CloudTrail + GCP Audit log connectors in Sentinel.
This is a Tier 1 finding — blind spot in cloud logging = attacker can persist undetected.
```
