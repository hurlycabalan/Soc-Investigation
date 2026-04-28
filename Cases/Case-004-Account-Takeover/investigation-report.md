# Case 004 — Account Takeover Investigation Report
**Analyst:** Hurly Cabalan  
**Date:** 2025-03-15  
**Severity:** 🔴 High  
**Status:** Closed — Confirmed Breach  
**MITRE ATT&CK:** T1110.003 · T1621 · T1078 · T1114.001 · T1567.002

---

## 📋 Table of Contents
1. [Executive Summary](#executive-summary)
2. [Scenario Background](#scenario-background)
3. [Phase 1 — Alert Triage](#phase-1--alert-triage)
4. [Phase 2 — Password Spray Detection](#phase-2--password-spray-detection)
5. [Phase 3 — MFA Fatigue Analysis](#phase-3--mfa-fatigue-analysis)
6. [Phase 4 — Account Compromise Confirmation](#phase-4--account-compromise-confirmation)
7. [Phase 5 — Persistence & Post-Compromise Activity](#phase-5--persistence--post-compromise-activity)
8. [Phase 6 — Exfiltration Indicators](#phase-6--exfiltration-indicators)
9. [Attack Timeline](#attack-timeline)
10. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
11. [Containment Actions](#containment-actions)
12. [Recommendations](#recommendations)

---

## Executive Summary

On March 15, 2025, Microsoft Sentinel triggered a high-severity incident alerting on a suspected account takeover targeting **sarah.almansouri@contoso.com**, a Finance Manager in the Doha office.

Investigation confirmed a multi-stage attack: the threat actor conducted a **password spray** across 47 accounts before successfully authenticating as Sarah. Upon triggering MFA, the actor launched a sustained **MFA fatigue (push bombing)** campaign until the user approved a fraudulent request. Following initial access, the attacker **registered a new MFA device**, created a **hidden inbox rule** to suppress security alerts, and accessed **SharePoint financial documents** consistent with data exfiltration intent.

The account was revoked and remediated. No confirmed data exfiltration was verified, but the access pattern indicated high exfiltration risk.

---

## Scenario Background

| Field | Detail |
|---|---|
| **Victim Account** | sarah.almansouri@contoso.com |
| **Role** | Finance Manager |
| **Department** | Finance — Doha HQ |
| **Attack Start** | 2025-03-15T01:14:22Z |
| **Initial Access Confirmed** | 2025-03-15T02:47:11Z |
| **Detection by Sentinel** | 2025-03-15T03:05:00Z |
| **Attacker IP (Primary)** | 185.220.101.47 |
| **Attacker IP (Secondary)** | 45.142.212.100 |
| **IP Geolocation** | Netherlands / Romania (Tor exit nodes) |
| **User's Usual Location** | Qatar (Doha) |

**Simulated threat context:** The attacker obtained a partial credential list from a prior dark web leak of corporate email addresses. The password spray used a short list of common enterprise passwords. Sarah's account had a weak legacy password not updated after the last company-wide reset.

---

## Phase 1 — Alert Triage

### 🎬 Scene 1 — Sentinel Incident Queue

You arrive at your shift and open **Microsoft Sentinel → Incidents**. A high-severity incident is waiting:

> **Incident #2041**  
> Title: *Multiple failed sign-ins followed by successful login from anomalous IP*  
> Severity: High | Status: New | Assigned to: Unassigned  
> Entities: sarah.almansouri@contoso.com · 185.220.101.47

**📸 SCREENSHOT 1** — `Sentinel Incidents blade` showing Incident #2041 at the top of the queue with High severity, timestamp, and entity tags visible.

You assign the incident to yourself and open it. The incident is correlated from two analytics rules:
- *Successful Sign-in After Multiple Failures* (built-in)
- *Sign-in from Known Tor Exit Node* (custom rule)

**📸 SCREENSHOT 2** — `Incident details panel` showing both correlated alerts, the entity timeline, and the two triggering rules listed under "Evidence."

You note the entities: one user account, two IPs. You begin the investigation by pivoting to the **Investigation Graph**.

**📸 SCREENSHOT 3** — `Incident Investigation Graph` with sarah.almansouri node connected to 185.220.101.47 and the sign-in event cluster. Expand the node to show related alerts.

---

## Phase 2 — Password Spray Detection

### 🎬 Scene 2 — Identifying the Spray Pattern

You run your first KQL query against **SigninLogs** to establish the scope of failed logins from the attacker IP.

> 📄 See `kql-queries.md` → Query 01: Password Spray — Failed Logins by IP

**Results returned:** 47 unique accounts targeted. 46 failed. 1 succeeded — sarah.almansouri@contoso.com.

**📸 SCREENSHOT 4** — `Log Analytics query results` showing the KQL output: table with UserPrincipalName, FailureCount, SuccessCount columns. Sarah's row shows 3 failures then 1 success. All other rows show failures only.

Key observations from the results:
- The attacker tried only **2–3 passwords per account** — classic spray pattern to avoid lockout thresholds
- All attempts occurred within a **52-minute window** (01:14 → 02:06 UTC)
- The source IP **185.220.101.47** is a known Tor exit node (confirmed via threat intelligence)
- A secondary IP **45.142.212.100** was used for 6 of the attempts — likely a backup proxy

**📸 SCREENSHOT 5** — `Threat Intelligence blade` showing 185.220.101.47 flagged as malicious with TI source, confidence score, and threat type (Anonymizer/Tor).

---

## Phase 3 — MFA Fatigue Analysis

### 🎬 Scene 3 — The Push Bombing Window

Sarah's password was correctly entered at **02:06:44Z**. At this point, Entra ID triggered an MFA push notification to her phone. The attacker could not proceed without her approval.

What followed was a sustained push bombing campaign.

> 📄 See `kql-queries.md` → Query 02: MFA Fatigue — Repeated Push Requests

**📸 SCREENSHOT 6** — `KQL results` showing the MFA request timeline: 14 MFA push requests sent between 02:06 and 02:47 UTC. Column view: TimeGenerated, UserPrincipalName, ResultType, AuthenticationDetail. The first 13 rows show "MFA denied by user" or "MFA timed out." Row 14 shows "MFA successfully completed."

**Key finding:** The attacker sent **14 consecutive MFA push requests over 41 minutes**. Sarah approved the 14th request at **02:47:11Z** — likely from fatigue or confusion ("I keep getting notifications, maybe I accidentally triggered one").

This is **T1621 — Multi-Factor Authentication Request Generation**, also known as MFA Fatigue or Push Bombing.

**📸 SCREENSHOT 7** — `SigninLogs entry detail` for the successful MFA approval at 02:47:11Z — expanded JSON showing AuthenticationRequirement, MFA detail, IP address, and DeviceDetail fields.

---

## Phase 4 — Account Compromise Confirmation

### 🎬 Scene 4 — First Malicious Session

With MFA approved, the attacker now has a live authenticated session.

> 📄 See `kql-queries.md` → Query 03: Post-Authentication Session from Attacker IP

**📸 SCREENSHOT 8** — `Query results` showing the first successful session: TimeGenerated 02:47:11Z, IPAddress 185.220.101.47, Location Netherlands, UserAgent "python-requests/2.28.0" — a non-browser user agent confirming automated tooling.

The UserAgent **python-requests/2.28.0** is a significant red flag — legitimate users do not authenticate via Python scripts. This confirms the attacker is using an automated tool (likely a credential stuffing / ATO toolkit).

**📸 SCREENSHOT 9** — `User entity page` for sarah.almansouri — scroll to the Activity section showing the anomalous sign-in from Netherlands flagged against her baseline (all previous logins from Qatar, using Chrome on Windows).

---

## Phase 5 — Persistence & Post-Compromise Activity

### 🎬 Scene 5 — Locking In the Backdoor

Attackers with account access rarely rely solely on the stolen password — they establish persistence immediately in case the victim changes their password.

You pivot to **AuditLogs** to look for post-compromise changes.

> 📄 See `kql-queries.md` → Query 04: MFA Device Registration After Compromise

**📸 SCREENSHOT 10** — `AuditLogs KQL results` showing a new Authenticator app registration at **02:51:33Z** — just 4 minutes after initial access. OperationName: "Update user" / "User registered security info." InitiatedBy: sarah.almansouri (attacker-controlled session). Target device: new TOTP authenticator.

**Finding:** The attacker registered their own MFA device in under 5 minutes. Even if Sarah changes her password, the attacker retains access. This is **T1078 — Valid Accounts** (persistence via legitimate credential modification).

### 🎬 Scene 6 — Hiding the Evidence

Next you check for **inbox manipulation rules** — a classic technique to suppress security notification emails.

> 📄 See `kql-queries.md` → Query 05: Suspicious Inbox Rule Creation

**📸 SCREENSHOT 11** — `OfficeActivity or AuditLogs results` showing inbox rule created at **02:53:17Z**: Rule name "." (single dot — designed to be invisible), conditions: subject contains "Microsoft account", "Security alert", "Unusual sign-in" → action: move to Deleted Items and mark as read.

This is **T1114.001 — Email Collection: Local Email Collection** (inbox rule abuse). The attacker is suppressing all Microsoft security alert emails so Sarah never sees the "new device registered" notification.

---

## Phase 6 — Exfiltration Indicators

### 🎬 Scene 7 — Following the Data

With persistence established and alerts suppressed, the attacker begins accessing sensitive data.

> 📄 See `kql-queries.md` → Query 06: SharePoint/OneDrive File Access Post-Compromise

**📸 SCREENSHOT 12** — `OfficeActivity query results` filtered for sarah.almansouri between 02:47Z and 04:30Z. Table showing: OfficeObjectId (file paths), Operation (FileAccessed, FileDownloaded), ClientIP 185.220.101.47. Key files accessed:
- `/Finance/Q1-2025-Budget-Final.xlsx`
- `/Finance/Vendor-Contracts-2025.pdf`
- `/Finance/Payroll-March-2025.xlsx`

**📸 SCREENSHOT 13** — `CloudAppEvents or OfficeActivity` showing a FileDownloaded event for `Payroll-March-2025.xlsx` at 03:18:44Z from the attacker IP — this is the most critical finding, indicating likely successful exfiltration of payroll data.

**Finding:** Three high-value financial documents were accessed. One confirmed download. This activity maps to **T1567.002 — Exfiltration Over Web Service** — data accessed via Microsoft 365 cloud services from an external threat actor IP.

**📸 SCREENSHOT 14** — `Microsoft Defender for Cloud Apps (MCAS) anomaly alert` (if available in your environment) showing the "Unusual file download" alert triggered for sarah.almansouri — volume and file sensitivity score.

---

## Attack Timeline

```
01:14:22Z  ── Password spray begins (185.220.101.47)
              47 accounts targeted over 52 minutes
              46 accounts: authentication failed
              
02:06:44Z  ── Sarah's password successfully matched
              MFA push notification sent to her phone
              
02:06 – 02:47  ── MFA push bombing (14 requests)
                  Sarah receives repeated notifications
                  
02:47:11Z  ── Sarah approves MFA push (fatigue)
              Attacker gains authenticated session
              
02:51:33Z  ── Attacker registers new MFA device
              Persistence established (T1078)
              
02:53:17Z  ── Hidden inbox rule created
              Security alerts suppressed (T1114.001)
              
02:55Z – 03:30Z  ── SharePoint file enumeration
                    Finance documents accessed
                    
03:18:44Z  ── Payroll-March-2025.xlsx downloaded
              Likely exfiltration confirmed (T1567.002)
              
03:05:00Z  ── Sentinel alert fires (slight lag from ingestion)

03:45:00Z  ── SOC analyst (Hurly) picks up Incident #2041

04:10:00Z  ── Account revoked, MFA devices cleared
              Active session terminated
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Password Spraying | T1110.003 | 47 accounts, 2–3 attempts each, 52-min window |
| Credential Access | MFA Request Generation | T1621 | 14 push requests over 41 minutes |
| Persistence | Valid Accounts | T1078 | New MFA device registered 4 min post-compromise |
| Collection | Email Collection: Inbox Rule | T1114.001 | Hidden rule suppressing security alert emails |
| Exfiltration | Exfiltration Over Web Service | T1567.002 | Financial documents accessed and downloaded |

---

## Containment Actions

| Action | Performed By | Time |
|---|---|---|
| Revoke all active sessions (Entra ID) | SOC Analyst | 04:10Z |
| Disable account pending investigation | SOC Analyst | 04:10Z |
| Remove unauthorized MFA device | Identity Admin | 04:15Z |
| Delete malicious inbox rule | Identity Admin | 04:17Z |
| Block attacker IPs at Conditional Access | SOC Analyst | 04:20Z |
| Notify user and HR | SOC Lead | 04:30Z |
| Force password reset on all 47 targeted accounts | Identity Admin | 05:00Z |

---

## Recommendations

**Immediate (0–7 days)**
- Enable **Number Matching** for MFA push notifications — forces user to match a displayed number before approving, defeats push bombing
- Enable **Additional Context** in Authenticator — shows app name and location in push notification so users can identify fraudulent requests
- Block **legacy authentication protocols** via Conditional Access — eliminates token-based spray vectors
- Alert on **MFA device registration outside trusted networks**

**Short Term (1–4 weeks)**
- Implement **Conditional Access policy** requiring compliant/Entra-joined device for Finance department
- Enable **Microsoft Defender for Identity** anomaly alerts for inbox rule creation
- Run **Security Awareness Training** for Finance team focused on MFA fatigue attacks

**Long Term**
- Migrate high-risk users (Finance, HR, Exec) to **Phishing-Resistant MFA** (FIDO2 / Windows Hello for Business)
- Implement **Privileged Identity Management (PIM)** for finance document access
- Review SharePoint permissions — payroll files should not be accessible to standard M365 sessions without additional verification

---

*Investigation conducted using Microsoft Sentinel, KQL (Kusto Query Language), Microsoft Entra ID audit logs, and OfficeActivity logs. All findings mapped to MITRE ATT&CK Enterprise Framework v14.*
