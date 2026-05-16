# SC-02 | Insider Threat — Unauthorized Data Access & Exfiltration

**Scenario ID:** SC-02  
**Classification:** Insider Threat  
**Severity:** 🔴 High  
**Platform:** Microsoft Sentinel + Microsoft Defender XDR  
**Author:** Hurly Cabalan  
**Status:** Investigation Complete  

---

## S1 — Alert Summary

### Incident Trigger
Microsoft Sentinel Analytics Rule fired: **"Anomalous Data Access Volume — Privileged User"**  
A long-tenured employee with legitimate credentials began accessing HR and Finance file shares outside their normal scope, downloaded unusually large volumes of data, and attempted exfiltration via personal webmail.

### Severity Rubric

| Factor | Assessment | Score |
|---|---|---|
| **Impact** | Sensitive HR/Finance data at risk of exfiltration | High |
| **Confidence** | Behavioral anomaly + DLP alert correlated | High |
| **Scope** | Single user, multiple sensitive systems accessed | Medium |
| **Business Criticality** | HR/Payroll data = regulatory exposure (PDPA/GDPR) | High |
| **Final Severity** | 🔴 **HIGH** | |

### Timeline Overview
```
09:12 UTC — User authenticates via Okta SSO (normal location, normal time)
09:47 UTC — File share access begins: HR folder (outside role scope)
10:03 UTC — Finance folder accessed, 2.3 GB download detected
10:31 UTC — Outbound transfer attempt to personal Gmail (blocked by DLP)
10:45 UTC — CrowdStrike: Suspicious PowerShell data staging alert fires
11:00 UTC — Sentinel incident created, SOC L1 assigned
```

---

## S2 — 🔵 SC-200 Investigation (Sentinel + Defender XDR)

### Hypothesis
> A legitimate user is abusing their access to collect and exfiltrate sensitive organizational data. The behavior pattern suggests premeditated intent — the access scope, volume, and exfiltration attempt are inconsistent with their job role.

### Step 1 — Confirm Authentication (Okta)
**What we're looking for:** Was this the real user, or is the account already compromised?

```kql
OktaV2_CL
| where TimeGenerated > ago(12h)
| where actor_displayName_s contains "SuspectUser"
| where eventType_s == "user.session.start"
| project TimeGenerated, actor_displayName_s, client_ipAddress_s,
          client_geographicalContext_city_s, outcome_result_s
| sort by TimeGenerated asc
```

**Expected Result:** Authentication from known office IP, no MFA failures — confirms this is the real user, not an external attacker using stolen creds.

**Actual Result:** ✅ Login from registered device, Qatar office IP, MFA passed — **insider confirmed, not account compromise.**

---

### Step 2 — Map Data Access Scope (SigninLogs)
**What we're looking for:** Which apps/systems did they access that are outside their normal role?

```kql
SigninLogs
| where TimeGenerated > ago(12h)
| where UserPrincipalName contains "suspectuser@company.com"
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
| sort by TimeGenerated asc
```

**Expected Result:** Access to HR Management System and Finance Portal — outside normal Sales role scope.

**Actual Result:** ✅ Confirmed access to HRConnect and FinancePortal apps — **role boundary violation.**

---

### Step 3 — Quantify Data Volume (CrowdStrike)
**What we're looking for:** What did they actually do on the endpoint after accessing those systems?

```kql
CrowdStrikeAlerts
| where TimeGenerated > ago(12h)
| where UserName contains "suspectuser"
| where Severity in ("High", "Medium")
| project TimeGenerated, ComputerName, AlertType, UserName, Severity
| sort by TimeGenerated asc
```

**Expected Result:** Data staging activity — large file copy, PowerShell compression commands.

**Actual Result:** ✅ Alert: `"Suspicious PowerShell — Compress-Archive on HR directory"` — **staging for exfiltration confirmed.**

---

### Step 4 — Correlate Volume Pattern
**What we're looking for:** Is this a one-time spike or a pattern building over days?

```kql
OktaV2_CL
| where TimeGenerated > ago(7d)
| where actor_displayName_s contains "SuspectUser"
| where eventType_s == "user.authentication.sso"
| summarize DailyLogins = count() by bin(TimeGenerated, 1d)
| sort by TimeGenerated asc
```

**Expected Result:** Baseline of 1–2 app logins/day. Spike to 12 on incident day.

**Actual Result:** ✅ Confirmed spike — **behavioral deviation from 7-day baseline.**

---

### TP/FP Decision

| Signal | Weight |
|---|---|
| Role boundary violation (HR + Finance access) | ✅ Strong |
| 2.3 GB download in 18 minutes | ✅ Strong |
| PowerShell Compress-Archive on HR directory | ✅ Strong |
| Exfiltration attempt to personal Gmail (blocked) | ✅ Strong |
| Authentication from known IP, MFA passed | Confirms insider — not ATO |

**VERDICT: ✅ TRUE POSITIVE — Insider Threat, Intentional Data Exfiltration Attempt**

---

### FP Branch — Could This Be Legitimate?

**FP Scenario:** User was assigned temporary HR/Finance access for a project and was archiving data for IT migration.

**Why Ruled Out:**
- No change ticket or IT request linked to this user for that period
- Personal Gmail as exfiltration destination ≠ IT migration workflow
- PowerShell Compress-Archive not standard IT tooling in this environment
- No manager approval in ITSM system

**FP Confidence: LOW — This is a TP.**

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | Legitimate SSO login with MFA |
| Discovery | File and Directory Discovery | T1083 | Access to HR/Finance directories |
| Collection | Data from Local System | T1005 | 2.3 GB download from file shares |
| Collection | Archive Collected Data | T1560 | PowerShell Compress-Archive |
| Exfiltration | Exfiltration Over Web Service | T1567 | Gmail upload attempt |
| Defense Evasion | Valid Accounts (blend with normal traffic) | T1078 | No initial anomaly — behavioral drift only |

---

## S4 — Mitigation (Immediate Response)

### Containment
- [ ] Suspend user account immediately via Okta (disable SSO + all active sessions)
- [ ] Revoke all active tokens and app authorizations
- [ ] Block outbound transfers from user's device via Defender for Endpoint
- [ ] Preserve endpoint forensic image before any HR/IT action
- [ ] Escalate to HR + Legal — insider threat = HR protocol, not just IT

### Evidence Preservation
- [ ] Export Okta session logs for the past 30 days
- [ ] Capture CrowdStrike timeline for the endpoint
- [ ] Pull DLP logs for the blocked Gmail transfer attempt
- [ ] Screenshot all Sentinel alerts and incident timeline

### Communication
- [ ] Notify SOC L2/L3 and Incident Response team
- [ ] Do NOT alert the user — preserve investigation integrity
- [ ] Loop in Legal and HR as per insider threat policy

---

## Control Failure Analysis

| Control | Expected Behavior | What Failed |
|---|---|---|
| **RBAC / Least Privilege** | User should not access HR/Finance systems | Role assignment too broad — no least-privilege enforcement |
| **UEBA / Behavioral Analytics** | Alert on access volume anomaly earlier | Alert fired 48 minutes after access began — detection lag |
| **DLP Policy** | Block + alert on large file upload to personal email | DLP blocked transfer but did not trigger SOC alert in real-time |
| **Privileged Access Review** | Quarterly access reviews | Access scope not reviewed — dormant over-privilege |

---

## S5 — 🟠 AZ-500 Hardening Recommendations (D1–D4)

> ⚠️ **THEORETICAL — Hands-on lab verification scheduled Month 2–3**

### D1 — Identity & Access
- **Implement PIM (Privileged Identity Management)** — Just-in-time access for HR/Finance systems. No standing access. Access expires after defined window.
- **Conditional Access Policy** — Require compliant device + MFA re-challenge when accessing sensitive app categories outside business hours.
- **Access Reviews** — Quarterly automated reviews via Entra ID Governance. Auto-revoke if manager does not recertify.

### D2 — Secure Networking
- **Private Endpoints** — HR and Finance file shares should not be accessible from general corporate network. Scope access to approved subnets only.
- **Network segmentation** — VLAN separation between Sales and HR/Finance systems.

### D3 — Compute + Storage
- **Microsoft Purview DLP** — Tighten policy to trigger SOC alert (not just block) on bulk download + external upload within same session window.
- **Storage Account Firewall** — Restrict access to approved IPs only. No public endpoint.

### D4 — Security Operations
- **UEBA Rule Tuning** — Lower detection threshold: alert on >500 MB download in 30 minutes for non-IT users.
- **Sentinel Watchlist — Sensitive Users** — Add HR, Finance, and C-suite to watchlist. Apply stricter analytics rules to this cohort.
- **Automation Playbook** — Auto-suspend Okta session when DLP high-volume alert fires. Remove manual handoff delay.

---

## S6 — Lessons Learned & Interview Q&A

### What Went Wrong
1. **Over-permissioned role** — Sales user retained legacy access from a previous cross-team project, never cleaned up.
2. **DLP-to-SOC gap** — DLP blocked the transfer but the SOC alert took 15 minutes to populate in Sentinel. Real-time integration needed.
3. **No behavioral baseline** — UEBA had no established baseline for this user, so the spike only triggered after significant data was already staged.

### What Went Right
1. DLP policy stopped the exfiltration at the perimeter
2. CrowdStrike telemetry captured the PowerShell staging activity
3. Multi-source correlation (Okta + Defender + CrowdStrike) provided strong TP confidence

### Closure Criteria
- [ ] User account suspended and all sessions terminated
- [ ] Legal and HR notified with full evidence package
- [ ] RBAC reviewed and over-permissions removed for similar role profiles
- [ ] DLP policy updated to trigger real-time SOC alert
- [ ] Sentinel UEBA baseline reinitialized for affected user cohort
- [ ] Incident post-mortem completed within 5 business days

---

### Interview Q&A

**Q: How do you distinguish an insider threat from an account takeover?**  
> A: The authentication context is the first pivot. If MFA passed, the device is registered, and the IP is the known office range — you're likely dealing with the real user. Account takeover usually shows login from an anomalous IP or location, often with MFA failures first. In this case, authentication was clean. The behavior after login — role boundary violations and exfiltration attempt — is what confirmed insider intent.

**Q: What's the first thing you do when you suspect an insider threat?**  
> A: Preserve evidence first, contain second. Unlike external threats, insider cases often involve HR and Legal. If you disable the account too early without capturing forensic logs, you might compromise the investigation chain. The right order is: capture Okta + endpoint + DLP logs → escalate to L2 + HR + Legal → then contain.

**Q: Why is RBAC the root cause here, not a SOC detection failure?**  
> A: The SOC detected it — eventually. But the attacker (insider) had standing access they shouldn't have had. If least privilege was enforced via PIM, this user would have needed explicit approval to access HR or Finance resources. The exfiltration attempt would never have gotten as far as it did. Detection is the last line of defense. Prevention via proper access controls is the first.

---

*Portfolio: [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)*  
*Scenario Chain: SC-01 → SC-02 → SC-03 → SC-04 → SC-05*
