# SC-04 | Account Takeover — Credential Stuffing + MFA Fatigue

**Scenario ID:** SC-04  
**Classification:** Account Takeover (ATO)  
**Severity:** 🔴 Critical  
**Platform:** Microsoft Sentinel + Microsoft Defender XDR  
**Author:** Hurly Cabalan  
**Status:** Investigation Complete  

---

## S1 — Alert Summary

### Incident Trigger
Microsoft Sentinel Analytics Rule fired: **"Multiple Failed Sign-ins Followed by Successful Authentication — Impossible Travel Detected"**  
An external attacker used credential stuffing to bypass authentication, then exploited MFA fatigue (push bombing) to gain access to a valid user account. Post-compromise lateral movement was detected via CrowdStrike within 22 minutes.

### Severity Rubric

| Factor | Assessment | Score |
|---|---|---|
| **Impact** | Compromised account with access to corporate apps + email | Critical |
| **Confidence** | Failed login spike + impossible travel + post-auth anomaly | High |
| **Scope** | One account confirmed, lateral movement attempted | High |
| **Business Criticality** | User has access to ERP and HR systems | Critical |
| **Final Severity** | 🔴 **CRITICAL** | |

### Timeline Overview
```
02:14 UTC — 47 failed login attempts from 185.220.x.x (Tor exit node)
02:31 UTC — MFA push bombardment begins (14 push requests in 8 minutes)
02:39 UTC — User approves MFA push (fatigue/accident)
02:40 UTC — Successful authentication — New location: Frankfurt, Germany
02:41 UTC — User's last known location: Doha, Qatar (17 minutes prior)
02:52 UTC — Attacker accesses email, SharePoint, ERP portal
03:01 UTC — CrowdStrike: Remote tool download detected on user's endpoint
03:06 UTC — Sentinel incident created, SOC L1 assigned
```

---

## S2 — 🔵 SC-200 Investigation (Sentinel + Defender XDR)

### Hypothesis
> An external attacker obtained valid credentials (likely from a credential dump or phishing), attempted to bypass MFA via push fatigue, and successfully authenticated. Post-compromise activity suggests the goal is persistence and lateral movement, not just account access.

### Step 1 — Quantify Failed Logins (SigninLogs)
**What we're looking for:** Was this a brute force or credential stuffing pattern? Volume + source IP are key.

```kql
SigninLogs
| where TimeGenerated > ago(2h)
| where UserPrincipalName contains "victim@company.com"
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName, IPAddress, Location
| sort by FailCount desc
```

**Expected Result:** High fail count from a single non-Qatar IP — credential stuffing pattern.

**Actual Result:** ✅ 47 failures from 185.220.x.x (known Tor exit node) — **external attacker confirmed.**

---

### Step 2 — Confirm MFA Fatigue Pattern (Okta)
**What we're looking for:** Rapid MFA push requests in a short window = push bombing.

```kql
OktaV2_CL
| where TimeGenerated > ago(2h)
| where actor_displayName_s contains "VictimUser"
| where eventType_s contains "mfa"
| project TimeGenerated, actor_displayName_s, eventType_s,
          outcome_result_s, client_ipAddress_s
| sort by TimeGenerated asc
```

**Expected Result:** Multiple `mfa.challenge.sent` events followed by one `mfa.challenge.responded` — fatigue sequence.

**Actual Result:** ✅ 14 push requests in 8 minutes → 1 approved. **MFA fatigue confirmed.**

---

### Step 3 — Verify Impossible Travel
**What we're looking for:** Physical impossibility of the login sequence = compromised session, not the real user.

```kql
SigninLogs
| where TimeGenerated > ago(3h)
| where UserPrincipalName contains "victim@company.com"
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, Location, IPAddress, AppDisplayName
| sort by TimeGenerated asc
```

**Expected Result:** Prior successful login from Qatar, then login from Germany 17 minutes later.

**Actual Result:** ✅ Doha at 02:24 UTC → Frankfurt at 02:41 UTC. **Impossible travel — account is compromised.**

---

### Step 4 — Map Post-Compromise Activity (CrowdStrike)
**What we're looking for:** What did the attacker do after gaining access? Remote tools = persistence intent.

```kql
CrowdStrikeAlerts
| where TimeGenerated > ago(2h)
| where UserName contains "victimuser"
| where Severity in ("High", "Critical")
| project TimeGenerated, ComputerName, AlertType, UserName, Severity
| sort by TimeGenerated asc
```

**Expected Result:** Alerts for remote tool download and suspicious process execution post-authentication.

**Actual Result:** ✅ Alert: `"Remote Access Tool Download — ngrok"` on victim's endpoint. **Persistence attempt confirmed.**

---

### TP/FP Decision

| Signal | Weight |
|---|---|
| 47 failed logins from Tor exit node | ✅ Strong |
| 14 MFA push requests in 8 minutes | ✅ Strong |
| Successful auth from Frankfurt (impossible travel from Doha) | ✅ Strong |
| ngrok download 11 minutes post-auth | ✅ Strong |
| ERP + SharePoint access from new IP | ✅ Strong |

**VERDICT: ✅ TRUE POSITIVE — Account Takeover via Credential Stuffing + MFA Fatigue**

---

### FP Branch — Could This Be Legitimate?

**FP Scenario 1:** User is traveling to Germany and forgot about a prior Doha session.  
**Why Ruled Out:** 17-minute gap between Doha and Frankfurt is physically impossible. Flight time is 7+ hours.

**FP Scenario 2:** User approved MFA push accidentally but it was really them.  
**Why Ruled Out:** ngrok download immediately post-auth is not normal user behavior. No business justification.

**FP Scenario 3:** Pen test or red team activity.  
**Why Ruled Out:** No authorized pen test window in the change calendar for this period.

**FP Confidence: NONE — This is a confirmed TP.**

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Credential Stuffing | T1110.004 | 47 failed logins from Tor exit node |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | 14 push requests in 8 minutes |
| Initial Access | Valid Accounts | T1078 | Successful auth after MFA bypass |
| Discovery | Account Discovery | T1087 | Email and SharePoint enumeration |
| Persistence | Remote Access Software | T1219 | ngrok download on endpoint |
| Lateral Movement | Use Alternate Authentication Material | T1550 | Session token reuse post-ATO |

---

## S4 — Mitigation (Immediate Response)

### Containment
- [ ] Revoke all active sessions immediately via Entra ID (Revoke Sign-in Sessions)
- [ ] Disable account in Okta + Entra ID simultaneously
- [ ] Block source IP range (185.220.x.x Tor exit node) via Conditional Access
- [ ] Isolate endpoint via Defender for Endpoint — network isolation mode
- [ ] Reset credentials via out-of-band channel (call user directly — do not email)

### Evidence Preservation
- [ ] Export full SigninLogs for the account (last 30 days)
- [ ] Export Okta session and MFA challenge logs
- [ ] CrowdStrike timeline export for the endpoint
- [ ] Capture ngrok process tree and parent process

### User Communication
- [ ] Call user directly to confirm they did not initiate the logins
- [ ] Inform user of MFA fatigue risk — never approve unexpected push
- [ ] Guide user through credential reset process

---

## Control Failure Analysis

| Control | Expected Behavior | What Failed |
|---|---|---|
| **MFA (Push Notification)** | Prevent unauthorized access | Push-based MFA vulnerable to fatigue attack — no rate limiting |
| **Conditional Access** | Block sign-in from Tor exit nodes | Policy did not include known Tor IP ranges in Named Locations block |
| **Impossible Travel Detection** | Alert on physically impossible login sequence | Alert fired but after compromise was already complete — no automated block |
| **Endpoint Protection** | Block unauthorized remote access tools | ngrok is a legitimate tool — not flagged pre-execution, only post-download |

---

## S5 — 🟠 AZ-500 Hardening Recommendations (D1–D4)

> ⚠️ **THEORETICAL — Hands-on lab verification scheduled Month 2–3**

### D1 — Identity & Access
- **Switch from Push MFA to FIDO2/Authenticator Number Matching** — Eliminates push fatigue. User must enter a matching number shown on screen — accidental approval impossible.
- **Conditional Access — Block Tor/Anonymizer IPs** — Add known Tor exit node ranges to Named Locations and block sign-in. Free Threat Intelligence feeds available.
- **Conditional Access — Impossible Travel Policy** — Block authentication from locations physically impossible from prior session. Require re-authentication from a compliant device.
- **Identity Protection — Risk-Based Conditional Access** — Flag high-risk sign-ins (leaked credentials, impossible travel) and require step-up authentication automatically.

### D2 — Secure Networking
- **Named Locations Policy** — Define Qatar + approved geo as trusted. Require additional controls for sign-ins from outside trusted locations.
- **Azure Firewall / WAF** — Block known Tor exit node ranges at perimeter before authentication is even attempted.

### D3 — Compute + Storage
- **Defender for Endpoint — Attack Surface Reduction Rules** — Block download/execution of known remote access tools (ngrok, AnyDesk, TeamViewer) unless explicitly allowed by policy.
- **JIT VM Access** — For any VMs accessible post-compromise, JIT prevents lateral movement via RDP/SSH.

### D4 — Security Operations
- **Sentinel Automation Playbook** — Auto-revoke session and disable account when impossible travel alert fires. Remove the human latency from containment.
- **SOAR Response — MFA Spike Alert** — Auto-notify user and block further push requests when >5 MFA challenges in 5 minutes.
- **KQL Detection Rule** — Correlate failed logins + MFA spike + successful auth as a single chained detection, not three separate alerts.

---

## S6 — Lessons Learned & Interview Q&A

### What Went Wrong
1. **Push MFA is not phishing-resistant** — The weakest link was the MFA method itself. 14 pushes in 8 minutes should have auto-blocked. It didn't.
2. **Conditional Access had no Tor block** — A known high-risk IP range was not in the Named Locations blocklist. Basic hygiene gap.
3. **Impossible travel alert did not auto-contain** — The alert fired, but containment required manual SOC action. 15 minutes elapsed before response began.

### What Went Right
1. CrowdStrike detected ngrok download immediately — caught the persistence attempt early
2. Multi-signal correlation in Sentinel (SigninLogs + Okta + CrowdStrike) gave strong TP confidence quickly
3. Session revocation and account disable were executed within 20 minutes of incident creation

### Closure Criteria
- [ ] Account fully disabled, all sessions revoked
- [ ] Credentials reset via secure out-of-band channel
- [ ] Endpoint re-imaged (ngrok persistence eliminated)
- [ ] Conditional Access policy updated: Tor IP block + impossible travel auto-block
- [ ] MFA method upgraded to number matching for all users
- [ ] Post-mortem completed and distributed to security team
- [ ] User security awareness training assigned (MFA fatigue)

---

### Interview Q&A

**Q: How do you detect MFA fatigue vs. a legitimate user approving a push?**  
> A: Volume and timing are the tell. A legitimate MFA challenge is one push, one approval. MFA fatigue looks like 10–14 push requests in under 10 minutes. Nobody accidentally approves that many. In this case, 14 pushes in 8 minutes with the approval happening on push 14 — that's a fatigue pattern. Combine that with the source IP being a Tor exit node and you have high confidence it's an attack, not user error.

**Q: Why is push MFA weaker than other MFA methods?**  
> A: Push MFA doesn't require the user to prove they're looking at the same screen as the attacker. The user just taps "Approve" on their phone without verifying a code shown on the login page. FIDO2 keys and number-matching authenticator apps solve this — the user must enter a specific number that only appears if they're on the legitimate login page. Attacker can't replicate that without physical access to the user's device.

**Q: What's your first action when you confirm an ATO?**  
> A: Revoke sessions first, then disable the account. Revoking sessions kills the attacker's active access immediately, even before the account is formally disabled. Disabling without revoking first can leave active tokens alive for up to an hour depending on token lifetime settings. Speed matters — the attacker had ngrok running in under 12 minutes post-auth.

---

*Portfolio: [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)*  
*Scenario Chain: SC-01 → SC-02 → SC-03 → SC-04 → SC-05*
