# SC01 — Brute Force Login Investigation

**Severity:** Critical | **Status:** Closed — True Positive | **Platform:** Microsoft Sentinel + Defender XDR

---

## S1 — Alert Summary & Severity Rubric

| Field | Detail |
| --- | --- |
| Alert Name | Multiple Failed Sign-In Attempts |
| Data Source | SigninLogs |
| Trigger | Threshold rule — repeated failed logins from single IP |
| Affected Account | testuser01@hurlysoclaboutlook.onmicrosoft.com |
| Source IP | 20.21.211.28 |
| Timeframe | 5/3/2026 — clustered within 5-minute windows |

**Severity Rubric:**

| Factor | Assessment |
| --- | --- |
| Volume of failures | High — 9 failed attempts from single IP over session |
| Successful login after failures? | ✅ YES — 4 successful logins confirmed from attacker IP |
| Known IP / TI match | Checked against ThreatIntelligenceIndicator |
| Blast radius | Single account — lateral movement must be investigated |

---

## S2 — 🔵 SC-200 Detection: Sentinel + Defender XDR

### Step 1 — Full Attack Pattern: All Failures from Attacker IP

Establish the full scope of failed attempts from the suspicious IP over 30 days.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "testuser01@hurlysoclaboutlook.onmicrosoft.com"
| where IPAddress == "20.21.211.28"
| where ResultType != 0
| project TimeGenerated, IPAddress, Location, UserAgent
| sort by TimeGenerated desc
```

**WHY:** Establish the full attack surface — how many failures came from this IP before a success. **WHAT:** Returns all failed authentication attempts from the attacker IP against the targeted account. **LIMITATION:** SigninLogs only covers Azure AD authentications — on-prem logins not visible here.

![SC01 Step 1 — Failed login pattern from attacker IP](https://github.com/hurlycabalan/Soc-Investigation/raw/main/SC-Series/SC01-BruteForce/screenshots/sc01-step1.png)

---

### Step 2 — Detection: Clustered Failure Spike

Isolate the brute force window — look for failures clustered in 5-minute bins.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 3
| sort by FailedAttempts desc
```

**WHY:** Confirm whether failures are clustered (brute force pattern) vs scattered (user error). **WHAT:** Groups failures by IP in 5-minute bins — a spike indicates automated attack behavior. **LIMITATION:** Single threshold filter — password spray uses distributed IPs and needs a broader multi-account query.

![SC01 Step 2 — Clustered failure spike detected](https://github.com/hurlycabalan/Soc-Investigation/raw/main/SC-Series/SC01-BruteForce/screenshots/sc01-step2.png)

---

### Step 3 — FP Branch: Successful Login Check

Critical step — did the attacker succeed? This determines TP escalation vs FP closure.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName == "testuser01@hurlysoclaboutlook.onmicrosoft.com"
| where IPAddress == "20.21.211.28"
| where ResultType == 0
| project TimeGenerated, IPAddress, Location, UserAgent
| sort by TimeGenerated desc
```

**WHY:** A successful login (ResultType 0) following the failure spike = account compromise. **WHAT:** Returns only successful authentications from the attacker IP — 4 results confirmed. **LIMITATION:** Successful login confirms access but does not confirm post-compromise actions — lateral movement investigation required.

![SC01 Step 3 — Successful logins from attacker IP confirmed](https://github.com/hurlycabalan/Soc-Investigation/raw/main/SC-Series/SC01-BruteForce/screenshots/sc01-step3.png)

---

### TP / FP Decision

| Signal | Finding |
| --- | --- |
| Failure spike confirmed | ✅ Yes — 9 failures, clustered in 5-minute windows |
| Successful login after spike | ✅ YES — 4 successful logins from same attacker IP |
| IP matches known TI | Checked against ThreatIntelligenceIndicator |
| **Verdict** | **🚨 TRUE POSITIVE — ACCOUNT COMPROMISED. ESCALATE IMMEDIATELY.** |

**Escalation:** Escalate to Tier 2 immediately — account compromise confirmed. Disable account, block IP, begin lateral movement investigation.

---

### Control Failure Identified

MFA was **not enforced** on the targeted account — brute force succeeded because no MFA challenge was presented after repeated failures. Account lockout policy also failed to trigger before attacker gained access.

---

### Closure Criteria

- [ ] Attacker IP blocked at Conditional Access or firewall
- [ ] Compromised account disabled immediately
- [ ] MFA enforced on all accounts — no exceptions
- [ ] Lateral movement investigation completed — no other accounts affected
- [ ] Session tokens revoked for compromised account
- [ ] Incident closed in Sentinel with TP + Compromise classification

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Account Manipulation (possible post-access) | T1098 |

---

## S4 — Mitigation

| Action | Owner | Priority |
| --- | --- | --- |
| Disable compromised account immediately | IAM team | Critical |
| Block source IP in Conditional Access | Identity/IAM team | Critical |
| Revoke all active sessions for account | IAM team | Critical |
| Enforce MFA on all accounts — no exceptions | IAM team | High |
| Enable Identity Protection risk policy — Block at High risk | Azure AD admin | High |
| Investigate lateral movement from compromised account | SOC Tier 2 | High |
| Lower alert threshold for failure spike | SOC / Sentinel admin | Medium |

---

## S5 — 🟠 AZ-500 Hardening (THEORETICAL — Hands-on Month 2–3)

> ⚠️ All items below are theoretical based on AZ-500 study. Not yet validated in live lab environment.

### D1 — Identity & Access Hardening

- **Conditional Access Policy:** Block sign-ins from high-risk locations and enforce MFA for all users — this attack would have been stopped at the MFA prompt.
- **Identity Protection:** Enable sign-in risk policy set to Block at High risk level — repeated failures from single IP should auto-block.
- **Named Locations:** Define trusted IP ranges — 20.21.211.28 would have been flagged immediately.

### D2 — Network Controls

- **Tenant Restrictions:** Limit which external tenants can authenticate.
- **Private Endpoints:** Reduce publicly exposed authentication surfaces where possible.

### D3 — Compute / Resource Controls

- Not primary attack surface for brute force — N/A for this scenario.

### D4 — Security Operations

- **Sentinel Analytics Rule:** Custom rule for 3+ failures from single IP within 5 minutes — auto-generate incident.
- **Playbook (Logic App):** Auto-disable account and notify IAM team on confirmed brute force + successful login combination.
- **Automation vs Playbook distinction:** Automation rules triage and assign — Playbooks execute response actions (account disable, IP block, session revocation).

---

## S6 — Lessons Learned & Interview Q&A

### Lessons Learned

1. **Always check for successful logins — never close on failures alone.** This case looked like a blocked attempt until Step 3 confirmed 4 successful logins from the same IP. Stopping at Step 2 would have been a missed compromise.
2. **MFA was the real gap.** One MFA prompt would have stopped this entire chain. The brute force succeeded not because detection failed — but because the control layer had a hole.
3. **ResultType codes matter.** Knowing that ResultType 0 = success and anything else = failure is the difference between catching a compromise and missing it.

---

### Interview Q&A

**Q: You get a brute force alert — what's the first thing you check?**
> Whether there was a successful login after the failure spike. That's the TP/FP pivot point. In this case, 4 successful logins confirmed account compromise — stopping at the failure count alone would have missed it.

**Q: How do you tell brute force from password spray?**
> Brute force = many failures against one account from one IP. Password spray = one or few failures across many accounts from distributed IPs. Different query approach — spray needs account-side grouping, not IP-side.

**Q: Alert fired, you found successful logins after failures — what do you do?**
> Escalate immediately as TP — account compromised. Disable the account, block the IP, revoke all active sessions. Then hand off to Tier 2 for lateral movement investigation. I don't wait for confirmation — the evidence is already strong.

**Q: What's the control failure in this scenario?**
> Two failures: MFA not enforced, and account lockout policy didn't trigger before the attacker got in. Either control alone could have stopped this. Both were missing.

---

*Portfolio case — SC01 | Microsoft Sentinel Training Lab | Hurly Cabalan*
