# Exercise 07 — Okta MFA Factor Manipulation

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%)  
**Rule:** `Lab Stage E3 - MFA Factor Manipulation (Okta)`  
**Difficulty:** Intermediate | **Status:** ✅ Complete

---

## What This Exercise Covers

An attacker who compromises an account but leaves MFA in place will eventually be blocked or detected. The next move is to **remove or replace the MFA factor** — registering their own device, guaranteeing persistent access. This exercise detects that exact pattern: MFA lifecycle events in Okta correlated with foreign logins, producing a high-fidelity identity-based detection. This maps to Stage 4 of the lab attack chain (Account Takeover) and represents one of the highest-value identity detection patterns for any SOC.

---

## Attack Context

**Lab Attack Stage 4 — Credential Access / Account Takeover**

After the attacker gains Okta credentials (via phishing in S1 + credential dump in S3), they:
1. Log in from a foreign IP (foreign country login = immediate suspicion)
2. Deactivate the victim's existing MFA factor
3. Re-enrol their own MFA device
4. Now have persistent, MFA-protected access — even after the victim's password is reset

If the SOC only monitors for failed logins, this attack succeeds silently.

---

## Relevant Okta Event Types

| Event Type | Description | Severity Signal |
|------------|-------------|-----------------|
| `user.mfa.factor.deactivate` | MFA factor removed from user | High |
| `user.mfa.factor.reset_all` | All MFA factors cleared | Critical |
| `user.mfa.factor.update` | MFA factor configuration changed | Medium |

**Lab note:** Table is `OktaV2_CL` — NOT `OktaSystemLogs`. Know this distinction cold.

---

## Lab Steps Completed

### Step 1 — Verify Data Availability

Confirmed MFA manipulation events were present in the workspace.

```kql
OktaV2_CL
| where TimeGenerated > ago(4h)
| where EventOriginalType has "mfa"
| project TimeGenerated, ActorUsername, EventOriginalType, EventMessage, SrcIpAddr, SrcGeoCountry
```

**Why `has` instead of `==`:** `has` performs a whole-word match (faster than `contains` for indexed fields). Here it catches all `user.mfa.*` event types in one filter without listing each one.

📸 *[Screenshot — OktaV2_CL query results showing MFA events with country and IP context]*

---

### Step 2 — Review the Base Detection Query

Examined the existing rule logic in `Lab Stage E3 - MFA Factor Manipulation (Okta)`.

**Base query — standalone MFA event detection:**

```kql
OktaV2_CL
| where EventOriginalType in ("user.mfa.factor.deactivate",
    "user.mfa.factor.reset_all", "user.mfa.factor.update")
| where OriginalOutcomeResult == "SUCCESS"
| project
    TimeGenerated,
    ActorUsername,
    EventOriginalType,
    SrcIpAddr,
    SrcGeoCountry,
    SrcGeoCity
| extend
    AccountUpn = ActorUsername,
    RemoteIP = SrcIpAddr
```

**Why filter on `SUCCESS`:** Failed MFA changes are noisy and less actionable — a failed deactivation attempt means the attacker was blocked. Successful changes mean the attack landed. Filter to what matters.

📸 *[Screenshot — base detection query results showing MFA events with geolocation fields]*

---

### Step 3 — Add Correlation with Stage 4 (Foreign Login → MFA Change)

Enhanced the detection by correlating a foreign login with a subsequent MFA change within 30 minutes — a much higher-fidelity signal.

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
| project
    LoginTime,
    MfaTime,
    ActorUsername,
    SrcIpAddr,
    SrcGeoCountry,
    MfaAction = EventOriginalType
| extend
    TimeGenerated = LoginTime,
    AccountUpn = ActorUsername,
    RemoteIP = SrcIpAddr,
    ReportId = tostring(hash_sha256(strcat(ActorUsername, tostring(MfaTime))))
```

> ⚠️ **Lab-level KQL** — uses `let` variables, `between`, `join kind=inner` on multiple keys, `hash_sha256()`. Beyond SC-200 exam scope. **SC-200 relevance:** `join kind=inner`, `where OriginalOutcomeResult == "SUCCESS"`, and the `in` operator are core exam topics.

**Why same IP join (`on ActorUsername, SrcIpAddr`):** Requiring BOTH the same username AND the same source IP eliminates coincidental matches — foreign login from IP X followed by MFA change from IP X on the same account is extremely suspicious. Different IP would be a looser correlation (still suspicious, but lower fidelity).

📸 *[Screenshot — correlated query results showing LoginTime → MfaTime sequence with 30-minute window]*

---

### Step 4 — Enable and Verify

Saved the correlated query, enabled the rule, and verified alert firing with correct entity mapping.

**Entity mapping confirmed:**

| Field | Entity Type |
|-------|------------|
| `AccountUpn` ← `ActorUsername` | User (impacted identity) |
| `RemoteIP` ← `SrcIpAddr` | IP (attack origin) |

📸 *[Screenshot — rule enabled in Custom Detection Rules list]*  
📸 *[Screenshot — triggered alert showing entity mapping with AccountUpn and RemoteIP populated]*

---

## Geolocation Enrichment — Why It Matters

| Column | Example | Analyst Use |
|--------|---------|-------------|
| `SrcGeoCountry` | `RU` | Flag foreign-origin MFA changes immediately |
| `SrcGeoCity` | `Moscow` | Pinpoint location for threat intel correlation |
| `SrcIpAddr` | `198.51.100.42` | Cross-reference against TI feed (Ex02) |

**Key analyst question:** "Does the user regularly log in from this country?" If yes → FP branch. If no (first-time country) → TP escalation.

---

## FP Branch Analysis

**What would make this a False Positive?**

| Evidence | Conclusion |
|----------|-----------|
| User was travelling to `SrcGeoCountry` on that date | FP — verify via HR/calendar |
| IT helpdesk reset MFA on behalf of user (different actor) | FP — check `ActorUsername` vs target user |
| VPN exit node in foreign country | FP — check if company has VPN exits in that country |
| User enrolled new phone/authenticator (known device change) | Context-dependent — verify with user |

**What confirms a TP?**

| Evidence | Conclusion |
|----------|-----------|
| User has no travel record for that country | TP — account taken over |
| MFA change followed credential-dump alert (S3) | TP — confirmed attack chain |
| New MFA factor enrolled from same foreign IP within 5 min | TP — attacker registered their own device |
| User reports not initiating the change | TP — immediate containment |

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| Identity event filtering in OktaV2_CL | D3 Sentinel | Custom log table queries |
| `in` operator for multi-value event filter | D3 Sentinel | KQL operators |
| `join kind=inner` for event correlation | D3 Sentinel | KQL joins |
| Geolocation fields for enrichment | D3 Sentinel | Alert enrichment |
| Entity mapping (AccountUpn, RemoteIP) | D1 Defender XDR | Custom detection entity mapping |
| TP/FP analysis for identity alerts | D3 Sentinel | Incident investigation |

---

## MITRE ATT&CK

| Technique | ID | Description |
|-----------|----|-------------|
| Modify Authentication Process: MFA | T1556.006 | Disabling or replacing MFA factors post-compromise |
| Valid Accounts: Cloud Accounts | T1078.004 | Using stolen credentials to authenticate |
| Account Manipulation | T1098 | Modifying account MFA to maintain persistent access |

---

## Key Takeaways

- MFA lifecycle events (`deactivate`, `reset_all`, `update`) are **critical post-compromise signals** — if an attacker has credentials, MFA manipulation is often the very next step
- Standalone MFA events are Medium fidelity. MFA event **correlated with a foreign login within 30 minutes** = High/Critical fidelity
- Always filter on `OriginalOutcomeResult == "SUCCESS"` for MFA change events — failed attempts are noise
- `SrcGeoCountry` is a built-in Okta field — no enrichment needed. Use it in every Okta identity query
- The `between (LoginTime .. LoginTime + 30m)` time-window correlation pattern is reusable across any identity attack scenario — foreign login → privilege change, failed login → successful login from different IP
- `OktaV2_CL` is the correct table name in this lab. Never use `OktaSystemLogs` here.
