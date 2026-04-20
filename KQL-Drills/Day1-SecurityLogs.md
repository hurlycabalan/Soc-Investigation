# KQL Daily Drills — Day 1
**Analyst:** Hurly Cabalan  
**Environment:** Azure Data Explorer — SecurityLogs Database  
**Date:** April 2026  
**Scenario:** Suspicious authentication activity detected — possible brute force and phishing campaign  

---

## Scenario Overview

The SOC team received alerts on unusual authentication failures and suspicious email patterns. The following KQL queries were written and executed to investigate the scope of the activity, identify threat actors, and support incident response actions.

---

## Drill 1 — Failed Login Count by Username

**Objective:** Identify which user accounts are being targeted by failed authentication attempts.

**MITRE ATT&CK:** `T1110.001 — Brute Force: Password Guessing`

```kql
AuthenticationEvents
| where result == "Failed Login"
| summarize FailedAttempts = count() by username
| order by FailedAttempts desc
```

**Screenshot — Query Results:**  
![Drill 1 - Failed logins by username](https://raw.githubusercontent.com/hurlycabalan/Soc-Investigation/main/KQL-Drills/Drill2.png)

**Finding:**  
User `jadenman` recorded 22 failed login attempts — significantly above the normal threshold. This pattern is consistent with an automated brute force or password spraying attack targeting a specific account.

**Analysis:**  
- 22 failed attempts against a single account in a short window is a strong brute force indicator
- Account may be locked depending on policy thresholds
- Requires cross-referencing with successful logins to determine if the attack succeeded

**Next Steps (SOC Response):**
- Check if `jadenman` had any successful logins after the failed attempts
- Review source IPs behind the failed attempts (see Drill 2)
- Notify account owner and temporarily lock account pending investigation
- Escalate to Tier 2 if successful login is confirmed post-failed-attempts

---

## Drill 2 — Failed Login Count by Source IP

**Objective:** Identify which IP addresses are the source of the failed authentication attempts.

**MITRE ATT&CK:** `T1110 — Brute Force` | `T1078 — Valid Accounts`

```kql
AuthenticationEvents
| where result == "Failed Login"
| summarize FailedAttempts = count() by src_ip
| order by FailedAttempts desc
```

**Screenshot — Query Results:**  
![Drill 2 - Failed logins by IP](https://raw.githubusercontent.com/hurlycabalan/Soc-Investigation/main/KQL-Drills/src_ip.png)

**Finding:**  
IP address `88.150.11.111` generated 10 failed login attempts. This is an external IP not associated with any known corporate or trusted network range — high confidence external threat actor.

**Analysis:**
- External IP with repeated failures = likely automated attack tool or threat actor probing the environment
- Single IP responsible for multiple failures suggests targeted rather than distributed attack
- No geolocation context available in this dataset — recommend threat intel lookup

**Next Steps (SOC Response):**
- Run `88.150.11.111` through threat intel platforms (VirusTotal, AbuseIPDB)
- Block IP at firewall/perimeter level immediately
- Check if this IP appears in successful login logs
- Add IP to watchlist for continued monitoring

---

## Drill 3 — Phishing Detection via Reply-To Mismatch

**Objective:** Identify emails where the reply-to address differs from the sender address — a common phishing and business email compromise (BEC) indicator.

**MITRE ATT&CK:** `T1566.001 — Phishing: Spearphishing Attachment` | `T1566.002 — Phishing: Spearphishing Link`

```kql
Email
| where sender != reply_to
| project event_time, sender, reply_to, recipient, subject
```

**Screenshot — Query Results:**  
![Drill 3 - Phishing detection](https://raw.githubusercontent.com/hurlycabalan/Soc-Investigation/main/KQL-Drills/3800Query.png)

**Finding:**  
3,869 emails were identified where the `reply_to` address differs from the `sender` address. This volume strongly suggests an active phishing campaign or bulk BEC attempt targeting the organization.

**Analysis:**
- Reply-to mismatch is a classic phishing technique — sender appears legitimate but replies go to attacker-controlled inbox
- Volume of 3,869 emails is too high to be isolated incidents — organized campaign
- Requires urgent review of subject lines and recipients to assess blast radius

**Next Steps (SOC Response):**
- Filter results further by suspicious domains in `reply_to` field
- Pull a sample of subject lines to identify campaign themes (urgency, finance, IT helpdesk)
- Identify which recipients opened or replied to these emails
- Quarantine or recall suspicious emails via email gateway
- Alert end users about active phishing campaign

---

## Hardening & Mitigation Recommendations

| # | Finding | Recommendation | Priority |
|---|---------|---------------|----------|
| 1 | Brute force against `jadenman` | Enforce account lockout policy after 5 failed attempts | 🔴 High |
| 2 | External IP `88.150.11.111` | Block at firewall, add to threat intel watchlist | 🔴 High |
| 3 | No MFA detected on targeted accounts | Enforce MFA across all user accounts via Conditional Access | 🔴 High |
| 4 | 3,869 phishing emails not blocked | Enable DMARC, DKIM, SPF enforcement on email gateway | 🔴 High |
| 5 | Reply-to mismatch not auto-flagged | Configure email security rules to flag/quarantine reply-to mismatches | 🟠 Medium |
| 6 | No geolocation filtering | Implement Conditional Access policies blocking logins from high-risk countries | 🟠 Medium |
| 7 | No alerting on failed login thresholds | Create SIEM alert rule: >5 failed logins per account within 10 minutes | 🟠 Medium |

---

## Lessons Learned

**1. Always correlate username AND IP data together**  
Drilling into failed logins by username alone doesn't tell you where the attack is coming from. Running both Drill 1 and Drill 2 together gives a fuller picture — who is being targeted and from where.

**2. Volume is a signal**  
3,869 phishing emails is not noise — it's a campaign. When query results return unusually high numbers, treat it as an active incident, not a data quality issue.

**3. KQL pattern — Filter → Aggregate → Rank**  
Every detection query in this drill followed the same core pattern:
- `where` — narrow the dataset to the relevant events
- `summarize count() by field` — group and count by the key identifier
- `order by desc` — surface the highest-risk items first

This is the foundational SOC analyst loop that applies to almost every investigation scenario.

**4. Findings need analyst context, not just numbers**  
Raw query output is not a finding. A finding is: *what does this number mean, why does it matter, and what should happen next.* Always add analysis and next steps.

---

## Framework Reference

| Framework | Technique | ID |
|-----------|-----------|-----|
| MITRE ATT&CK | Brute Force: Password Guessing | T1110.001 |
| MITRE ATT&CK | Valid Accounts | T1078 |
| MITRE ATT&CK | Phishing: Spearphishing Attachment | T1566.001 |
| MITRE ATT&CK | Phishing: Spearphishing Link | T1566.002 |
| NIST CSF | Detect / Respond | DE.CM-1, RS.AN-1 |

---

*Documentation by Hurly Cabalan — SOC Analyst Portfolio | github.com/hurlycabalan*
