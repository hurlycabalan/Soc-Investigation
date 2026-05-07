# TL-01 — Identity-Driven Investigation
**Date:** 2026-05-07
**Platform:** Microsoft Sentinel | OktaV2_CL
**Analyst:** Hurly Cabalan

---

## S1 — Alert Summary
- **Source:** OktaV2_CL (Sentinel Training Lab)
- **Actor:** mirage@pkwork.onmicrosoft.com
- **Source IP:** 198.51.100.42
- **Geolocation:** Moscow, Russia
- **Timestamp:** 2026-05-06, 11:35:47 AM UTC
- **Severity:** High
- **Verdict:** True Positive

---

## S2 — Investigation (SC-200 Layer)

### KQL Queries Used
**Q1 — Event overview:**
```kql
OktaV2_CL
| where TimeGenerated > ago(24h)
| summarize EventCount = count() by EventOriginalType
```

**Q2 — MFA deactivation actor:**
```kql
OktaV2_CL
| where TimeGenerated > ago(24h)
| where EventOriginalType == "user.mfa.factor.deactivate"
| project TimeGenerated, ActorUsername, SrcIpAddr, SrcGeoCity
```

**Q3 — Full actor activity:**
```kql
OktaV2_CL
| where TimeGenerated > ago(7d)
| where ActorUsername contains "mirage"
| project TimeGenerated, EventOriginalType, SrcIpAddr, SrcGeoCity
```

### Attack Timeline
| Time | Event | Significance |
|---|---|---|
| 11:35:47 | user.session.start | Attacker logged in |
| 11:35:47 | user.account.privilege.grant | Privilege escalation |
| 11:35:47 | system.api_token.create | Persistence established |
| 11:35:47 | user.mfa.factor.deactivate | MFA removed |
| 11:35:47 | user.mfa.factor.reset_all | All MFA wiped |
| 11:35:47 | user.mfa.factor.update | Attacker-controlled MFA set |

### TP/FP Decision
**Verdict: TRUE POSITIVE**
- Moscow geolocation anomalous
- MFA deactivation + reset in same session
- Privilege escalation + API token = persistence
- All events same timestamp = automated/scripted attack

### Escalation
Escalated to L2 with full timeline. Account disabled, API token revoked, IP blocked.

---

## S3 — MITRE Mapping

| Event | Tactic | Technique |
|---|---|---|
| user.session.start | Initial Access | T1078 Valid Accounts |
| user.account.privilege.grant | Privilege Escalation | T1078.004 Cloud Accounts |
| system.api_token.create | Persistence | T1528 Steal App Access Token |
| user.mfa.factor.deactivate | Defense Evasion | T1556.006 MFA Modification |
| user.mfa.factor.reset_all | Defense Evasion | T1556.006 MFA Modification |

---

## S4 — Mitigation (Immediate Response)
- Disable mirage@pkwork.onmicrosoft.com account
- Revoke API token created during session
- Block IP 198.51.100.42
- Force MFA re-enrollment for affected account
- Review scope of privilege grant

---

## S5 — Hardening (AZ-500 Layer)

| Domain | Control | Purpose |
|---|---|---|
| D1 Identity | Conditional Access | Block sign-ins from anomalous locations |
| D1 Identity | PIM | Restrict who can grant privileges |
| D1 Identity | Identity Protection | Alert on risky sign-ins |
| D4 Operations | Sentinel Analytics Rule | Alert on MFA deactivation events |

---

## S6 — Lessons Learned
- **Control that failed:** MFA policy — no geolocation restriction
- **Bypass method:** Attacker deactivated MFA after initial access
- **Earlier detection:** Alert on first MFA config change, not after reset_all
- **Post-incident:** Implement Conditional Access with named locations

### Interview Q&A
**Q: How did you detect this attack?**
> Proactive threat hunting in OktaV2_CL — queried for MFA deactivation events, identified anomalous Moscow IP, expanded to full actor timeline revealing 4-tactic attack chain.

**Q: Why was this a TP?**
> Multi-signal confirmation — geolocation anomaly + privilege escalation + persistence + MFA bypass in one session. Behavioral pattern consistent with account takeover.

---

## TI Lookup
- IP: 198.51.100.42
- VirusTotal: 0/97 clean (RFC 5737 reserved range — lab simulation)
- ThreatIntelIndicators: Not available on free tier
- **Decision: TP maintained based on behavioral evidence**
