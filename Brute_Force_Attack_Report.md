# Case 002: Brute Force Attack Analysis

**Analyst:** Hurly Cabalan  
**Date:** April 2026  
**Platform:** Microsoft Entra ID / Azure Portal  
**Severity:** Medium  
**Status:** ✅ Complete  

---

## Summary

A brute force attack was detected against an Active Directory account. Ten consecutive failed login attempts were recorded within a 2-minute window from a single IP address. The account was locked, the IP was blocked, and hardening measures were applied. No successful unauthorized access was confirmed.

---

## Phase 1: Alert

### Alert Triggered

Multiple **failed login attempts** detected for **User: Naruto** within a **2-minute window**.

| Field | Detail |
|-------|--------|
| Error Code | `50126` — Invalid username or password |
| Failed Attempts | 10 in rapid succession |
| Source IP | `20.21.211.28` |
| Location | Ad Dawhah, QA |
| Application | Azure Portal |
| Authentication Type | Single-factor (no MFA enrolled) |

The alert fired based on repeated failed logins from the same user and same IP — consistent with a brute force pattern.

---

## Phase 2: Investigation

### Step 1: Validate User & Authentication Details

Pulled sign-in logs from Entra ID filtered by user `Naruto` and status `Failure`. Confirmed all 10 failed attempts originated from IP `20.21.211.28` with no IP rotation or proxy behavior observed.

### Step 2: Analyze the Log Pattern

All 10 failures returned error code `50126` — wrong password. The attempts occurred in rapid succession within 2 minutes, indicating automated or scripted password guessing rather than a legitimate user forgetting their credentials. A real forgotten password scenario would show slower, spaced-out attempts from a recognized device.

### Step 3: Check for Geo-Anomalies & Lateral Movement

No geo-location discrepancy — Ad Dawhah is the user's normal location. No other accounts showed similar failed attempts in the same window, ruling out a password spray. No successful authentication at any point during the attack window.

### Raw Sign-In Log Data

| Timestamp | User | Application | Status | Error Code | IP Address | Auth Method |
|-----------|------|-------------|--------|------------|------------|-------------|
| 2026-04-15 16:31 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:32 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:33 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:34 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:35 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:36 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:37 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:38 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:39 | Naruto | Azure Portal | Failure | 50126 | 20.21.211.28 | Single-factor |
| 2026-04-15 16:40 | Naruto | Azure Portal | **Success** | 0 | 20.21.211.28 | **Multifactor** |

> The final successful login used MFA — confirming MFA enforcement was active and that even after the correct password was guessed, the attacker could not fully compromise the account without the second factor.

### Visual Evidence — Azure AD Sign-In Logs

![Azure AD Sign-in Logs](images/Screenshot (1).png)

> Screenshot of Entra ID sign-in logs showing the 10 failed attempts with error code 50126 followed by the MFA-protected successful login.

---

## Phase 3: Mitigation

**Immediate actions taken:**

- Temporarily locked the account after the 10th failed login attempt
- Blocked source IP `20.21.211.28` at the network level to prevent continued attempts

**Monitoring:**
- Continued watching for resumed attempts from new IPs for 48 hours post-incident
- No further attempts detected from this source

---

## Phase 4: Hardening

Security measures implemented following the incident:

- Enabled **rate-limiting** on login attempts — slows future brute force attempts before lockout threshold is reached
- **Enforced MFA** for all user accounts — as demonstrated in this case, MFA blocked the attacker even after the correct password was guessed
- Increased **password complexity** requirements across all accounts
- Applied **geofencing restrictions** — logins only permitted from pre-approved regions
- Enabled **behavioral analytics** to flag anomalous login velocity and device anomalies going forward

---

## Phase 5: Decision

- **Escalation:** Not required — incident was fully contained at account and network level
- **Outcome:** Attacker successfully guessed the password but was blocked by MFA. No data accessed, no lateral movement.
- **Recommendation:** Continue monitoring the affected account for 48 hours. Review lockout threshold — 10 attempts may be too permissive for privileged accounts.

---

## Phase 6: Lessons Learned

- **Lockout threshold too high:** 10 attempts before lockout gave the attacker too many chances. For standard user accounts, 5 attempts is more appropriate. For privileged accounts, 3.
- **MFA proved its value:** The attacker reached a successful credential match but MFA enforcement stopped the breach. This is exactly the scenario MFA is designed for.
- **Automation gap:** Account lockout was triggered manually in this case. Should be fully automated via Entra ID Smart Lockout — manual response creates a window for continued attempts.

### Problems Encountered During Investigation

- The initial alert showed attempt count but not granular timestamps — had to pull raw sign-in logs separately to confirm the 2-minute window. Lesson: always go to raw logs, not just the alert summary.
- Distinguishing brute force from a user forgetting their password required looking at attempt velocity. 10 attempts in 2 minutes is machine-speed, not human behavior.
- Geofencing was not configured prior to this incident. Since Ad Dawhah is the user's legitimate location, the IP alone wasn't a strong anomaly signal — the velocity was the real indicator.

---

*Part of the [SOC Investigation Lab](./README.md) — manual threat analysis using Active Directory and Microsoft Entra ID.*
