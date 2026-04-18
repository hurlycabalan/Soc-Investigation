# Case 002: Brute Force Attack Analysis

**Analyst:** Hurly Cabalan  
**Date:** 2025  
**Platform:** Azure Portal / Active Directory  
**Severity:** Medium  

---

## Phase 1: Alert

### Alert Triggered

Multiple **failed login attempts** detected for **User 1 (Naruto)** within a **2-minute window**.

| Field | Detail |
|-------|--------|
| Error Code | `S0126` – Invalid username or password |
| Failed Attempts | 10 in rapid succession |
| Source IP | `20.21.211.28` |
| Location | Ad Dawhah, QA |
| Application | Azure Portal |

The alert was triggered due to repeated failed logins from the same user and same IP, consistent with a **brute force attack** pattern.

---

## Phase 2: Investigation

### Step 1: Validate User & Authentication Details

- **User Affected:** Naruto (testuser)
- **IP Address:** `20.21.211.28`
- **Location:** Ad Dawhah, QA
- **Application:** Azure Portal

### Step 2: Analyze Failed Login Attempts

- All 10 failures occurred within 2 minutes — rapid succession with incorrect passwords each time
- Error code `S0126` consistently confirmed invalid credentials, ruling out account lockout or MFA failure as the cause
- Same IP address across all attempts — no proxy rotation or distributed attack behavior observed

### Step 3: Check for Similar Events / Geo-Anomalies

- No logins from additional IPs or unusual geographic locations
- No signs of lateral movement or successful authentication at any point
- Isolated incident — single attacker pattern

---

## Phase 3: Mitigation

**Immediate actions taken:**

- Temporarily locked the account after 10 failed login attempts
- Blocked source IP `20.21.211.28` at the network level

**Next steps:**
- Continue monitoring account for resumed attempts from new IPs
- Review lockout threshold — 10 attempts may be too high for sensitive accounts

---

## Phase 4: Hardening

**Security measures implemented following the incident:**

- Enabled **rate-limiting** on login attempts to slow future brute force attempts
- **Enforced MFA** for all user accounts — unauthorized access is blocked even if credentials are compromised
- Increased **password complexity** requirements across all accounts
- Applied **geofencing restrictions** — logins only permitted from pre-approved regions
- Enabled **behavioral analytics** to detect anomalous login patterns and device anomalies going forward

---

## Phase 5: Decision

- **Escalation:** Not required — incident was contained at the account and network level
- **Recommendation:** Continue monitoring the affected account for abnormal activity over the next 48 hours

---

## Phase 6: Lessons Learned

- **Alert threshold review:** 10 failed attempts before alerting may be too permissive for privileged accounts — consider lowering to 5
- **Automation gap:** Account lockout should be automated, not manual — delayed manual response creates a window for continued attempts
- **MFA as a safety net:** Even if the attacker had guessed the password correctly, MFA enforcement would have blocked access — reinforces the value of MFA as a non-negotiable baseline

### Problems Encountered During Investigation

- The initial alert lacked timestamp granularity — I could see the count (10 attempts) but needed to dig into the raw sign-in logs to confirm the 2-minute window. Lesson: always pull the raw log, not just the alert summary.
- Geofencing was not enabled prior to this incident. Ad Dawhah is a legitimate location for this user, so the IP alone wasn't a strong anomaly signal — the volume and speed of attempts was the real indicator.
- Distinguishing between a brute force attempt and a user simply forgetting their password required looking at the attempt speed. A legitimate forgotten password case would show slower, spaced-out attempts — not 10 in 2 minutes.

---

*Part of the [SOC Investigation Lab](./README.md) — manual threat analysis using Active Directory.*
