# SOC Investigation Lab

> Manual threat analysis using Active Directory — no automated SIEM tools.

📍 Analyst: Hurly Cabalan | Doha, Qatar  
🎯 Focus: Identity-based threat investigation | Brute Force | Phishing

---

## 📁 Cases

| Case | Title | Status |
|------|-------|--------|
| 001 | User Creation & MFA Enforcement | ✅ Complete |
| 002 | Brute Force Attack Analysis | ✅ Complete |
| 003 | Phishing Investigation | 🔄 In Progress |

---

## Case 001: User Creation & MFA Enforcement

### Scenario

A new user account (`testuser_01`) was provisioned in Active Directory as part of a simulated onboarding workflow. The objective was to verify that the security baseline — specifically MFA enforcement — triggers correctly for new identities before they gain access to any resources.

### Investigation Steps

1. Created user account in Active Directory and assigned to standard user group
2. Logged in as the new user for the first time via Azure Portal
3. Observed the MFA enrollment prompt triggered immediately on first login
4. Verified that access to resources was blocked until MFA setup was completed
5. Confirmed Conditional Access policy was the enforcement mechanism — not a manual admin step

### Analysis

MFA enforcement fired as expected. The Conditional Access policy correctly identified a new account with no registered MFA method and blocked resource access until enrollment was completed. This is the intended security baseline behavior for new identities.

### Problems Encountered

- Initially, the MFA prompt did **not** appear on first login. Traced back to the Conditional Access policy being scoped to a specific group — and the new user hadn't been added to that group yet. Added the user to the correct group and confirmed the policy applied.
- Needed to distinguish between MFA enforcement via Conditional Access vs. per-user MFA settings in Entra ID. These behave differently and can conflict if both are configured.

### Decision

No escalation required — behavior confirmed as expected after group assignment correction.

### Key Takeaway

Conditional Access policy scope matters. A new user outside the target group will bypass enforcement entirely, which is a real gap in onboarding workflows if not caught early.

---

## Case 002: Brute Force Attack Analysis

📄 Full report: [Brute_Force_Attack_Report.md](./Brute_Force_Attack_Report.md)

### Scenario

Multiple failed login attempts detected against an Active Directory account (`User 1 / Naruto`) — 10 failed logins within a 2-minute window from IP `20.21.211.28`, location: Ad Dawhah, QA, via Azure Portal.

### Investigation Summary

- Reviewed authentication failure logs — error code `S0126` (invalid credentials) repeated across all attempts
- Identified consistent source IP, no geo-location anomaly (same city), no lateral movement
- Confirmed brute force pattern: rapid succession, same user, same IP

### Mitigation & Hardening

- Temporarily locked the account after threshold breach
- Blocked source IP `20.21.211.28`
- Enabled rate-limiting on login attempts
- Enforced MFA across all accounts
- Applied geofencing to restrict logins to pre-approved regions
- Enabled behavioral analytics for anomaly detection

### Decision

No escalation required — contained at account and network level. Continued monitoring recommended.

---

## Case 003: Phishing Investigation 🔄 In Progress

### Scope

Manual phishing email analysis covering:

- DMARC & SPF record validation
- Email header tracing
- URL inspection & typosquatting detection
- Attachment macro analysis

📄 Partial documentation: [Phishing_Lab_Documentation.md](./Phishing_Lab_Documentation.md)

---

*Portfolio in active development — building toward AZ-500, SC-200, and cloud security specialization.*
