# SOC Investigation Lab
> Manual threat analysis using Active Directory — no automated SIEM tools.

📍 Analyst: Hurly Cabalan | Doha, Qatar
🎯 Focus: Identity-based threat investigation | Brute Force | Phishing

---

## 📁 Cases

| Case | Title | Status |
|------|-------|--------|
| 001 | User Creation & MFA Trigger | ✅ Complete |
| 002 | Brute Force Attack Analysis | ✅ Complete |
| 003 | Phishing Investigation | 🔄 In Progress |

---

## Case 001: User Creation & MFA Trigger

### Scenario
A new user account was created in the identity system.

### Investigation
- Checked user creation event
- Observed MFA requirement triggered on first login

### Analysis
This indicates security baseline enforcement for new identities.

### Decision
No escalation required — expected behavior.

### Notes
MFA acts as a secondary authentication control to prevent unauthorized access.

---

## Case 002: Brute Force Attack Analysis

📄 Full report: [Brute_Force_Attack_Report.md](./Brute_Force_Attack_Report.md)

### Scenario
Multiple failed login attempts detected against an Active Directory account.

### Investigation
- Reviewed authentication failure logs
- Identified attack patterns, timing, and source behavior
- Documented indicators of compromise (IOCs)

### Analysis
Repeated failed authentications consistent with a brute force attempt.

### Decision
Escalation recommended — account lockout policy review required.

---

## Case 003: Phishing Investigation 🔄 In Progress

### Scope
Manual phishing email analysis covering:
- DMARC & SPF record validation
- Email header tracing
- URL inspection & typosquatting detection
- Attachment analysis

---

*Portfolio in progress — actively building toward AZ-500 & SC-200 specialization.*# SOC Investigation Lab

## Case 001: User Creation & MFA Trigger

### Scenario
A new user account was created in the identity system.

### Investigation
- Checked user creation event
- Observed MFA requirement triggered on first login

### Analysis
This indicates security baseline enforcement for new identities.

### Decision
No escalation required (expected behavior)

### Notes
MFA acts as a secondary authentication control to prevent unauthorized access.`
