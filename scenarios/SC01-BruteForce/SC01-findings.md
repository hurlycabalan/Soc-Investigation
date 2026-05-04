## Scenario 01 — Brute Force Attack
**Status:** ✅ COMPLETED | **Date Executed:** 2026-05-03 | **Severity:** HIGH

---

### Alert
9 failed logins from single IP (20.21.211.28) targeting 
testuser01@hurlysoclab.onmicrosoft.com via One Outlook Web 
over a 31-minute window (06:54 – 07:25 UTC).

---

### Hypothesis
Brute force attack — low-and-slow credential stuffing attempt 
targeting webmail access.

---

### Investigation

| Step | Query | Result |
|------|-------|--------|
| 1 | Failed logins check | 9 failures, 1 account, 1 IP |
| 2 | Detection threshold >=10 | ❌ Empty — attack missed |
| 3 | Detection threshold >=5 | ✅ testuser01 detected |
| 4 | Success after failures (TP check) | 4 successful logins confirmed |
| 5 | AuditLogs post-compromise | Empty — no directory changes |
| 6 | IP enrichment | Single IP, Ad Dawhah QA, multi-account |

**Screenshots:** `scenarios/SC01-BruteForce/screenshots/`

---

### Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 06:54 | First failure — expired password (50055) |
| 06:56 | ✅ BREACH — successful login |
| 06:57 | ✅ Continued access |
| 07:01 | ✅ Continued access |
| 07:08–07:10 | 4 more failures (50126) |
| 07:25 | Last failure — attack ends |

---

### TP/FP Decision
**TRUE POSITIVE — Escalate immediately**

Evidence confidence: STRONG
- Multi-signal: failures + success + same IP + same user ✅
- Breach occurred within 2 minutes of first attempt ✅
- Post-breach: email access risk (Outlook Web), no privilege escalation ✅

---

### Detection Gap
Default threshold (>=10) missed this attack entirely.  
9 failures was sufficient to compromise the account.  
**Fix:** Lower threshold to >=5 with time-window filter to reduce FP noise.

---

### FP Stress Case
Same IP hit both testuser01 and admin account (hurly.soclab).  
Pattern mimics lateral movement but was analyst test session.  
**Lesson:** Always cross-reference IP against known-good analyst IPs 
before escalating. Detection alone cannot distinguish admin testing 
from real lateral movement — process context required.

---

### Mitigation
- Disable testuser01 immediately
- Block IP 20.21.211.28 at Conditional Access
- Force password reset on testuser01
- Enable MFA — this attack succeeds only because MFA was absent
- Lower Sentinel alert threshold to >=5
- Add time-window filter: 5+ failures within 10 minutes

---

### Automation vs Human Boundary
| Action | Owner |
|--------|-------|
| Disable account | Automate (Logic App) |
| Block IP | Automate (Sentinel playbook) |
| Notify SOC | Automate |
| TP/FP decision | Human |
| Escalation severity | Human |
| Legal/HR notification | Human |

---

### Compliance
- **QCSF:** Access control failure — identity protection control gap
- **NIST:** PR.AC-1 (identities managed), DE.CM-1 (network monitored)
- **ISO 27001:** A.9.4.2 (secure log-on procedures)

---

### Lessons Learned
1. **Low failure count ≠ low risk.** 9 failures breached the account. 
   Threshold tuning is a detection engineering decision.
2. **Always check for success after failures.** That's the real question — 
   not how many times they tried, but did they get in.
3. **Lab contamination is real.** Analyst IP hitting multiple accounts 
   creates false lateral movement signals. Document your known-good IPs.
