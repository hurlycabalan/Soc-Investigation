## Phase 1: Alert

### Alert Triggered:
Multiple **failed login attempts** detected for **User 1** (Naruto) within a **2-minute window**.

- **Error Code**: `S0126` - Invalid username or password.
- **Number of Attempts**: 10 failed logins in rapid succession.
- **Source**: IP Address: `20.21.211.28`
- **Location**: Ad Dawhah, QA
- **Application**: Azure Portal

The alert was triggered due to multiple failed logins from the same user, indicating potential **brute force attack** behavior.


## Phase 2: Investigation

### Step 1: Validate the User and Authentication Details
- **User Affected**: Naruto
- **IP Address**: 20.21.211.28
- **Location**: Ad Dawhah, QA
- **Application**: Azure Portal

### Step 2: Analyze Failed Login Attempts
- The failed login attempts occurred in **quick succession**, with multiple incorrect passwords entered.
- The **error code** (`S0126`) confirmed **invalid credentials**.
- Repeated logins within a short time window from the **same IP** and **same user** indicated **brute force** attempts.

### Step 3: Check for Similar Events
- There were no similar logins or **geo-location discrepancies**, confirming that this was likely an isolated brute force attempt.
- 

## Phase 3: Mitigation

- **Action Taken**: Temporarily locked the account after 10 failed login attempts.
- **Next Steps**: Monitor for additional failed login attempts or patterns that suggest a continuation of the attack.

- ## Phase 4: Hardening

- **Security Measures Implemented**:
  - Enabled **rate-limiting** for login attempts to prevent further brute force attacks.
  - **Enforced MFA** (Multi-Factor Authentication) for all users.
  - **Increased password complexity** requirements for user accounts.
 
  - ## Phase 5: Decision

- **Escalation**: No immediate escalation required as the issue was contained with account lock.
- **Recommendation**: Continue monitoring the affected account for abnormal activity.

- ## Phase 6: Lessons Learned

- **Improvement**: Alert thresholds should be adjusted for more sensitive detection of brute force attempts.
- **Actionable Insight**: Automate the account lockout after a specified number of failed login attempts.
- **Recommendation**: Ensure all accounts use **MFA** to mitigate unauthorized access.
