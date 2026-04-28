# Case 004 — KQL Detection Queries
**Case:** Account Takeover — Password Spray + MFA Fatigue  
**Analyst:** Hurly Cabalan  
**Environment:** Microsoft Sentinel / Log Analytics  
**Log Sources:** SigninLogs · AuditLogs · OfficeActivity

---

## Query 01 — Password Spray: Failed Logins by IP

**Purpose:** Identify all accounts targeted by the attacker IP. Confirms spray pattern — low attempts per account across many accounts.

**Screenshot trigger:** Run this first. Results show all 47 targeted accounts.

```kql
SigninLogs
| where TimeGenerated between (datetime(2025-03-15T01:00:00Z) .. datetime(2025-03-15T03:00:00Z))
| where IPAddress == "185.220.101.47"
| summarize 
    TotalAttempts = count(),
    FailureCount = countif(ResultType != "0"),
    SuccessCount = countif(ResultType == "0"),
    PasswordsAttempted = dcount(tostring(parse_json(AuthenticationDetails)[0].authenticationMethod))
    by UserPrincipalName
| sort by TotalAttempts desc
```

**Expected output columns:** UserPrincipalName · TotalAttempts · FailureCount · SuccessCount  
**Key finding:** sarah.almansouri shows SuccessCount = 1. All others = 0.

---

## Query 02 — MFA Fatigue: Repeated Push Requests

**Purpose:** Timeline all MFA requests against sarah's account during the attack window. Shows the 14 push requests and the eventual approval.

**Screenshot trigger:** Run after Query 01. Shows the full push bombing timeline.

```kql
SigninLogs
| where TimeGenerated between (datetime(2025-03-15T02:00:00Z) .. datetime(2025-03-15T03:00:00Z))
| where UserPrincipalName == "sarah.almansouri@contoso.com"
| where AuthenticationRequirement == "multiFactorAuthentication"
| extend MFADetail = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType,
    ResultDescription,
    MFADetail,
    Location
| sort by TimeGenerated asc
```

**Expected output:** 14 rows. First 13: MFA denied or timed out. Row 14: MFA succeeded at 02:47:11Z.

---

## Query 03 — Post-Authentication Session from Attacker IP

**Purpose:** Confirm the attacker's successful session. Identify the user agent (reveals automated tooling).

**Screenshot trigger:** Run to confirm attacker session details — pay attention to UserAgent field.

```kql
SigninLogs
| where TimeGenerated between (datetime(2025-03-15T02:45:00Z) .. datetime(2025-03-15T04:00:00Z))
| where UserPrincipalName == "sarah.almansouri@contoso.com"
| where ResultType == "0"
| extend 
    UserAgent = tostring(DeviceDetail.browser),
    OS = tostring(DeviceDetail.operatingSystem),
    DeviceName = tostring(DeviceDetail.displayName)
| project 
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    UserAgent,
    OS,
    DeviceName,
    AuthenticationRequirement
| sort by TimeGenerated asc
```

**Key finding:** UserAgent returns "python-requests/2.28.0" — confirms automated attacker tooling, not a legitimate browser session.

---

## Query 04 — MFA Device Registration After Compromise

**Purpose:** Detect attacker registering a new MFA device within minutes of gaining access — establishes persistence.

**Screenshot trigger:** Run this to show the persistence move. Note the timestamp is 4 minutes after initial access.

```kql
AuditLogs
| where TimeGenerated between (datetime(2025-03-15T02:45:00Z) .. datetime(2025-03-15T04:00:00Z))
| where OperationName in (
    "Update user",
    "User registered security info",
    "User registered all required security info"
  )
| extend 
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    ModifiedProperty = tostring(TargetResources[0].modifiedProperties[0].displayName),
    InitiatedByIP = tostring(parse_json(InitiatedBy).user.ipAddress)
| where TargetUser == "sarah.almansouri@contoso.com"
| project 
    TimeGenerated,
    OperationName,
    TargetUser,
    ModifiedProperty,
    InitiatedByIP,
    Result
| sort by TimeGenerated asc
```

**Key finding:** New authenticator registered at 02:51:33Z from IP 185.220.101.47 — 4 minutes after compromise. Persistence confirmed.

---

## Query 05 — Suspicious Inbox Rule Creation

**Purpose:** Detect hidden inbox rule created to suppress security alert emails — attacker covering their tracks.

**Screenshot trigger:** Run this to reveal the inbox rule. The rule name "." is a red flag on its own.

```kql
OfficeActivity
| where TimeGenerated between (datetime(2025-03-15T02:45:00Z) .. datetime(2025-03-15T04:00:00Z))
| where Operation == "New-InboxRule"
| where UserId == "sarah.almansouri@contoso.com"
| extend 
    RuleName = tostring(parse_json(Parameters)[0].Value),
    Conditions = tostring(parse_json(Parameters)[1].Value),
    Actions = tostring(parse_json(Parameters)[2].Value)
| project 
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    RuleName,
    Conditions,
    Actions
```

**Alternative query using AuditLogs if OfficeActivity not available:**

```kql
AuditLogs
| where TimeGenerated between (datetime(2025-03-15T02:45:00Z) .. datetime(2025-03-15T04:00:00Z))
| where OperationName == "New-InboxRule"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| where TargetUser == "sarah.almansouri@contoso.com"
| project TimeGenerated, OperationName, TargetUser, AdditionalDetails
```

**Key finding:** Rule name "." created at 02:53:17Z. Conditions filter "Microsoft account", "Security alert", "Unusual sign-in" subject keywords → move to Deleted Items + mark read.

---

## Query 06 — SharePoint / OneDrive File Access Post-Compromise

**Purpose:** Identify all files accessed or downloaded during the attacker's session — establishes exfiltration scope.

**Screenshot trigger:** Run this last. The FileDownloaded row for Payroll-March-2025.xlsx is the critical finding.

```kql
OfficeActivity
| where TimeGenerated between (datetime(2025-03-15T02:47:00Z) .. datetime(2025-03-15T04:30:00Z))
| where UserId == "sarah.almansouri@contoso.com"
| where Operation in ("FileAccessed", "FileDownloaded", "FileSyncDownloadedFull")
| where ClientIP == "185.220.101.47"
| extend FileName = tostring(split(OfficeObjectId, "/")[-1])
| project 
    TimeGenerated,
    Operation,
    FileName,
    OfficeObjectId,
    ClientIP,
    UserAgent
| sort by TimeGenerated asc
```

**Key findings:**
- 3 files in `/Finance/` accessed between 02:55Z – 03:30Z
- `Payroll-March-2025.xlsx` — FileDownloaded at 03:18:44Z
- All operations from IP 185.220.101.47

---

## Query 07 — Full Attack Summary (Single View)

**Purpose:** One query to generate a complete attack timeline for the incident report and management briefing.

```kql
let AttackerIP = "185.220.101.47";
let TargetUser = "sarah.almansouri@contoso.com";
let StartTime = datetime(2025-03-15T01:00:00Z);
let EndTime = datetime(2025-03-15T05:00:00Z);
// --- Spray attempts ---
let SprayAttempts = SigninLogs
| where TimeGenerated between (StartTime .. EndTime)
| where IPAddress == AttackerIP and ResultType != "0"
| summarize SprayCount = count() by IPAddress
| extend Phase = "1 - Password Spray", Detail = strcat(tostring(SprayCount), " failed attempts across 47 accounts");
// --- MFA push bombing ---
let MFAPush = SigninLogs
| where TimeGenerated between (StartTime .. EndTime)
| where UserPrincipalName == TargetUser and IPAddress == AttackerIP
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize PushCount = count() by UserPrincipalName
| extend Phase = "2 - MFA Fatigue", Detail = strcat(tostring(PushCount), " MFA push requests sent");
// --- Successful login ---
let SuccessLogin = SigninLogs
| where TimeGenerated between (StartTime .. EndTime)
| where UserPrincipalName == TargetUser and ResultType == "0" and IPAddress == AttackerIP
| extend Phase = "3 - Initial Access", Detail = strcat("Authenticated at ", tostring(TimeGenerated))
| project Phase, Detail;
// --- File downloads ---
let FileAccess = OfficeActivity
| where TimeGenerated between (StartTime .. EndTime)
| where UserId == TargetUser and ClientIP == AttackerIP
| where Operation == "FileDownloaded"
| extend Phase = "4 - Exfiltration", Detail = strcat("Downloaded: ", tostring(split(OfficeObjectId, "/")[-1]))
| project Phase, Detail;
// Union all phases
SprayAttempts | project Phase, Detail
| union (MFAPush | project Phase, Detail)
| union SuccessLogin
| union FileAccess
| sort by Phase asc
```

---

## Notes for Lab Validation (From May 1)

When lab access is available, validate each query by:

1. **Query 01** — Adjust the IP to your lab's simulated attacker. Confirm table returns multiple UPNs.
2. **Query 02** — Verify `AuthenticationDetails` JSON path is correct for your Sentinel workspace version.
3. **Query 03** — `DeviceDetail.browser` field may need to be `tostring(DeviceDetail.["browser"])` depending on schema.
4. **Query 05** — OfficeActivity ingestion can have 30–60 min lag. Check time range if no results.
5. **Query 06** — `OfficeObjectId` path depth varies. Adjust `split(..., "/")[-1]` index if filename not returning correctly.

---

*All queries written for Microsoft Sentinel / Log Analytics using KQL. Log sources: SigninLogs (Entra ID), AuditLogs (Entra ID), OfficeActivity (Microsoft 365). MITRE ATT&CK v14.*
