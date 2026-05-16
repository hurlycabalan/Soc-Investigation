# SC-03 | C2 Beacon — Compromised Endpoint Communicating with Command & Control

**Scenario ID:** SC-03  
**Classification:** Command & Control / Malware Infection  
**Severity:** 🔴 Critical  
**Platform:** Microsoft Sentinel + Microsoft Defender XDR + CrowdStrike  
**Author:** Hurly Cabalan  
**Status:** Investigation Complete  

---

## S1 — Alert Summary

### Incident Trigger
Microsoft Sentinel Analytics Rule fired: **"Periodic Outbound Connection to Low-Reputation IP — Beacon Pattern Detected"**  
A corporate endpoint began making regular outbound HTTPS connections to an external IP at near-identical intervals — a classic C2 beaconing pattern. CrowdStrike independently flagged suspicious PowerShell execution on the same host 11 minutes prior. The combination indicates an active malware infection with an established C2 channel.

### Severity Rubric

| Factor | Assessment | Score |
|---|---|---|
| **Impact** | Active C2 channel = attacker has persistent access to endpoint | Critical |
| **Confidence** | Beacon pattern + CrowdStrike alert + low-reputation IP correlated | High |
| **Scope** | One endpoint confirmed; lateral movement not yet detected | Medium |
| **Business Criticality** | Endpoint has domain access — potential for credential harvesting + spread | Critical |
| **Final Severity** | 🔴 **CRITICAL** | |

### Timeline Overview
```
09:34 UTC — CrowdStrike: Suspicious PowerShell execution — encoded command
09:41 UTC — First outbound connection to 185.220.x.x:443 (low-reputation IP)
09:51 UTC — Second connection to same IP — 10-minute interval
10:01 UTC — Third connection — interval confirmed: 10 minutes ±3 seconds
10:11 UTC — Fourth connection — beacon pattern locked
10:15 UTC — Sentinel analytics rule fires — SOC L1 assigned
10:22 UTC — CrowdStrike: Credential access alert fires (LSASS memory read)
10:31 UTC — SOC L1 begins investigation
```

---

## S2 — 🔵 SC-200 Investigation (Sentinel + Defender XDR)

### Hypothesis
> A corporate endpoint is infected with malware that established a persistent C2 channel immediately after a suspicious PowerShell execution. The consistent 10-minute beacon interval suggests an automated implant, not manual attacker interaction. The LSASS access alert indicates credential harvesting — the attacker may be preparing for lateral movement. Time is critical.

### Step 1 — Confirm Beacon Pattern (CrowdStrike)
**What we're looking for:** Consistent interval between outbound connections = automated beacon. Jitter of ±5 seconds = C2 framework behavior.

```kql
CrowdStrikeDetections
| where TimeGenerated > ago(2h)
| where ComputerName contains "WKSTN-0147"
| where DetectionDescription contains "beacon" or DetectionDescription contains "C2"
           or DetectionDescription contains "periodic"
| project TimeGenerated, ComputerName, DetectionDescription,
          Severity, NetworkRemoteAddress
| sort by TimeGenerated asc
```

**Expected Result:** Multiple detections with the same remote IP at regular intervals.

**Actual Result:** ✅ 4 detections, 185.220.x.x, intervals of 10 minutes ±3 seconds. **Beacon pattern confirmed — automated implant.**

---

### Step 2 — Identify the Initial Infection Vector (CrowdStrike)
**What we're looking for:** What executed before the first beacon? PowerShell? A document? A download? Tracing back to patient zero.

```kql
CrowdStrikeAlerts
| where TimeGenerated > ago(3h)
| where ComputerName contains "WKSTN-0147"
| where Severity in ("High", "Critical")
| project TimeGenerated, ComputerName, AlertType, UserName, Severity
| sort by TimeGenerated asc
```

**Expected Result:** PowerShell encoded command alert as the earliest event — initial stager execution.

**Actual Result:** ✅ `"Suspicious PowerShell — Base64 Encoded Command"` at 09:34 UTC — 7 minutes before first beacon. **PowerShell stager = initial infection vector.**

---

### Step 3 — Profile the C2 IP (Threat Intelligence)
**What we're looking for:** Is the destination IP known-bad? TI match = higher confidence TP. No TI match = still suspicious but requires more context.

```kql
CrowdStrikeDetections
| where TimeGenerated > ago(2h)
| where NetworkRemoteAddress contains "185.220"
| summarize ConnectionCount = count(), 
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by NetworkRemoteAddress, ComputerName
| sort by ConnectionCount desc
```

**Expected Result:** Multiple connections from one host to the same IP, confirming consistent destination.

**Actual Result:** ✅ 4 connections, first seen 09:41, last seen 10:11. **Single C2 destination, consistent target — not random noise.**

> **TI Check:** 185.220.x.x matches known Cobalt Strike C2 infrastructure in ThreatIntelligenceIndicator table (added via MISP feed). **Known-bad confirmation.**

---

### Step 4 — Assess Credential Threat (CrowdStrike)
**What we're looking for:** LSASS access = attacker is attempting to dump credentials from memory. If successful, all domain accounts on this endpoint are at risk.

```kql
CrowdStrikeAlerts
| where TimeGenerated > ago(2h)
| where ComputerName contains "WKSTN-0147"
| where AlertType contains "credential" or AlertType contains "lsass"
           or AlertType contains "mimikatz"
| project TimeGenerated, ComputerName, AlertType, UserName, Severity
| sort by TimeGenerated asc
```

**Expected Result:** LSASS memory read alert — credential harvesting in progress.

**Actual Result:** ✅ `"LSASS Memory Read — Potential Credential Dumping"` at 10:22 UTC. **Credential harvesting confirmed — lateral movement risk elevated to CRITICAL.**

---

### TP/FP Decision

| Signal | Weight |
|---|---|
| 10-minute beacon interval ±3 seconds (automated implant) | ✅ Strong |
| Base64 PowerShell stager 7 minutes before first beacon | ✅ Strong |
| C2 IP matches known Cobalt Strike infrastructure (TI hit) | ✅ Strong |
| LSASS memory read 48 minutes post-infection | ✅ Strong |
| Single consistent destination — not CDN or cloud service | ✅ Strong |

**VERDICT: ✅ TRUE POSITIVE — Active C2 Beacon with Credential Harvesting in Progress**

---

### FP Branch — Could This Be Legitimate?

**FP Scenario 1:** Legitimate software (antivirus, monitoring agent) making regular outbound calls to its cloud backend.  
**Why Ruled Out:** Legitimate vendors use known, high-reputation domains (not raw IPs). The destination is a raw IP on port 443, not a named domain. No software inventory matches 185.220.x.x.

**FP Scenario 2:** Browser or app with telemetry making periodic pings.  
**Why Ruled Out:** Telemetry pings do not correlate with a Base64 PowerShell execution 7 minutes prior. Co-occurrence is too specific to be coincidental.

**FP Scenario 3:** Authorized red team activity.  
**Why Ruled Out:** No active red team engagement in the change calendar. Cobalt Strike TI match on the C2 IP is not consistent with internal red team infrastructure.

**FP Confidence: NONE — Confirmed TP, active incident.**

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Base64 encoded PowerShell stager at 09:34 |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 encoding of PowerShell payload |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS beacon to C2 IP on port 443 |
| Command & Control | Non-Standard Port / Encrypted Channel | T1573 | C2 communication disguised as HTTPS traffic |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | LSASS memory read alert at 10:22 |
| Persistence | Scheduled Task / Startup Folder | T1053 | Beacon survives reboot — persistence mechanism inferred |

---

## S4 — Mitigation (Immediate Response)

### Containment
- [ ] **Network isolate the endpoint immediately** — Defender for Endpoint: Device Actions → Isolate Device. Cuts C2 channel without losing forensic state.
- [ ] Block 185.220.x.x at firewall/proxy level — prevent re-establishment from other hosts
- [ ] Revoke all credentials of the logged-in user on WKSTN-0147 (assume LSASS dump succeeded)
- [ ] Force password reset for the user account and any accounts that were active on the endpoint
- [ ] Check for lateral movement: did any other hosts connect to 185.220.x.x?

### Evidence Preservation
- [ ] Initiate Defender for Endpoint Live Response — collect memory dump before isolation
- [ ] Export CrowdStrike process tree for the PowerShell execution event
- [ ] Export full beacon timeline (timestamps, intervals, payload sizes)
- [ ] Capture network traffic logs for the C2 connection window

### Escalation
- [ ] Escalate to SOC L2/L3 immediately — active C2 + credential dump = P1 incident
- [ ] Notify IR team — endpoint needs forensic analysis
- [ ] Check if 185.220.x.x appears in any other endpoint's connection logs — assess campaign scope

---

## Control Failure Analysis

| Control | Expected Behavior | What Failed |
|---|---|---|
| **Email / Web Filtering** | Block malicious document or URL that delivered the stager | Initial vector (email attachment or malicious URL) was not blocked pre-execution |
| **PowerShell Constrained Language Mode** | Prevent execution of encoded/obfuscated PowerShell | Constrained Language Mode not enforced on this endpoint |
| **Application Allow-listing** | Block unauthorized executables and scripts | Allow-listing policy had gaps — unsigned PowerShell with encoded payload was not blocked |
| **Outbound Firewall Rules** | Block direct outbound connections to raw IPs on 443 | Egress filtering allowed direct outbound to unknown IPs — C2 channel established freely |
| **EDR Response Automation** | Auto-isolate on C2 detection | CrowdStrike alert fired but did not trigger automated isolation — manual response required |

---

## S5 — 🟠 AZ-500 Hardening Recommendations (D1–D4)

> ⚠️ **THEORETICAL — Hands-on lab verification scheduled Month 2–3**

### D1 — Identity & Access
- **Privileged Access Workstations (PAW)** — Admin accounts should only authenticate from hardened, isolated workstations. If the compromised endpoint had admin rights, blast radius is significantly larger.
- **PIM for Admin Roles** — Just-in-time elevation. If credentials were dumped, PIM-protected roles require fresh MFA approval — stolen hashes don't grant standing admin access.
- **Conditional Access — Compliant Device** — Require device compliance before granting access to corporate resources. Isolated/compromised endpoint would fail compliance check and be blocked.

### D2 — Secure Networking
- **Azure Firewall — Outbound Rules** — Whitelist-only egress policy. Block all outbound connections to raw IPs not in the approved list. C2 beaconing to 185.220.x.x would be stopped at the perimeter.
- **DNS Filtering** — Use Azure DNS Private Resolver or third-party DNS filtering to block resolution of known C2 domains. If the stager uses DGA (domain generation algorithm), DNS filtering catches it.
- **NSG Outbound Rules** — Deny outbound to internet except specific approved ports/destinations. Most endpoints don't need arbitrary outbound HTTPS to unknown IPs.

### D3 — Compute + Storage
- **Defender for Endpoint — Attack Surface Reduction Rules** — Enable: Block execution of potentially obfuscated scripts, Block credential stealing from LSASS, Block process creations from PSExec and WMI commands.
- **PowerShell Constrained Language Mode** — Enforce via AppLocker or WDAC. Prevents encoded/obfuscated PowerShell stagers from executing.
- **JIT VM Access** — For VMs accessed via RDP/SSH post-lateral movement — JIT prevents unauthorized access even with valid credentials.

### D4 — Security Operations
- **Sentinel TI Integration** — Connect MISP or Microsoft Threat Intelligence to Sentinel. Auto-alert when any endpoint connects to a known-bad IP. The TI hit on 185.220.x.x should have fired immediately on first connection.
- **Automation Playbook — C2 Detection** — Auto-isolate endpoint when beacon pattern + TI match is confirmed. Remove the 16-minute gap between detection and isolation.
- **Beacon Detection KQL** — Proactive hunting: identify periodic connections with consistent intervals across all endpoints, not just confirmed C2 IPs.

---

## S6 — Lessons Learned & Interview Q&A

### What Went Wrong
1. **PowerShell stager was not blocked** — Encoded PowerShell is a red flag. Constrained Language Mode and ASR rules would have stopped this before the beacon was ever established.
2. **Egress filtering was not restrictive enough** — The endpoint was able to make direct outbound connections to a raw IP on port 443. A deny-by-default outbound policy would have killed the C2 channel immediately.
3. **No automated isolation on C2 detection** — 16 minutes elapsed between the first beacon detection and the SOC beginning isolation. With LSASS access happening at minute 48, every minute of delay increases lateral movement risk.

### What Went Right
1. CrowdStrike detected both the PowerShell stager and the LSASS access — EDR telemetry was comprehensive
2. TI feed matched the C2 IP — confidence in TP was immediate
3. Sentinel correlated beacon pattern + CrowdStrike alerts into a single incident — no manual correlation required

### Closure Criteria
- [ ] Endpoint isolated via Defender for Endpoint
- [ ] C2 IP (185.220.x.x) blocked at firewall and proxy layer
- [ ] Compromised user credentials fully revoked and reset
- [ ] Lateral movement check completed: no other endpoints connecting to C2 IP
- [ ] Endpoint reimaged — do not trust cleaned infection
- [ ] ASR rules and PowerShell CLM enabled on all endpoints
- [ ] Egress firewall rules tightened — deny outbound to raw IPs
- [ ] Automation playbook deployed: auto-isolate on beacon + TI match
- [ ] Post-mortem completed within 48 hours

---

### Interview Q&A

**Q: How do you distinguish a C2 beacon from normal application traffic?**  
> A: Two things: interval consistency and destination reputation. Legitimate apps make connections driven by user activity — irregular, varying intervals. A C2 beacon is timer-driven — the malware wakes up every N minutes and phones home regardless of user activity. The interval is the fingerprint. In this case, 10 minutes ±3 seconds across 4 consecutive connections — that's a clock, not a user. Combine that with a raw IP destination matching known Cobalt Strike infrastructure and you have a TP with high confidence.

**Q: LSASS was accessed 48 minutes into the incident. What does that mean for your response priority?**  
> A: It means credential containment becomes as urgent as endpoint isolation. LSASS access means the attacker likely has hashed or cleartext credentials for every account that authenticated on that machine. If you only isolate the endpoint but don't revoke credentials, the attacker can pivot to other systems using those credentials immediately. The two actions — isolate endpoint and revoke credentials — have to happen in parallel, not sequentially.

**Q: Why do you reimage instead of just cleaning the infection?**  
> A: Because you can never fully trust an endpoint that had an active C2 channel. The implant may have dropped secondary persistence mechanisms — scheduled tasks, registry run keys, WMI subscriptions — that survive standard malware removal. Reimaging guarantees a clean baseline. The only exception is if forensics needs the disk state preserved — in that case you image first, then reimage the operational machine.

---

*Portfolio: [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)*  
*Scenario Chain: SC-01 → SC-02 → SC-03 → SC-04 → SC-05*
