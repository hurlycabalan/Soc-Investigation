# TL-02 Run Sheet — Endpoint-Driven Lateral Movement
**Pivot: CrowdStrike → PaloAlto (Forward) | NO Identity Pivot**  
**Tables: CrowdStrikeDetections, CrowdStrikeAlerts, CommonSecurityLog (PaloAlto)**

---

## ⚠️ PRE-FLIGHT — Run These FIRST (5 minutes)

### Verify PaloAlto Table
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| take 5
```
**If results → PaloAlto confirmed. Proceed.**  
**If 0 results → run this fallback:**
```kql
search *
| where Type contains "Palo" or Type contains "Firewall"
| summarize count() by Type
| take 10
```
Note the actual table name — replace `CommonSecurityLog` in all queries below.

### Grab Your Endpoint Name
```kql
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| summarize count() by DeviceName
| sort by count_ desc
| take 5
```
**Pick the top DeviceName. Use it as your `endpoint` variable below.**

---

## 6 Queries — Run in Order, Screenshot Each

---

### Screenshot 01 — CrowdStrike: Credential/Lateral Movement Alert
**Save as:** `01-crowdstrike-detection.png`

```kql
let endpoint = "REPLACE-WITH-YOUR-DEVICE-NAME";
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| where DeviceName == endpoint
| where Tactic contains "Credential" 
    or Tactic contains "Lateral"
    or Technique contains "Dumping"
    or Technique contains "Pass"
| project TimeGenerated, DeviceName, UserName,
          FileName, CommandLine, Tactic, Technique
| sort by TimeGenerated asc
```
**Screenshot when:** At least one row with Tactic or Technique visible.  
**If 0 results:** Remove the `where Tactic` filter — show all detections for that endpoint.

---

### Screenshot 02 — CrowdStrike: Alert Severity Corroboration
**Save as:** `02-crowdstrike-alert-severity.png`

```kql
let endpoint = "REPLACE-WITH-YOUR-DEVICE-NAME";
CrowdStrikeAlerts
| where TimeGenerated > ago(7d)
| where DeviceName == endpoint
| project TimeGenerated, DeviceName, Severity,
          Name, Description, Status
| sort by TimeGenerated asc
```
**Screenshot when:** Severity column visible. Note if High/Critical.  
**This confirms: same endpoint, corroborated by two CrowdStrike tables = Medium-Strong confidence.**

---

### Screenshot 03 — PaloAlto: Outbound Traffic from Endpoint
**Save as:** `03-paloalto-outbound.png`

> First — get the endpoint IP from Screenshot 01 results (look at the row details).  
> If no IP visible, run: `CrowdStrikeDetections | where DeviceName == "YOUR-DEVICE" | project LocalIP | take 1`

```kql
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == endpoint_ip
| where DeviceAction == "allow"
| project TimeGenerated, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol, DeviceAction
| sort by TimeGenerated asc
```
**Screenshot when:** Rows show outbound connections from endpoint IP.  
**Look for:** Unusual DestinationPorts (4444, 8080, 443 to unknown IPs, 22).

---

### Screenshot 04 — PaloAlto: Denied / Suspicious Traffic
**Save as:** `04-paloalto-denied-traffic.png`

```kql
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == endpoint_ip
| where DeviceAction == "deny"
| project TimeGenerated, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol, DeviceAction
| sort by TimeGenerated asc
```
**Screenshot when:** Any rows visible — denied = blocked lateral move attempt.  
**If 0 results:** Screenshot the 0-result screen anyway + note "no blocked traffic = attacker moved freely."

---

### Screenshot 05 — PaloAlto: East-West (Internal Lateral Movement)
**Save as:** `05-paloalto-east-west.png`

```kql
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == endpoint_ip
| where DestinationIP startswith "10." 
    or DestinationIP startswith "192.168."
    or DestinationIP startswith "172."
| project TimeGenerated, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol
| sort by TimeGenerated asc
```
**Screenshot when:** Internal IPs visible in DestinationIP = lateral movement evidence.  
**This is your strongest pivot — endpoint → internal spread.**

---

### Screenshot 06 — Full Kill Chain Timeline
**Save as:** `06-timeline-endpoint-network.png`

```kql
let endpoint = "REPLACE-WITH-YOUR-DEVICE-NAME";
let endpoint_ip = "REPLACE-WITH-ENDPOINT-IP";
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| where DeviceName == endpoint
| project TimeGenerated, Source="CrowdStrike-Detection",
          Event=Technique, Detail=FileName
| union (
    CrowdStrikeAlerts
    | where TimeGenerated > ago(7d)
    | where DeviceName == endpoint
    | project TimeGenerated, Source="CrowdStrike-Alert",
              Event=Name, Detail=Severity
)
| union (
    CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceVendor == "Palo Alto Networks"
    | where SourceIP == endpoint_ip
    | project TimeGenerated, Source="PaloAlto-Firewall",
              Event=ApplicationProtocol, Detail=DestinationIP
)
| sort by TimeGenerated asc
```
**Screenshot when:** Both CrowdStrike AND PaloAlto rows visible in Source column.  
**This is your money screenshot. Full forward pivot — endpoint alert to network traffic.**

---

## Quick Checklist

| # | File Name | Query Ran | Screenshotted |
|---|---|---|---|
| Pre | PaloAlto table verified | ☐ | — |
| Pre | Endpoint name grabbed | ☐ | — |
| 01 | 01-crowdstrike-detection.png | ☐ | ☐ |
| 02 | 02-crowdstrike-alert-severity.png | ☐ | ☐ |
| 03 | 03-paloalto-outbound.png | ☐ | ☐ |
| 04 | 04-paloalto-denied-traffic.png | ☐ | ☐ |
| 05 | 05-paloalto-east-west.png | ☐ | ☐ |
| 06 | 06-timeline-endpoint-network.png | ☐ | ☐ |

---

## If PaloAlto Has 0 Data (Same as TL-04 situation)

Run Queries 01 and 02 only (CrowdStrike). Screenshot both.  
Then run this as Screenshot 03:

```kql
CrowdStrikeDetections
| where TimeGenerated > ago(7d)
| summarize count() by Tactic, Technique
| sort by count_ desc
```

Document in README: *"PaloAlto/CommonSecurityLog returned 0 results — network logging connector not configured. Control Failure: no east-west traffic visibility. Recommend enabling PAN-OS CEF connector."*

---

## Imperfect Reality Layer (Fill in README after lab)

- **False assumption I made:** _________________________
- **Failed query (write exact KQL):** _________________________
- **Uncertainty moment:** _________________________

*(Required per lab discipline rules — imperfect reality = credibility)*

---

---

# README TEMPLATE — Paste into GitHub after lab

```markdown
# TL-02 — Endpoint-Driven Lateral Movement
**Pivot Direction:** Forward (Endpoint → Network)  
**Vendors:** CrowdStrike → PaloAlto Firewall  
**Identity Pivot:** NONE (endpoint-only investigation)  
**Severity:** [High/Critical — fill after lab]  
**Status:** TP / FP / Escalated — [fill after lab]

---

## S1 — Alert Summary

**Trigger:** CrowdStrikeDetections fired [TACTIC] on endpoint [DEVICE-NAME]  
**Time of Detection:** [TimeGenerated from Screenshot 01]  
**Affected Endpoint:** [DeviceName]  
**Endpoint IP:** [LocalIP]

### Severity Rubric
| Factor | Score | Notes |
|---|---|---|
| Impact | High | Credential access on endpoint |
| Confidence | Medium/High | 2 CrowdStrike tables corroborate |
| Scope | Medium | Single endpoint, possible spread |
| Business Criticality | [fill] | [domain-joined? server? workstation?] |
| **Final Severity** | **High** | |

---

## S2 — 🔵 SC-200 Investigation

### Hypothesis
CrowdStrike detected suspicious process on [DEVICE]. I expect to find:
- Credential dumping technique (Mimikatz/LSASS access)
- Outbound C2 traffic from endpoint IP via PaloAlto
- Possible internal east-west movement

### Query 01 — CrowdStrike Detection
![01-crowdstrike-detection](screenshots/01-crowdstrike-detection.png)
**Finding:** [what tactic/technique appeared]

### Query 02 — CrowdStrike Alert Severity
![02-crowdstrike-alert-severity](screenshots/02-crowdstrike-alert-severity.png)
**Finding:** [severity level, alert name]

### Query 03 — PaloAlto Outbound
![03-paloalto-outbound](screenshots/03-paloalto-outbound.png)
**Finding:** [outbound connections / or 0 results + gap documented]

### Query 04 — PaloAlto Denied Traffic
![04-paloalto-denied](screenshots/04-paloalto-denied-traffic.png)
**Finding:** [blocked attempts / or free movement]

### Query 05 — East-West Internal
![05-paloalto-east-west](screenshots/05-paloalto-east-west.png)
**Finding:** [internal spread / or no lateral movement]

### Query 06 — Kill Chain Timeline
![06-timeline](screenshots/06-timeline-endpoint-network.png)

### TP/FP Decision
**Decision:** [TP / FP]  
**Reason:** [evidence that tipped the decision]  
**Evidence Confidence:** Strong / Medium / Weak

### FP Branch
If FP — what would have looked different?
- No matching PaloAlto traffic from endpoint IP
- CrowdStrike alert = test/simulation tag
- User confirmed authorized pentest activity

---

## S3 — MITRE ATT&CK

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | OS Credential Dumping | T1003 | CrowdStrikeDetections — Technique |
| Lateral Movement | Remote Services | T1021 | PaloAlto east-west traffic |
| Command & Control | Application Layer Protocol | T1071 | PaloAlto outbound port 443/8080 |
| Discovery | Network Service Discovery | T1046 | PaloAlto denied scan traffic |

---

## S4 — Mitigation

1. Isolate [DEVICE-NAME] from network immediately
2. Revoke credentials for [UserName from Query 01]
3. Block [suspicious DestinationIP] at firewall
4. Run full forensic scan on endpoint
5. Check other endpoints for same Technique signature

---

## Control Failure

**What failed:**
- Endpoint allowed credential dumping process to run (no EDR block rule)
- [If PaloAlto 0 results]: No network logging for east-west traffic = blind spot

**Why it matters:** Attacker moved from endpoint to network without automated block.

---

## S5 — 🟠 AZ-500 Hardening ⚠️ THEORETICAL — Hands-on Month 2–3

### D1 — Identity
- Enable PIM for any admin accounts on affected endpoint
- Require MFA re-auth after endpoint anomaly trigger

### D2 — Networking
- Enable Azure Firewall / NSG rules to block lateral movement ports (445, 3389, 22)
- Deploy Bastion — eliminate direct RDP/SSH exposure

### D3 — Compute
- Enable JIT VM Access on affected machine
- Deploy Defender for Endpoint — auto-isolate on High severity alert
- Enable Credential Guard on Windows endpoints

### D4 — Security Operations
- Create Sentinel Automation Rule: CrowdStrike High → auto-tag + notify SOC
- Add PaloAlto CEF connector if not configured (detection gap fix)

---

## S6 — Lessons Learned + Interview Q&A

### What I Did Right
- [fill after lab]

### What Failed / Unexpected
- [fill imperfect reality layer here]

### If I Did This Again
- [fill after lab]

### Interview Q&A

**Q: Walk me through a lateral movement investigation.**  
A: I start with the endpoint alert — CrowdStrike fired a credential dumping detection on [DEVICE]. I confirmed severity via CrowdStrikeAlerts — two tables corroborating = higher confidence. I then pivoted forward to PaloAlto firewall logs using the endpoint IP — looking for outbound C2 traffic and internal east-west connections. [Fill actual findings]. Decision: TP — escalated to Tier 2 with full kill chain timeline.

**Q: What if the firewall had no logs?**  
A: That itself is a finding — it means the PaloAlto connector isn't configured, which is a detection gap. I document it as a control failure in my report and recommend enabling the CEF connector. A zero-result query is not a failed investigation — it's evidence of a blind spot.

---

## Closure Criteria
- [ ] Endpoint isolated or cleared
- [ ] Credentials rotated for affected user
- [ ] Suspicious IPs blocked at firewall
- [ ] Detection gap (if any) documented and ticket raised
- [ ] README complete with all screenshots
```
