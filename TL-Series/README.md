
# TL-03 — Network-Driven Investigation
**Threat Lab | Network-First Pivot: PaloAlto → CrowdStrike → Okta**

---

## S1 — Alert Summary

| Field | Details |
|---|---|
| **Case ID** | TL-03 |
| **Date** | May 6, 2026 |
| **Severity** | 🔴 Critical |
| **Actor** | User `mirage` — host `win11a` (10.0.1.50) |
| **Initial Signal** | PaloAlto firewall — burst port scan from internal host |
| **Verdict** | ✅ True Positive — Escalate to L2 immediately |

### Severity Rubric
| Factor | Score | Reason |
|---|---|---|
| **Impact** | High | LSASS dumped, Okta super admin granted |
| **Confidence** | High | Multi-vendor corroboration (PaloAlto + CrowdStrike + Okta) |
| **Scope** | High | win11a + srv-file01 compromised, Okta tenant affected |
| **Business Criticality** | Critical | Active credential theft + cloud identity takeover |

### Attack Timeline

| Time | Event |
|---|---|
| 09:14 | `report.exe` executed by user `mirage` on `win11a` |
| 09:15 | Automated port scan begins — 124 unique ports, 298 firewall events |
| 09:17 | 46 outbound sessions on port 443 to external IPs |
| 09:24 | Lateral movement to `srv-file01` (10.0.0.20) |
| 09:29 | LSASS credential dumping detected on `srv-file01` |
| 09:36 | Stolen credentials used in Okta — super admin granted, MFA wiped |

### What Happened (3-Sentence Story)
User `mirage` executed `report.exe` (rare prevalence, not quarantined) from `C:\Users\mirage\Downloads\` on internal host `win11a` (10.0.1.50). The malware performed an automated burst port scan hitting 124 unique destination ports across the network, then established 46 outbound sessions on port 443 to external IPs consistent with C2 behavior. The attacker likely moved laterally to `srv-file01` (10.0.0.20) prior to LSASS credential dumping (TA0006/T1003) — exact lateral movement method unconfirmed — and subsequently used the stolen credentials in Okta, granting super admin, creating a persistent API token, and wiping MFA for other accounts.

> **Note:** External IPs (192.0.2.100, 198.51.100.42, 203.0.113.77) use RFC 5737 documentation ranges for safe public sharing.

---

## S2 — 🔵 SC-200 | Sentinel + Defender XDR

### Investigation Queries (Chronological)

**Step 1 — PaloAlto Recon**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| take 5
```
*Confirmed PAN-OS data available. Activity = drop. Starting point.*

![PaloAlto Recon Take5](TL-Series/screenshots/TL-03-01-PaloAlto-Recon-Take5.png)

---

**Step 2 — Port Scan Detection**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize PortCount = dcount(DestinationPort) by SourceIP
| where PortCount > 5
| sort by PortCount desc
```
*Result: 10.0.1.50 → 124 unique destination ports. Automated scanner confirmed.*

![Port Scan 124 Ports](TL-Series/screenshots/TL-03-02-PortScan-124Ports.png)

---

**Step 3 — Traffic Drill-Down**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == "10.0.1.50"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Activity
| sort by TimeGenerated asc
```
*Result: 298 firewall events — all "drop". Firewall blocking the scan.*

![Traffic 298 Drops Sorted](TL-Series/screenshots/TL-03-03-Traffic-298Drops-Sorted.png)

![Traffic 298 Drops Project](TL-Series/screenshots/TL-03-04-Traffic-298Drops-Project.png)

---

**Step 4 — Successful Outbound Sessions**
```kql
CommonSecurityLog
| where SourceIP == "10.0.1.50"
| where Activity == "end"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort
```
*Result: 46 completed outbound sessions on port 443 to external IPs — consistent with C2 behavior. Confirmed C2 pending deeper forensics.*

![Activity End 46 Results](TL-Series/screenshots/TL-03-08-Activity-End-46Results.png)

![C2 External IPs Port 443](TL-Series/screenshots/TL-03-09-C2-ExternalIPs-Port443.png)

---

**Step 5 — CrowdStrike Endpoint Detection**
```kql
CrowdStrikeDetections
| take 5
```
*Result: report.exe — C:\Users\mirage\Downloads\report.exe. GlobalPrevalence = rare. Not quarantined. Parent = explorer.exe. Critical severity. SHA256: [redacted for lab realism]*

![CrowdStrike ReportExe](TL-Series/screenshots/TL-03-05-CrowdStrike-ReportExe.png)

---

**Step 6 — Host Lookup (srv-file01)**
```kql
CrowdStrikeHosts
| where Hostname == "srv-file01"
```
*Result: srv-file01 = 10.0.0.20, ExternalIp = 167.236.57.104, agent_id = cs-aid-srvfile-0008.*

![CrowdStrikeHosts SrvFile01](TL-Series/screenshots/TL-03-06-CrowdStrikeHosts-SrvFile01.png)

---

**Step 7 — Host Lookup (win11a)**
```kql
CrowdStrikeHosts
| where ConnectionIp == "10.0.1.50"
```
*Result: 2 Dell desktops confirmed mapped to 10.0.1.50 — win11a is the scanner host.*

![CrowdStrikeHosts Win11a](TL-Series/screenshots/TL-03-07-CrowdStrikeHosts-Win11a.png)

---

**Step 8 — LSASS Detection on srv-file01**
```kql
CrowdStrikeDetections
| where DetectionId contains "srv"
```
*Result: tactic = Credential Access (TA0006), technique = OS Credential Dumping (T1003), display_name = "Credential Dumping via LSASS". Hostname = srv-file01. MaxSeverity = Critical (80). SHA256: [redacted for lab realism]*

![LSASS SrvFile01 Confirmed](TL-Series/screenshots/TL-03-10-LSASS-SrvFile01-Confirmed.png)

---

**Step 9 — Okta Identity Pivot**
```kql
OktaV2_CL
| where ActorUserId contains "mirage"
```
*Result: user.session.start → user.account.privilege.grant (super admin) → system.api_token.create → user.mfa.factor.deactivate → user.mfa.factor.reset_all → user.mfa.factor.update. Full account takeover confirmed.*

![Okta SuperAdmin MFAWipeout](TL-Series/screenshots/TL-03-11-Okta-SuperAdmin-MFAWipeout.png)

---

### FP Branch
> **What would make this benign?**
- Port scan from authorized vulnerability scanner (Nessus, Qualys) running scheduled assessment
- report.exe is an internal reporting tool with known hash
- Okta admin actions performed by authorized IT admin during maintenance window

> **What log disproves malice?**
- CrowdStrikeHosts showing report.exe with known/whitelisted hash
- Change ticket or CAB approval for Okta admin changes
- Scheduled scan record in asset management

> **Decision: Close or Escalate?**
- **Escalate immediately to L2.** No change ticket found. report.exe = rare prevalence, not quarantined. LSASS dump + Okta super admin grant = active attacker, not scanner. Multi-vendor corroboration = Strong TP.

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1204.002 — User Execution: Malicious File | report.exe run by mirage from Downloads |
| Discovery | T1046 — Network Service Scanning | 124 ports, 298 firewall events from 10.0.1.50 |
| Command & Control | T1071.001 — Application Layer Protocol: Web | 46 outbound sessions on port 443 — consistent with C2 |
| Credential Access | T1003.001 — OS Credential Dumping: LSASS | LSASS dump on srv-file01, CrowdStrike detection |
| Lateral Movement | T1550 — Use Alternate Authentication Material | Likely lateral movement to srv-file01; exact method unconfirmed |
| Initial Access (Cloud) | T1078 — Valid Accounts | Stolen mirage credentials used in Okta |
| Privilege Escalation | T1098 — Account Manipulation | Super admin role granted in Okta |
| Persistence | T1528 — Steal Application Access Token | API token created in Okta |
| Defense Evasion | T1556 — Modify Authentication Process | MFA deactivated and reset for accounts |

---

## S4 — Mitigation

### Immediate (0–1 hour)
- [ ] Isolate `win11a` (10.0.1.50) — network containment
- [ ] Isolate `srv-file01` (10.0.0.20) — credential store compromised
- [ ] Disable `mirage` Okta account immediately
- [ ] Revoke all API tokens created by `mirage`
- [ ] Reset all MFA for affected accounts — force re-enrollment through secure channel
- [ ] Block external IPs: 192.0.2.100, 198.51.100.42, 203.0.113.77 at firewall

### Short-term (24–72 hours)
- [ ] Hash `report.exe` — SHA256: [redacted for lab realism] — add to blocklist
- [ ] Force password reset for all CONTOSO domain accounts (LSASS scope unknown)
- [ ] Audit all Okta privilege grants in last 30 days
- [ ] Review API token inventory — revoke unknown tokens
- [ ] Review srvdc01 detections — domain controller may be affected
- [ ] Investigate lateral movement path to srv-file01 — method unconfirmed

### Long-term
- [ ] Deploy EDR behavioral rule blocking LSASS access from non-system processes
- [ ] Enable Okta Privileged Access Management — require MFA step-up for admin actions
- [ ] Implement Conditional Access policy — block Okta admin actions from non-compliant devices
- [ ] Enable CrowdStrike real-time response for automatic isolation on Critical detections

---

## Control Failure Analysis

| Layer | Control | Failure Mode |
|---|---|---|
| Endpoint | CrowdStrike EDR | report.exe detected but **not quarantined** — prevention policy not enforced |
| Network | PaloAlto Firewall | Port scan traffic **logged but not alerted** — no alert rule for internal burst scanning |
| Identity | Okta MFA | Attacker able to **deactivate MFA** — no admin approval required for MFA changes |
| Identity | Okta RBAC | **Super admin role granted without approval** — no Privileged Access Management in place |
| Endpoint | LSASS Protection | **No LSA Protection enabled** on srv-file01 — LSASS accessible to non-system processes |

---

## S5 — 🟠 AZ-500 | D1–D4 Controls
⚠️ THEORETICAL — Hands-on Month 2–3

**D1 — Identity & Access**
- Enable Entra ID Conditional Access: block sign-in from non-compliant/unmanaged devices
- Implement PIM (Privileged Identity Management): just-in-time activation for admin roles
- Enforce MFA step-up for all privileged Okta operations

**D2 — Secure Networking**
- NSG rule: alert on internal-to-internal burst traffic (>50 connections/second from single source)
- Azure Firewall: IDPS signature for port scanning behavior
- Enable Network Watcher Flow Logs for east-west traffic visibility

**D3 — Compute + Storage**
- Enable LSA Protection on all Windows servers (registry: `RunAsPPL = 1`)
- Enable Credential Guard on domain-joined machines
- Restrict LSASS access via Attack Surface Reduction rules

**D4 — Security Operations**
- Analytics rule: `dcount(DestinationPort) > 50 from single SourceIP within 60 seconds` → High alert
- Playbook: auto-disable Okta account on CrowdStrike Critical detection
- Automation rule: isolate host when LSASS dump behavior detected

---

## Closure Criteria
- [x] Root cause identified — report.exe executed by user mirage
- [x] Blast radius mapped — win11a, srv-file01, Okta tenant, srvdc01 (potential)
- [x] Containment actions defined — isolation, account disable, token revoke, IP block
- [x] Ownership assigned — L2 escalation with full evidence package
- [x] Documentation complete — all queries, screenshots, MITRE mapping recorded

---

## S6 — Lessons Learned + Interview Q&A

### Biggest Lesson
**Single vendor = weak signal. Multi-vendor corroboration = strong confidence.**
PaloAlto alone = "suspicious traffic." PaloAlto + CrowdStrike + Okta = "active attacker, active takeover, escalate now." The kill chain only becomes visible when you follow the evidence across vendors.

### What I Got Wrong
- Initially assumed LSASS claim was unconfirmed — needed to learn CrowdStrikeDetections schema (`DetectionId contains "srv"`) before finding evidence
- Used wrong field name (`Device` instead of `ActorUserId` in OktaV2_CL) — schema check first next time
- Lateral movement method to srv-file01 stated as confirmed but evidence only proves LSASS was dumped there — exact path remains unconfirmed

### Interview Q&A

**Q: How did you identify this as a True Positive and not a vulnerability scanner?**
A: Three factors: (1) report.exe had rare GlobalPrevalence — a legitimate scanner would be a known tool. (2) Outbound sessions on port 443 to external IPs are consistent with C2 behavior — scanners don't call home. (3) LSASS dump + Okta privilege escalation confirmed active attacker behavior, not scheduled scanning.

**Q: Why did you pivot to Okta?**
A: LSASS credential dumping on srv-file01 means credentials were harvested. The logical question is: were those credentials used anywhere else? Okta is the identity provider — if stolen creds were replayed, that's where we'd see it. The 12 Okta events confirmed the attacker moved from on-prem to cloud identity.

**Q: What controls failed here?**
A: Five layers failed simultaneously: CrowdStrike detected but didn't quarantine, firewall logged but didn't alert on the scan, Okta allowed MFA deactivation without approval, super admin was grantable without PIM, and LSASS had no PPL protection. Any single one of these working would have broken the chain.

**Q: What's the blast radius?**
A: Confirmed: win11a and srv-file01 on-prem, full Okta tenant (super admin = everything). Potential: srvdc01 also had CrowdStrike detections — if the DC is compromised, we may need a full domain credential reset. That's L2's call after deeper forensics.

**Q: How certain are you about the C2 attribution?**
A: Moderate confidence. Firewall "end" events confirm completed outbound sessions on port 443 to external IPs — consistent with C2 callback behavior, but not definitively confirmed without PCAP or TI match. I'd escalate as high-confidence suspicious rather than confirmed C2.
