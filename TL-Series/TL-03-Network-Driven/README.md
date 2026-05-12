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

### What Happened (3-Sentence Story)
User `mirage` executed `report.exe` (rare prevalence, not quarantined) from `C:\Users\mirage\Downloads\` on internal host `win11a` (10.0.1.50). The malware performed an automated burst port scan hitting 124 unique destination ports across the network, then established 46 successful C2 callbacks on port 443 to external IPs 192.0.2.100, 198.51.100.42, and 203.0.113.77. The attacker then laterally moved to `srv-file01` (10.0.0.20), dumped LSASS credentials (TA0006/T1003), and used the stolen credentials to log into Okta — where they granted themselves super admin, created a persistent API token, and wiped MFA for other accounts.

---

## S2 — 🔵 SC-200 | Sentinel + Defender XDR

### Investigation Queries (Chronological)

**Step 1 — PaloAlto Recon (CommonSecurityLog)**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| take 5
```
*Confirmed PAN-OS data available. Activity = drop. Starting point.*

**Step 2 — Port Scan Detection**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize PortCount = dcount(DestinationPort) by SourceIP
| where PortCount > 5
| sort by PortCount desc
```
*Result: 10.0.1.50 → 124 unique destination ports. Automated scanner confirmed.*

**Step 3 — Traffic Drill-Down**
```kql
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where SourceIP == "10.0.1.50"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Activity
| sort by TimeGenerated asc
```
*Result: 298 firewall events — all "drop". Firewall blocking the scan.*

**Step 4 — Successful Connections (C2 Confirmation)**
```kql
CommonSecurityLog
| where SourceIP == "10.0.1.50"
| where Activity == "end"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort
```
*Result: 46 "end" events. DestinationIPs: 192.0.2.100, 198.51.100.42, 203.0.113.77 — all external, all port 443. C2 confirmed.*

**Step 5 — CrowdStrike Endpoint Pivot**
```kql
CrowdStrikeDetections
| take 5
```
*Result: report.exe — C:\Users\mirage\Downloads\report.exe. GlobalPrevalence = rare. Not quarantined. Parent = explorer.exe. Critical severity.*

**Step 6 — Host Lookup (win11a)**
```kql
CrowdStrikeHosts
| where Hostname == "srv-file01"
```
*Result: srv-file01 = 10.0.0.20, ExternalIp = 167.236.57.104, agent_id = cs-aid-srvfile-0008.*

**Step 7 — Host Tied to Scanning IP**
```kql
CrowdStrikeHosts
| where ConnectionIp == "10.0.1.50"
```
*Result: 2 Dell desktops confirmed mapped to 10.0.1.50 (win11a).*

**Step 8 — LSASS Detection on srv-file01**
```kql
CrowdStrikeDetections
| where DetectionId contains "srv"
```
*Result: 10 detections on srvfile-0008 and srvdc01. Expanded row: tactic = Credential Access (TA0006), technique = OS Credential Dumping (T1003), display_name = "Credential Dumping via LSASS". Hostname = srv-file01. MaxSeverity = Critical (80).*

**Step 9 — Okta Identity Pivot**
```kql
OktaV2_CL
| where ActorUserId contains "mirage"
```
*Result: 12 events. user.session.start → user.account.privilege.grant (super admin) → system.api_token.create → user.mfa.factor.deactivate → user.mfa.factor.reset_all → user.mfa.factor.update (new TOTP enrolled). Full account takeover confirmed.*

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
| Command & Control | T1071.001 — Application Layer Protocol: Web | 46 C2 callbacks on port 443 to external IPs |
| Credential Access | T1003.001 — OS Credential Dumping: LSASS | LSASS dump on srv-file01, CrowdStrike detection |
| Lateral Movement | T1550 — Use Alternate Authentication Material | LSASS creds used to access srv-file01 |
| Initial Access (Cloud) | T1078 — Valid Accounts | Stolen mirage credentials used in Okta |
| Privilege Escalation | T1098 — Account Manipulation | Super admin role granted in Okta |
| Persistence | T1528 — Steal Application Access Token | API token created in Okta |
| Defense Evasion | T1556 — Modify Authentication Process | MFA deactivated and reset for accounts |

---

## S4 — Mitigation

### Immediate (0–1 hour)
- [ ] Isolate `win11a` (10.0.1.50) — network containment
- [ ] Isolate `srv-file01` (10.0.0.20) — potential credential store compromised
- [ ] Disable `mirage` Okta account immediately
- [ ] Revoke all API tokens created by `mirage`
- [ ] Reset all MFA for affected accounts — force re-enrollment through secure channel
- [ ] Block external IPs: 192.0.2.100, 198.51.100.42, 203.0.113.77 at firewall

### Short-term (24–72 hours)
- [ ] Hash `report.exe` (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) — add to blocklist
- [ ] Force password reset for all CONTOSO domain accounts (LSASS scope unknown)
- [ ] Audit all Okta privilege grants in last 30 days
- [ ] Review API token inventory — revoke unknown tokens
- [ ] Review srvdc01 detections — domain controller may be affected

### Long-term
- [ ] Deploy EDR behavioral rule blocking LSASS access from non-system processes
- [ ] Enable Okta Privileged Access Management (PAM) — require MFA step-up for admin actions
- [ ] Implement Conditional Access policy — block Okta admin actions from non-compliant devices
- [ ] Enable CrowdStrike real-time response for automatic isolation on Critical detections

---

## Control Failure Analysis

| Layer | Control | Failure Mode |
|---|---|---|
| Endpoint | CrowdStrike EDR | report.exe detected but **not quarantined** — prevention policy not enforced |
| Network | PaloAlto Firewall | Port scan traffic **logged but not alerted** — no alert rule for internal burst scanning |
| Identity | Okta MFA | Attacker was able to **deactivate MFA** — no admin approval required for MFA changes |
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
- Initially assumed LSASS claim was unconfirmed — needed to learn CrowdStrikeDetections schema (`DetectionId contains "srv"`) before finding the evidence
- Used wrong field name (`Device` instead of `ActorUserId` in OktaV2_CL) — schema check first next time

### Interview Q&A

**Q: How did you identify this as a True Positive and not a vulnerability scanner?**
A: Three factors: (1) report.exe had rare GlobalPrevalence — a legitimate scanner would be a known tool. (2) The C2 callbacks on port 443 to external IPs confirmed outbound communication — scanners don't call home. (3) LSASS dump + Okta privilege escalation confirmed active attacker behavior, not scheduled scanning.

**Q: Why did you pivot to Okta?**
A: LSASS credential dumping on srv-file01 means credentials were harvested. The logical question is: were those credentials used anywhere else? Okta is the identity provider — if stolen creds were replayed, that's where we'd see it. The 12 Okta events confirmed the attacker moved from on-prem to cloud identity.

**Q: What controls failed here?**
A: Five layers failed simultaneously: CrowdStrike detected but didn't quarantine, firewall logged but didn't alert on the scan, Okta allowed MFA deactivation without approval, super admin was grantable without PIM, and LSASS had no PPL protection. Any single one of these working would have broken the chain.

**Q: What's the blast radius?**
A: Confirmed: win11a and srv-file01 on-prem, full Okta tenant (super admin = everything). Potential: srvdc01 also had CrowdStrike detections — if the DC is compromised, we may need a full domain credential reset. That's L2's call after deeper forensics.
