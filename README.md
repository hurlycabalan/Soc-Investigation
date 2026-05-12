# SOC Investigation Portfolio
**Hurly Jimenez Cabalan** | Aspiring SOC Analyst | Doha, Qatar  
📧 hurly.soclab@outlook.com | 🔗 [LinkedIn](https://linkedin.com/in/hurlycabalan)

---

## About This Repository

Structured detection and investigation portfolio built using **Microsoft Sentinel**, 
**Defender XDR**, and a multi-vendor training lab environment simulating real MSSP 
SOC operations. Every scenario follows a complete investigation lifecycle:

> Alert → Hypothesis → KQL Investigation → TP/FP Decision → 
> Mitigation → Lessons Learned → Interview Q&A

**Target role:** SOC Analyst L1 — Qatar-based MSSPs (Meeza, Help AG, NTT DATA)  
**Primary stack:** Microsoft Sentinel | Defender XDR | KQL | MITRE ATT&CK  
**Certifications:** Google Cybersecurity Professional | Fortinet NSE 1 & 2 | 
ISC2 CC (Candidate) | SC-200 (In Progress) | AZ-500 (In Progress)

---

## Repository Structure

---

## SC-Series — SC-200 Exam Scenarios

| Scenario | Title | Status | Key Skills |
|---|---|---|---|
| [SC01](SC01-BruteForce/evidence) | Brute Force Attack Detection | ✅ Complete | SignInLogs, KQL, TP/FP |
| SC02 | Insider Threat | 🔄 In Progress | AuditLogs, Anomaly Detection |
| SC03 | Phishing | 🔄 Planned | EmailEvents, URL Analysis |
| SC04 | Account Takeover | 🔄 Planned | Identity Protection, MFA |
| SC05 | Lateral Movement | 🔄 Planned | DeviceEvents, Process Tree |

---

## TL-Series — Training Lab Investigations

Multi-vendor environment: **CrowdStrike · Palo Alto · Okta · CloudTrail · GCP · MailGuard365**  
All investigations include vendor-agnostic analysis + Microsoft/SC-200 translation layer.

| Exercise | Title | Status | Key Skills |
|---|---|---|---|
| [TL-01](TL-01-Identity-Driven) | Identity-Driven Attack | ✅ Complete | Okta, SignInLogs, MFA Bypass |
| TL-02 | Network Intrusion | 🔄 Planned | Palo Alto, NSG, KQL joins |
| TL-03 | C2 Beacon Detection | ✅ Complete | CrowdStrike, C2 patterns |
| [TL-04](TL-04-AutomationRule) | Automation Rule Troubleshooting | ✅ Complete | Logic Apps, Playbooks, Sentinel Automation |
| TL-05 | Cross-Source Correlation | 🔄 Planned | Multi-vendor KQL, Graph |

---

## KQL Drills

SC-200 level KQL reference library — 10 drills covering core detection patterns.

📄 [KQL Drills Reference](KQL-Drills)

**Drill topics:** SignInLogs · AuditLogs · SecurityEvent · DeviceEvents · 
AzureActivity · Brute Force · C2 Beacon · Account Takeover

---

## Investigation Framework

Every scenario is documented using a consistent 6-section structure:

| Section | Content |
|---|---|
| S1 | Alert Summary — what fired, why it matters |
| S2 | Investigation — KQL queries, timeline, evidence, TP/FP decision |
| S3 | MITRE ATT&CK Mapping |
| S4 | Mitigation — immediate response actions |
| S5 | Hardening — AZ-500 control layer (Identity, Network, Compute) |
| S6 | Lessons Learned + Interview Q&A |

---

## Evidence Standards

All investigations use **real lab screenshots** with:
- Azure tenant ID and timestamps
- Analyst account (`hurly.soclab@outlook.com`) visible in JSON output
- KQL queries written before documentation (no query = no GitHub entry)
- One false assumption, one failed query, one uncertainty moment per scenario

*Not copy-pasted. Real lab. Real errors. Real fixes.*

---

## Certifications & Study Stack

| Cert | Status |
|---|---|
| Google Cybersecurity Professional Certificate | ✅ Complete |
| Fortinet NSE 1 & 2 | ✅ Complete |
| ISC2 CC | ✅ Complete (Candidate) |
| Microsoft SC-200 | 🔄 Month 2 — May 2026 |
| Microsoft AZ-500 | 🔄 Month 3 — June 2026 |

---

*Built in Doha, Qatar | 2026*
