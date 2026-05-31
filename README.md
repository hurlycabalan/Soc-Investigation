# SOC Investigation Portfolio — Hurly Cabalan

**Targeting:** SOC L1 Analyst roles in Qatar's cybersecurity market (MSSP focus)

This portfolio demonstrates hands-on detection and investigation work across cloud, endpoint, identity, and network environments using Microsoft Sentinel. It covers alert triage, KQL-based log analysis, MITRE ATT&CK mapping, TP/FP decision-making, and incident documentation — the core skills required in a Tier 1 SOC role.

> **Lab Environment:** Microsoft Sentinel deployed from the official [Azure Sentinel Training Lab](https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Microsoft-Sentinel-Training-Lab) into a personal Azure subscription (`soc-workspace`). Pre-recorded multi-vendor log data covering GCP, CrowdStrike, Okta, Palo Alto, AWS, and Microsoft Entra ID. All investigation work — KQL queries, TP/FP decisions, MITRE mapping, and documentation — is original.

---

## Featured Investigations

These three investigations are the best representation of my analytical approach. Each includes a plain English summary, full KQL methodology, real query results, MITRE mapping, and hardening recommendations.

| # | Investigation | Data Source | Key Techniques | Evidence |
|---|---|---|---|---|
| [SC-06](./SC-06-GCPCloudAttack/) | GCP Cloud Attack: Privilege Escalation, Cryptomining & Data Exfiltration | GCPAuditLogs | T1098.001 · T1562.008 · T1530 · T1552 · T1496 | ✅ Real KQL results + screenshots |
| [SC-01](./SC-01-BruteForce/) | Brute Force Attack — Identity Investigation | Okta / Entra ID | T1110.001 · T1078 | Investigation documented |
| [SC-03](./SC-03/) | Credential-Based Attack | Multi-vendor | T1110 · T1621 | Investigation documented |

---

## Additional Investigations

Extended lab work demonstrating breadth across attack types and vendor environments.

**SC Series — Single-Vendor Scenarios**

| Folder | Scenario |
|---|---|
| [SC-02](./SC-02/) | Endpoint detection and process investigation |
| [SC-04](./SC-04/) | Network-based lateral movement |
| [SC-05](./SC-05/) | Cloud workload detection |

**TL Series — Multi-Vendor Kill Chains**

Constructed kill chain scenarios mapping attacker progression across multiple security vendors. Scenarios are narrative-documented with KQL written against vendor table schemas.

| Folder | Scenario | Vendors |
|---|---|---|
| [TL-01](./TL-Series/TL-01/) | Identity-first attack | Okta → CrowdStrike |
| [TL-02](./TL-Series/TL-02/) | Endpoint-first attack | CrowdStrike → Palo Alto |
| [TL-03](./TL-Series/TL-03/) | Network-first reverse | Palo Alto → CrowdStrike → Okta |
| [TL-04](./TL-Series/TL-04/) | Cloud-only attack | AWS → GCP |
| [TL-05](./TL-Series/TL-05/) | Full kill chain capstone | MailGuard → Okta → CrowdStrike → Palo Alto → AWS → GCP |

---

## Investigation Methodology

Every investigation in this portfolio follows the same structured approach:

1. **Hypothesis** — What am I looking for and why?
2. **Query** — KQL written with explicit reasoning before execution
3. **Expected vs Actual** — Did the data confirm or challenge the hypothesis?
4. **TP/FP Decision** — Multi-source corroboration before escalating
5. **MITRE Mapping** — Tactic and technique identified per finding
6. **Hardening** — Specific controls recommended to prevent recurrence
7. **Lessons Learned** — One uncertainty, one failed query, analyst reflection

> Single query is never sufficient for TP/FP. Every escalation decision in this portfolio is backed by at least two correlated signals.

---

## Environment & Tools

| Category | Detail |
|---|---|
| **SIEM** | Microsoft Sentinel (Azure Log Analytics) |
| **Query Language** | KQL — `where`, `project`, `sort`, `summarize`, `contains`, `ago()`, `bin()` |
| **Log Sources** | GCPAuditLogs, CrowdStrikeAlerts, OktaV2_CL, CommonSecurityLog (Palo Alto), AWSCloudTrail, SigninLogs |
| **Frameworks** | MITRE ATT&CK, Evidence Confidence Model (Weak / Medium / Strong) |
| **Documentation** | GitHub Markdown — scenario narrative, KQL, screenshots, TP/FP, MITRE, hardening, closure |

---

## Certifications & Learning

| Credential | Status |
|---|---|
| Google Cybersecurity Certificate | ✅ Complete |
| Fortinet NSE 1 & 2 | ✅ Complete |
| TryHackMe SOC L1 Path | ✅ Complete |
| Microsoft SC-200 (Security Operations Analyst) | 🔄 In progress — exam target July 2026 |

---

## Background

I bring 16 years of client-facing and data-driven work in Qatar across Sony, Vodafone, and Nestlé — building the communication, analytical, and documentation discipline that SOC work demands. I transitioned into cybersecurity through structured self-study, hands-on lab work, and this investigation portfolio, targeting Tier 1 analyst roles at MSSPs in Qatar.

I am available for a live demonstration of the Sentinel workspace and any investigation in this portfolio.

---

**Skills demonstrated across this portfolio:** Alert triage · KQL log analysis · Cloud threat detection · Endpoint investigation · Identity attack detection · MITRE ATT&CK mapping · TP/FP decision-making · Incident documentation · Security hardening recommendations · Multi-vendor log correlation
