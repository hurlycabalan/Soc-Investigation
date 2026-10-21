# SOC Investigation Portfolio — Hurly Cabalan

**Microsoft Certified: Security Operations Analyst Associate (SC-200)**

**Targeting:** SOC L1 Analyst roles in Qatar and the GCC

This portfolio demonstrates hands-on detection and investigation work across cloud, endpoint, identity, and network environments using Microsoft Sentinel. It covers alert triage, KQL-based log analysis, MITRE ATT&CK mapping, TP/FP decision-making, and incident documentation — the core skills required in a Tier 1 SOC role.

> **Lab Environment:** Microsoft Sentinel deployed from the official [Azure Sentinel Training Lab](https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Microsoft-Sentinel-Training-Lab) into a personal Azure subscription (`soc-workspace`). Pre-recorded multi-vendor log data covering GCP, CrowdStrike, Okta, Palo Alto, AWS, and Microsoft Entra ID. All investigation work — KQL queries, TP/FP decisions, MITRE mapping, and documentation — is original.

---

## Featured Investigations

These three investigations are the best representation of my analytical approach. Each includes a plain English summary, full KQL methodology, real query results, MITRE mapping, and hardening recommendations. The SC scenario folders are inside [SC-Series](https://github.com/hurlycabalan/Soc-Investigation/tree/main/SC-Series).

| # | Investigation | Data Source | Key Techniques | Evidence |
|---|---|---|---|---|
| SC-06 | GCP Cloud Attack: Privilege Escalation, Cryptomining & Data Exfiltration | GCPAuditLogs | T1098.001 · T1562.008 · T1530 · T1552 · T1496 | ✅ Real KQL results + screenshots |
| SC-01 | Brute Force Attack — Identity Investigation | Okta / Entra ID | T1110.001 · T1078 | Investigation documented |
| SC-03 | Credential-Based Attack | Multi-vendor | T1110 · T1621 | Investigation documented |

---

## Additional Investigations

Extended lab work demonstrating breadth across attack types and vendor environments.

**SC Series — Single-Vendor Scenarios** (folder: [SC-Series](https://github.com/hurlycabalan/Soc-Investigation/tree/main/SC-Series))

| Scenario | Description |
|---|---|
| SC-02 | Endpoint detection and process investigation |
| SC-04 | Network-based lateral movement |
| SC-05 | Cloud workload detection |

**TL Series — Multi-Vendor Kill Chains**

Constructed kill chain scenarios mapping attacker progression across multiple security vendors. Scenarios are narrative-documented with KQL written against vendor table schemas.

| Folder | Scenario | Vendors |
|---|---|---|
| [TL-01](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series/TL-01) | Identity-first attack | Okta → CrowdStrike |
| [TL-02](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series/TL-02) | Endpoint-first attack | CrowdStrike → Palo Alto |
| [TL-03](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series/TL-03) | Network-first reverse | Palo Alto → CrowdStrike → Okta |
| [TL-04](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series/TL-04) | Cloud-only attack | AWS → GCP |
| [TL-05](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series/TL-05) | Full kill chain capstone | MailGuard → Okta → CrowdStrike → Palo Alto → AWS → GCP |

---

## Repository Map

| Item | What it is |
|---|---|
| [SC-Series](https://github.com/hurlycabalan/Soc-Investigation/tree/main/SC-Series) | Single-vendor investigation scenarios (SC-01 to SC-06) |
| [TL-Series](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-Series) | Multi-vendor kill chain scenarios (TL-01 to TL-05) |
| [TL-04-AutomationRule](https://github.com/hurlycabalan/Soc-Investigation/tree/main/TL-04-AutomationRule) | Automation rule work related to TL-04 |
| [KQL-Drills](https://github.com/hurlycabalan/Soc-Investigation/tree/main/KQL-Drills) | KQL practice drills |
| [Exercises](https://github.com/hurlycabalan/Soc-Investigation/tree/main/Exercises) | Practice exercises |
| [kql-queries.md](https://github.com/hurlycabalan/Soc-Investigation/blob/main/kql-queries.md) | KQL query reference |

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
| Microsoft Certified: Security Operations Analyst Associate (SC-200) | ✅ Earned September 2026 (valid to September 2027) |
| Google Cybersecurity Certificate | ✅ Complete |
| Fortinet NSE 1 & 2 | ✅ Complete |
| TryHackMe SOC L1 Path | ✅ Complete |
| Wazuh Challenge | ✅ Complete — 300/300, ranked 26 of 246 globally |

**Currently learning:** Splunk SPL for SOC L1 triage.

---

## Background

I bring 16 years of client-facing and data-driven work in Qatar across Sony, Vodafone, and Nestlé — building the communication, analytical, and documentation discipline that SOC work demands. I transitioned into cybersecurity through structured self-study, hands-on lab work, and this investigation portfolio, targeting Tier 1 analyst roles in Qatar and the GCC.

I am available for a live demonstration of the Sentinel workspace and any investigation in this portfolio.

---

**Skills demonstrated across this portfolio:** Alert triage · KQL log analysis · Cloud threat detection · Endpoint investigation · Identity attack detection · MITRE ATT&CK mapping · TP/FP decision-making · Incident documentation · Security hardening recommendations · Multi-vendor log correlation

*Last updated: October 2026*
