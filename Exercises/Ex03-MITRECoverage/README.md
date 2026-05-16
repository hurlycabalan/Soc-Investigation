# Exercise 03 — MITRE ATT&CK Coverage

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%)  
**Difficulty:** Beginner | **Status:** ✅ Complete

---

## What This Exercise Covers

Detection coverage is not just about having rules — it's about knowing **which adversary techniques you can and cannot detect**. This exercise uses Sentinel's **MITRE ATT&CK page** to visualise the lab's detection posture as a heat map, identify coverage gaps, and trace the full 10-stage lab attack chain through the MITRE framework. Understanding your coverage map is a core SOC analyst and detection engineer skill.

---

## Lab Steps Completed

### Step 1 — Open the MITRE ATT&CK Page

**Navigation path:**  
Microsoft Defender portal → Microsoft Sentinel → Threat management → MITRE ATT&CK

The matrix loads with colour-coded cells:

| Cell Colour | Meaning |
|-------------|---------|
| **Blue (shaded)** | At least one active analytics rule covers this technique |
| **Grey / unshaded** | No rule currently covers this technique |

The number inside each cell = number of rules mapped to that technique.

📸 *[Screenshot — MITRE ATT&CK matrix overview showing shaded cells across multiple tactics]*

---

### Step 2 — Filter to Active Analytics Rules Only

Filtered the matrix to show only deployed, active detection rules.

**Steps:**  
1. Click **Filters** (top of matrix)  
2. Under **Simulated** → deselect all  
3. Under **Active** → ensure **Analytics rules** is selected

📸 *[Screenshot — filtered matrix showing only active analytics rules coverage]*

**Result:** Matrix reflects exactly which techniques the lab's 22 deployed detection rules cover — no hunting queries or simulated coverage inflating the view.

---

### Step 3 — Explore a Covered Technique (T1046 — Network Service Discovery)

Clicked the **T1046** cell (blue, under Discovery tactic).

**Side panel showed:**
- Technique description: Network Service Discovery — adversaries probe the network to identify open services
- Rules mapped: `Lab Stage 3.5 - Internal Port Scan Detected (Palo Alto)` and `Lab Stage E2 - Port Scan Detection (Palo Alto)`
- Coverage from hunting queries (if applicable)

📸 *[Screenshot — T1046 technique side panel showing mapped rules]*

**Observation:** Some techniques have BOTH a stage rule (always enabled) AND an exercise rule (disabled by default). Stage rules = SOC baseline detection. Exercise rules = student practice versions with different thresholds.

---

### Step 4 — Identify Coverage Gaps

Scrolled through the matrix to find unshaded cells in critical tactics.

**Coverage gaps observed in the lab:**

| Tactic | Missing Technique | Root Cause |
|--------|------------------|------------|
| **Lateral Movement** | T1021 Remote Services | No east-west movement telemetry in current lab data |
| **Collection** | T1560 Archive Collected Data | Exfiltration detected at network level, not archiving stage |
| **Resource Development** | T1583 Acquire Infrastructure | Pre-attack activity — outside SOC telemetry scope |

📸 *[Screenshot — matrix showing unshaded cells in Lateral Movement tactic]*

**Key insight:** Coverage gaps don't always mean risk. Some techniques require specific data sources that may not be available in all environments. The MITRE page helps **prioritise detection engineering investment** — address gaps in high-frequency, high-impact techniques first.

---

### Step 5 — Map the Full Lab Attack Chain

Traced the 10-stage lab attack through the MITRE matrix:

| Stage | Tactic | Techniques | Data Source |
|-------|--------|-----------|-------------|
| S1 | Initial Access | T1566.001, T1566.002 | MailGuard — phishing email |
| S2 | Execution | T1204.002 | CrowdStrike — malicious payload |
| S3 | Credential Access | T1003.001 | CrowdStrike — LSASS credential dump |
| S3.5 | Discovery | T1046 | Palo Alto — internal port scan |
| S4 | Privilege Escalation | T1078.004, T1098 | Okta — account takeover |
| S6 | Exfiltration | T1041 | Palo Alto — large data transfer |
| S7 | Impact | T1078, T1098, T1496, T1562.008 | AWS — IAM escalation, resource abuse |
| S8 | Persistence | T1136.003, T1078.004 | AWS — backdoor account |
| S9 | Privilege Escalation | T1136.003, T1098, T1496 | GCP — IAM escalation |
| S10 | Initial Access | T1566.001, T1566.002 | MailGuard — second phishing wave |

📸 *[Screenshot — MITRE matrix with Stage annotations visible in shaded cells]*

---

### Step 6 — Evaluate a New Detection Idea (Password Spray — T1110.003)

Considered how to close the **T1110.003 Password Spraying** gap using OktaV2_CL data.

**Detection logic:** A single IP failing authentication against ≥5 distinct users in 4 hours is a classic spray pattern.

```kql
OktaV2_CL
| where TimeGenerated > ago(4h)
| where EventOriginalType == "user.session.start"
| where OriginalOutcomeResult == "FAILURE"
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(ActorUsername),
    TargetUsers = make_set(ActorUsername, 25)
    by SrcIpAddr
| where DistinctUsers >= 5
```

**If deployed:** This rule would appear as a new blue cell under **Credential Access → T1110.003** on the MITRE matrix.

> ⚠️ **Lab-level KQL** — uses `dcount()` and `make_set()` which are SC-200 adjacent but understand the concept: `dcount()` = count of distinct values, used for detecting diversity anomalies.

**This exercise is conceptual** — the rule was not deployed. The goal is understanding how detection engineering decisions drive the MITRE coverage map.

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| MITRE ATT&CK page navigation | D3 Sentinel | Sentinel threat management features |
| Filtering to active analytics rules | D3 Sentinel | Analytics rule management |
| Technique coverage vs. hunting queries | D3 Sentinel | Understanding detection coverage sources |
| Identifying coverage gaps | D3 Sentinel | Detection posture assessment |
| MITRE technique ID → detection rule mapping | D3 Sentinel | Rule configuration (MITRE tagging) |

**Key exam concept:** Every Sentinel analytics rule can be tagged with MITRE technique IDs during rule creation. These tags drive what appears on the coverage matrix. On the exam, expect questions about where to navigate to see coverage and how to map rules to techniques.

---

## MITRE ATT&CK — Full Lab Coverage Summary

### Covered by Lab Rules (22 detection rules)

| Tactic | Key Techniques Covered |
|--------|----------------------|
| Initial Access | T1566.001, T1566.002, T1078.004 |
| Execution | T1204.002 |
| Persistence | T1136.003 |
| Privilege Escalation | T1098 |
| Credential Access | T1003.001, T1556.006 |
| Discovery | T1046 |
| Command & Control | T1071.001 |
| Exfiltration | T1041 |
| Impact | T1496 |
| Defense Evasion | T1562.008 |

### Notable Gaps

| Tactic | Gap |
|--------|-----|
| Lateral Movement | T1021 (no east-west telemetry) |
| Collection | T1560 (no pre-exfil archiving data) |
| Resource Development | T1583 (pre-attack, no SOC telemetry) |

---

## Key Takeaways

- The MITRE ATT&CK page is a **real-time heat map** of your detection posture — it reflects only what your rules actually cover
- Always filter to **Active → Analytics rules** to see your true detection baseline, not hunting queries or simulated coverage
- Coverage gaps are **prioritisation inputs**, not failures — focus on gaps in high-frequency attack patterns with available data sources
- Every analytics rule MITRE tag you set during rule creation directly updates this matrix
- A single covered technique can have multiple rules — the number shown in each cell reflects this
- The attack chain is multi-stage. Defenders who see T1046 (port scan) without connecting it to T1566.001 (phishing) miss the full picture
