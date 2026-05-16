# Exercise 04 — Automation Rules

**SC-200 Domain:** D3 Microsoft Sentinel (50–55%)  
**Difficulty:** Beginner | **Status:** ✅ Complete

---

## What This Exercise Covers

Manual incident triage doesn't scale. **Automation rules** in Microsoft Sentinel allow no-code, automatic enrichment and routing of incidents the moment they're created — without needing a Logic App (playbook). This exercise creates two automation rules: one that tags AWS threat incidents, and one that escalates log-clearing events to Critical severity. These are the kind of workflow improvements that directly reduce analyst MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond).

---

## Automation Rules vs. Playbooks — Key Distinction

> **SC-200 exam critical:** This distinction appears on the exam. Know it cold.

| | Automation Rules | Playbooks (Logic Apps) |
|--|-----------------|----------------------|
| **Requires code?** | ❌ No | ✅ Yes (Logic App designer) |
| **Requires Azure resources?** | ❌ No | ✅ Yes (Logic App instance) |
| **Actions available** | Tags, severity, owner, status, suppress, run playbook | Anything — block IP, disable account, send Teams/email |
| **Execution trigger** | Incident created or updated | Triggered by automation rule or manually |
| **Human decision required?** | No (runs automatically) | No (but humans review results) |
| **Who owns TP/FP decision?** | Human analyst | Human analyst (always) |

**The rule:** Automation rules handle **triage automation** (tagging, routing, severity). Playbooks handle **response automation** (containment, notification). Humans own **all decisions** (TP/FP, escalation, legal action).

---

## Lab Steps Completed

### Step 1 — Review Existing Incidents

Navigated to the incident queue to identify automation targets.

**Navigation path:**  
Microsoft Sentinel → Threat management → Incidents

Incidents visible from lab rules:
- `Lab Stage 3.5 - Internal port scan detected (Palo Alto)`
- `Lab Stage 6 - Large data exfiltration to external IP (Palo Alto)`
- `Lab Stage 4 - Account Takeover Chain (Okta)`

📸 *[Screenshot — Sentinel incidents list showing lab-generated incidents]*

**Lab note:** Automation rules with the "Analytic rule name" condition work with **Sentinel analytics rules** (not custom detection rules in Defender). The lab's analytics rules include: `AWS Config Service Resource Deletion Attempts`, `Suspicious AWS CLI Command Execution`, `NRT Security Event log cleared`, `Scheduled Task Hide`.

---

### Step 2 — Create Automation Rule: Tag AWS Threat Incidents

**Navigation path:**  
Microsoft Sentinel → Configuration → Automation → + Create → Automation rule

**Rule configuration:**

| Field | Value |
|-------|-------|
| **Name** | `Tag AWS threat incidents` |
| **Rule type** | Standard rule |
| **Trigger** | When incident is created |
| **Condition** | Analytic rule name **Contains** `AWS` |
| **Action 1** | Add tags → `cloud-threat` |
| **Action 2** | Add tags → `aws` |
| **Order** | 1 |
| **Status** | Enabled |

**Why "Contains" over exact match:** The condition `Contains AWS` matches BOTH `AWS Config Service Resource Deletion Attempts` AND `Suspicious AWS CLI Command Execution` with a single rule. Exact match would require two separate rules.

📸 *[Screenshot — automation rule creation wizard showing condition and action configuration]*

---

### Step 3 — Create Automation Rule: Escalate Log Cleared Events

**Rule configuration:**

| Field | Value |
|-------|-------|
| **Name** | `Escalate log cleared events` |
| **Rule type** | Standard rule |
| **Trigger** | When incident is created |
| **Condition** | Analytic rule name **Contains** `Security Event log cleared` |
| **Action 1** | Add tags → `defense-evasion` |
| **Action 2** | Add tags → `log-tampering` |
| **Action 3** | Change severity → **Critical** |
| **Order** | 2 |
| **Status** | Enabled |

**Why this matters:** Log clearing (T1562.008 — Defense Evasion) is a high-priority signal. An attacker who can clear Windows Security Event logs is actively trying to blind the SOC. Auto-escalating to Critical ensures it doesn't get buried in a backlog of Medium incidents.

📸 *[Screenshot — second automation rule showing three actions including severity escalation]*

---

### Step 4 — Understand Rule Ordering and Logic

**Final automation rules list:**

| Order | Name | Trigger | Condition | Actions |
|-------|------|---------|-----------|---------|
| 1 | Tag AWS threat incidents | Incident created | Rule name contains "AWS" | Add tags: cloud-threat, aws |
| 2 | Escalate log cleared events | Incident created | Rule name contains "Security Event log cleared" | Add tags: defense-evasion, log-tampering; Change severity → Critical |

**Execution logic:**
- Rules run in **priority order** (lowest number first)
- If multiple rules match the same incident, all execute sequentially
- Conditions use **AND** logic by default — all conditions must match
- A single incident CAN trigger multiple automation rules if it matches multiple conditions

📸 *[Screenshot — Automation page showing both rules in the list with order numbers]*

---

### Step 5 — Verify the Automation Rules

Confirmed tags and severity changes were applied to newly triggered incidents.

**Verification path:**  
Microsoft Sentinel → Threat management → Incidents → Find a matching incident → Check tags and severity

📸 *[Screenshot — incident detail showing auto-applied tags "cloud-threat" and "aws"]*  
📸 *[Screenshot — log-cleared incident showing Critical severity and tags "defense-evasion", "log-tampering"]*

---

## Additional Automation Actions (Not Configured — Reference)

| Action | Use Case |
|--------|---------|
| **Assign owner** | Route phishing incidents to email security team |
| **Change status** | Auto-close known false positives (e.g., scanner from trusted IP) |
| **Run playbook** | Trigger Logic App to send Teams alert, block IP, disable account |
| **Add task** | Create investigation checklist for assigned analyst |
| **Suppress** | Deduplicate repeated incidents from same rule |

---

## SC-200 Exam Relevance

| Concept Practiced | SC-200 Domain | Exam Topic |
|-------------------|---------------|------------|
| Automation rule vs. playbook distinction | D3 Sentinel | Automation concepts |
| Trigger types (incident created vs. updated) | D3 Sentinel | Rule trigger configuration |
| Condition logic (rule name, entity, severity) | D3 Sentinel | Automation rule conditions |
| Tag-based incident management | D3 Sentinel | Incident enrichment workflow |
| Priority ordering | D3 Sentinel | Rule execution order |
| Playbook integration (concept) | D3 Sentinel | Logic App trigger |

**High-frequency exam question pattern:**  
*"Which automation action requires a Logic App?"* → Answer: Run playbook. All other actions (tag, severity, owner, status, suppress) are native automation rule actions — no Logic App needed.

---

## MITRE ATT&CK

| Technique | ID | Automation Rule Created |
|-----------|----|------------------------|
| Defense Evasion: Indicator Removal (Log Clearing) | T1562.008 | Escalate log cleared events → Critical |
| Cloud resource abuse | T1496 | Tag AWS threat incidents → cloud-threat, aws |

---

## Key Takeaways

- Automation rules = **no-code triage automation** — tags, severity, owner, status. Zero Azure resources required
- Playbooks = **code-based response automation** — requires Logic App, used for containment and notification
- Humans always own TP/FP decisions, escalation calls, and legal/policy decisions — automation never decides
- Rule priority order matters — lower number executes first
- `Contains` in rule name conditions is more flexible than exact match — one rule can target multiple analytics rules
- Log clearing (T1562.008) is a Critical-severity signal that should always auto-escalate — if an attacker is clearing logs, they're already inside and aware of the SOC
