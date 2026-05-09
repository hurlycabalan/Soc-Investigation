# TL-04: Automation Rule & Playbook Troubleshooting

**Date:** May 9, 2026  
**Exercise:** Ex04 — Automation Rule Trigger Failure  
**Analyst:** Hurly Jimenez Cabalan  
**Environment:** Microsoft Sentinel (soc-workspace) + Defender XDR  
**Status:** ✅ Complete  

---

## S1 — Alert Summary

**Observed Problem:** Automation rule `E04_AutomationRule` was configured and Active 
but not triggering the `E04_AutomationRule_Playbook` when incidents were created.

**Playbooks deployed (all Active):**

![Playbooks Active](screenshots/EX04_01_playbooks-active-status.png)

**Automation rules configured:**

![Automation Rules List](screenshots/EX04_02_automation-rules-list.png)

---

## S2 — Investigation & Root Cause Analysis

### Step 1: Inspect the Automation Rule Conditions

Opened `E04_AutomationRule` → found two AND conditions:

- `Severity = High`
- `Alert product names Contains Microsoft Defender for Office 365`

![Root Cause Condition](screenshots/EX04_03_root-cause-MDO-condition.png)

### Step 2: Cross-reference with Actual Incident Data

Manually triggered `E04_AutomationRule_Playbook` on Incident #7 
(Suspicious AWS CLI Command Execution) → viewed Logic App JSON output.

**Confirmed alert product name in actual incidents:**

```json
"alertProductNames": ["Azure Sentinel"]
```

Training lab vendors (CrowdStrike, Palo Alto, Okta, CloudTrail, GCP, MailGuard365) 
ingest as custom log tables — they do NOT register as standard Azure alert product names. 
All lab incidents surface under `alertProductNames: Azure Sentinel`.

**Root cause confirmed:** Condition filter `Microsoft Defender for Office 365` 
never matched any lab incident. Rule silently skipped every time.

### Step 3: Attempted Intermediate Fix

Updated conditions to Severity = 4 selected (all) + Alert product names = 13 selected 
(all Microsoft products). Still incorrect — custom log vendor incidents 
still not in the Microsoft product name list.

![Conditions Still Wrong](screenshots/EX04_05_conditions-severity-all-selected.png)

### Step 4: Final Fix Applied

Deleted ALL conditions from `E04_AutomationRule`. 
Rule now triggers on ANY incident created in soc-workspace.

![Automation Rule Fixed](screenshots/EX04_04_actions-permissions-warning.png)

### SC-200 Table Translation

| Sentinel Concept | Table/Location |
|---|---|
| Automation rule config | Sentinel → Configuration → Automation |
| Playbook run history | Logic Apps → Run History |
| Incident trigger payload | SecurityIncident |
| Alert product names field | SecurityAlert → ProductName |

---

## S3 — Evidence

### Playbook Run Panel (before trigger)

![Run Playbook Panel](screenshots/EX04_06_run-playbook-panel.png)

### Runs Tab — Empty Before Fix

![Runs Empty](screenshots/EX04_07_playbook-succeeded-runs-tab.png)

### Playbook Succeeded — Manual Trigger Confirmed

`E04_AutomationRule_Playbook` — Status: **Succeeded**  
Timestamp: 5/9/2026, 08:50:14 AM

![Playbook Succeeded](screenshots/EX04_07_playbook-succeeded-runs-tab.png)

### Logic App JSON Output — Root Cause Evidence

Full incident payload received by Logic App:

![JSON Output Page 1](screenshots/EX04_08_logicapp-output-json-p1.png)

![JSON Output Page 2](screenshots/EX04_09_logicapp-output-json-p2.png)

**Key fields confirmed in output:**
- `objectEventType: Create` — incident creation event captured
- `WorkspaceName: soc-workspace` — correct workspace
- `assignedTo: hurly.soclab@outlook.com` — analyst account
- `alertProductNames: ["Azure Sentinel"]` — **smoking gun**
- `tactics: ["Reconnaissance"]` — MITRE confirmed
- `labels: [{"labelName": "LabTest"}]` — lab tag present

---

## S4 — Permissions Verification

### Playbook Permissions — Configure

![Playbook Permissions](screenshots/EX04_10_playbook-permissions-configure.png)

### SentinelLabRG Granted

![SentinelLabRG](screenshots/EX04_11_sentinellabrg-permissions-granted.png)

**Permissions status:**
- SOC-Lab resource group → already in Current permissions ✅
- SentinelLabRG → granted during this session ✅
- E04_AutomationRule_Playbook → Sentinel has explicit run permission ✅

---

## S5 — MITRE ATT&CK Mapping

| Tactic | Technique | Relevance |
|---|---|---|
| Defense Evasion | T1562 — Impair Defenses | Misconfigured automation = detection gap |
| Initial Access | T1078 — Valid Accounts | Incident: Suspicious AWS CLI by `mirage` |
| Reconnaissance | T1595 — Active Scanning | Tactics field confirmed in JSON output |

---

## S6 — Lessons Learned

### Control That Failed
Automation rule condition used `Alert product names = Microsoft Defender for Office 365` 
— a Microsoft-native product name that does not apply to custom log ingestion from 
third-party vendors (CrowdStrike, Palo Alto, Okta, CloudTrail, GCP, MailGuard365).

### Why It Failed Silently
Sentinel automation rules do not throw errors when conditions don't match — 
they simply skip execution. No alert, no log entry, no notification. 
The rule appeared Active and healthy.

### Earlier Detection Method
Check Logic App Run History immediately after creating an automation rule. 
If no runs appear after a known incident is created — conditions are the first suspect.

### Post-Incident Changes
1. Removed restrictive product name conditions
2. Granted SentinelLabRG playbook permissions
3. Validated via manual trigger → Succeeded

### Automation vs Human Boundary

| Automated | Human Decision |
|---|---|
| Playbook triggered on incident creation | TP/FP determination |
| Logic App receives full incident payload | Escalation decision |
| Incident tagged via automation rule | Severity adjustment |
| Geo-enrichment via Get-GeoFromIpAndTagIncident | Investigation ownership |

---

## Interview Q&A

**Q: Your automation rule was Active but not triggering. How did you diagnose it?**

> I started by checking the Logic App Run History — it was empty, which confirmed 
> the rule wasn't firing at all. I then opened the automation rule and found two 
> AND conditions: Severity = High and Alert product names = Microsoft Defender for 
> Office 365. I manually triggered the playbook on an existing incident, viewed the 
> Logic App JSON output, and found `alertProductNames: Azure Sentinel` — not MDO. 
> The condition never matched because training lab vendors ingest as custom log tables, 
> not native Microsoft product alert sources. Fix was simple: remove the conditions.

**Q: What is the difference between an automation rule and a playbook in Sentinel?**

> An automation rule is a lightweight, no-code trigger that runs automatically 
> based on incident conditions — it can tag, assign, change status, or call a playbook. 
> A playbook is a Logic App — a full workflow that can interact with external systems, 
> send notifications, isolate devices, or query APIs. The automation rule is the 
> trigger; the playbook is the action engine.

**Q: When would you NOT use an automation rule and use a playbook instead?**

> When the response requires complex logic — API calls to external systems, 
> conditional branching, multi-step workflows, or actions beyond what automation 
> rules support (tag, assign, status change, close). Simple notification = 
> playbook triggered by automation rule. Complex orchestration = playbook with 
> multiple actions directly.

---

*TL-04 | Training Lab | SOC-Investigations | Hurly Jimenez Cabalan*
