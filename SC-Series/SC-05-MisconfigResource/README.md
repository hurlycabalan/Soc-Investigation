# SC-05 | Misconfigured Cloud Resource — Public Storage Exposure

**Scenario ID:** SC-05  
**Classification:** Cloud Misconfiguration / Data Exposure  
**Severity:** 🟠 High  
**Platform:** Microsoft Sentinel + GCP Audit Logs + Defender for Cloud  
**Author:** Hurly Cabalan  
**Status:** Investigation Complete  

---

## S1 — Alert Summary

### Incident Trigger
Microsoft Sentinel Analytics Rule fired: **"GCP Storage Bucket — Public Access Detected with High Read Volume"**  
A GCP Cloud Storage bucket containing HR documents was accidentally set to public access during a routine infrastructure change. Within 4 hours, 1,200 anonymous GET requests were observed — indicating external enumeration and potential data harvesting.

### Severity Rubric

| Factor | Assessment | Score |
|---|---|---|
| **Impact** | HR documents (contracts, payroll data) potentially exposed | High |
| **Confidence** | Audit logs confirm public ACL + anonymous access confirmed | High |
| **Scope** | Single bucket, unknown number of external IPs accessed it | Medium |
| **Business Criticality** | Regulatory exposure — PDPA/GDPR applies to HR data | High |
| **Final Severity** | 🟠 **HIGH** | |

### Timeline Overview
```
08:45 UTC — Infrastructure team modifies bucket ACL during storage migration
08:47 UTC — Bucket permissions set to "allUsers" read — misconfiguration occurs
09:02 UTC — First anonymous GET request detected (external IP: 91.108.x.x)
09:15 UTC — Enumeration pattern begins: 120 GET requests in 13 minutes
12:50 UTC — Sentinel alert fires: >1000 anonymous reads in 4 hours
13:05 UTC — SOC L1 assigned, investigation begins
13:22 UTC — Bucket ACL corrected, public access removed
```

---

## S2 — 🔵 SC-200 Investigation (Sentinel + Defender XDR)

### Hypothesis
> A misconfigured cloud storage bucket exposed sensitive HR data to the public internet. The access pattern — anonymous IPs, rapid sequential GET requests on structured filenames — suggests automated enumeration rather than accidental discovery. We need to confirm the scope of what was accessed and close the exposure window.

### Step 1 — Identify the Misconfiguration Event (GCP Audit Logs)
**What we're looking for:** Who changed the bucket ACL and when? Was this intentional?

```kql
GCPAuditLogs
| where TimeGenerated > ago(12h)
| where protoPayload_methodName_s contains "storage.setIamPolicy"
| project TimeGenerated, protoPayload_authenticationInfo_principalEmail_s,
          protoPayload_resourceName_s, protoPayload_requestMetadata_callerIp_s
| sort by TimeGenerated asc
```

**Expected Result:** An internal service account or admin changed the bucket IAM policy — allUsers binding added.

**Actual Result:** ✅ infra-migration@company.com changed IAM policy at 08:47 UTC — `allUsers` role `roles/storage.objectViewer` added. **Misconfiguration confirmed — human error during migration.**

---

### Step 2 — Quantify Anonymous Access Volume
**What we're looking for:** How many external reads happened? Is this random scanning or targeted enumeration?

```kql
GCPAuditLogs
| where TimeGenerated > ago(8h)
| where protoPayload_methodName_s == "storage.objects.get"
| where protoPayload_authenticationInfo_principalEmail_s == ""
| summarize AccessCount = count() by protoPayload_requestMetadata_callerIp_s
| sort by AccessCount desc
```

**Expected Result:** Multiple external IPs with high GET counts — enumeration pattern.

**Actual Result:** ✅ 3 unique external IPs, one with 847 requests in 4 hours. **Automated enumeration confirmed.**

---

### Step 3 — Identify What Files Were Accessed
**What we're looking for:** Which specific objects were retrieved? Do they contain PII/sensitive data?

```kql
GCPAuditLogs
| where TimeGenerated > ago(8h)
| where protoPayload_methodName_s == "storage.objects.get"
| where protoPayload_authenticationInfo_principalEmail_s == ""
| project TimeGenerated, protoPayload_resourceName_s,
          protoPayload_requestMetadata_callerIp_s
| sort by TimeGenerated asc
```

**Expected Result:** List of specific filenames accessed — HR contracts, payroll exports, employee records.

**Actual Result:** ✅ Files accessed include: `hr-contracts-2024.xlsx`, `payroll-q1-2025.csv`, `employee-directory.pdf`. **PII confirmed as accessed — regulatory notification may be required.**

---

### Step 4 — Check for Lateral Spread (Were Other Buckets Affected?)
**What we're looking for:** Did the misconfiguration spread to other storage resources, or is it isolated?

```kql
GCPAuditLogs
| where TimeGenerated > ago(12h)
| where protoPayload_methodName_s contains "storage.setIamPolicy"
| where protoPayload_authenticationInfo_principalEmail_s contains "infra-migration"
| project TimeGenerated, protoPayload_resourceName_s,
          protoPayload_methodName_s, protoPayload_requestMetadata_callerIp_s
| sort by TimeGenerated asc
```

**Expected Result:** Only one bucket modified — not a systematic error.

**Actual Result:** ✅ Only `hr-documents-prod` bucket affected. **Isolated misconfiguration — not systemic.**

---

### TP/FP Decision

| Signal | Weight |
|---|---|
| Bucket ACL changed to allUsers (audit log confirmed) | ✅ Strong |
| 1,200 anonymous GET requests in 4 hours | ✅ Strong |
| Specific PII files confirmed accessed | ✅ Strong |
| Enumeration pattern from 3 unique external IPs | ✅ Strong |
| Source IPs include known scanning infrastructure | ✅ Supporting |

**VERDICT: ✅ TRUE POSITIVE — Cloud Misconfiguration with Confirmed External Data Access**

---

### FP Branch — Could This Be Legitimate?

**FP Scenario 1:** The bucket was intentionally made public for a CDN or public-facing app.  
**Why Ruled Out:** Bucket contains HR documents — never intended for public distribution. No change ticket authorizing public access.

**FP Scenario 2:** The GET requests are Google's own crawler or internal GCP health checks.  
**Why Ruled Out:** Source IPs are external commercial ranges and known scanning services, not Google infrastructure. Volume (847 from one IP) is inconsistent with health checks.

**FP Scenario 3:** Automated backup system accessing the bucket.  
**Why Ruled Out:** Backup systems authenticate — these requests have no authentication principal (`principalEmail == ""`).

**FP Confidence: NONE — This is a confirmed TP with data exposure.**

---

## S3 — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Publicly accessible bucket discovered via scanning |
| Discovery | Cloud Storage Object Discovery | T1619 | 120 sequential GET requests across bucket contents |
| Collection | Data from Cloud Storage | T1530 | HR contracts, payroll files, employee directory accessed |
| Exfiltration | Exfiltration Over Web Service | T1567 | Data retrievable via public HTTPS URL |
| Defense Evasion | Impair Defenses: Disable or Modify Cloud Logs | T1562.008 | Log monitoring was not alerting on anonymous access volume |

---

## S4 — Mitigation (Immediate Response)

### Containment
- [ ] Immediately remove `allUsers` binding from bucket IAM policy
- [ ] Enable uniform bucket-level access (disable legacy ACLs)
- [ ] Enable public access prevention at the GCP project/organization level
- [ ] Rotate any service account keys that had access to the bucket
- [ ] Block source IPs (91.108.x.x range) at GCP firewall level

### Evidence Preservation
- [ ] Export full GCP Audit Logs for the bucket (last 30 days)
- [ ] Document exact file names and sizes accessed
- [ ] Capture source IP list with timestamp and request count
- [ ] Screenshot Sentinel alert, GCP IAM policy diff, and audit log evidence

### Regulatory Response
- [ ] Assess whether PDPA/GDPR breach notification is required (PII confirmed accessed)
- [ ] Notify Legal and Data Protection Officer within 24 hours
- [ ] Prepare incident report with: timeline, data exposed, IPs involved, containment actions
- [ ] Notify affected employees if personal data was confirmed downloaded

---

## Control Failure Analysis

| Control | Expected Behavior | What Failed |
|---|---|---|
| **Public Access Prevention** | GCP organization policy should block allUsers on private buckets | Policy was not enforced at organization level — only at bucket level |
| **Change Management (ITSM)** | ACL changes on sensitive buckets require change ticket + approval | Migration team bypassed ITSM for "minor" config change |
| **CSPM (Defender for Cloud)** | Detect public storage exposure in real-time | CSPM recommendation existed but was marked "Exempt" — not remediated |
| **Sentinel Alert Threshold** | Alert on anonymous access immediately | Alert threshold set to 1000 requests — 4-hour window before detection |

---

## S5 — 🟠 AZ-500 Hardening Recommendations (D1–D4)

> ⚠️ **THEORETICAL — Hands-on lab verification scheduled Month 2–3**

### D1 — Identity & Access
- **Enforce Least Privilege on Storage IAM** — Service accounts should have `roles/storage.objectCreator` only (not objectAdmin). No account should have permission to modify bucket IAM policies without explicit approval workflow.
- **Remove allUsers / allAuthenticatedUsers** — GCP Organization Policy `constraints/storage.publicAccessPrevention` enforces this at the org level and cannot be overridden by individual buckets.

### D2 — Secure Networking
- **VPC Service Controls** — Restrict GCP storage bucket access to approved VPC networks only. External IPs cannot reach private buckets even if IAM is misconfigured.
- **Private Google Access** — Internal services access GCS via private IPs. No data traverses the public internet.

### D3 — Compute + Storage
- **Customer-Managed Encryption Keys (CMEK)** — Even if the bucket is accessed externally, data is encrypted with keys only the organization controls. External access without the key = useless data.
- **Object Versioning + Retention Locks** — Detect and preserve evidence of data access. Attackers cannot delete access logs.
- **Storage Access Logs** — Enable data access audit logging for all storage buckets — not just the default admin activity logs.

### D4 — Security Operations
- **Defender for Cloud — CSPM** — Enable and enforce the "Ensure that Cloud Storage bucket is not anonymously or publicly accessible" recommendation. Remove any Exempt status for production buckets.
- **Sentinel Alert Tuning** — Lower anonymous access threshold: alert on first anonymous read from an external IP on buckets tagged `sensitivity:high`. Do not wait for 1000 requests.
- **Automation Playbook** — Auto-remove `allUsers` IAM binding when Defender for Cloud flags a public bucket. Remove the 4-hour detection-to-response gap.
- **Tagging Policy** — All buckets must have `data-classification` and `sensitivity` tags. Untagged buckets flagged automatically.

---

## S6 — Lessons Learned & Interview Q&A

### What Went Wrong
1. **No organization-level public access prevention** — A single engineer's error was enough to expose a production HR bucket. One IAM policy change at org level would have prevented this.
2. **CSPM recommendation ignored** — Defender for Cloud flagged this bucket as a risk weeks prior. It was marked Exempt. That exemption contributed directly to this incident.
3. **Alert threshold too high** — 1,000 anonymous reads before firing means 4 hours of exposure before detection. The first anonymous GET from an external IP on an HR bucket should have triggered an alert.

### What Went Right
1. GCP audit logs captured the exact misconfiguration event, including the principal who made the change
2. Containment (ACL removal) was completed within 17 minutes of SOC assignment
3. Impact was isolated — only one bucket affected, no lateral spread

### Closure Criteria
- [ ] Bucket ACL corrected and public access prevention enabled at org level
- [ ] All service account keys rotated
- [ ] Legal + DPO notified with incident report
- [ ] CSPM exemption removed — recommendation enforced
- [ ] Sentinel alert threshold lowered for high-sensitivity buckets
- [ ] Automation playbook deployed for auto-remediation of future public bucket detections
- [ ] Post-mortem completed with change management team
- [ ] Migration runbook updated to require ITSM ticket for any storage IAM change

---

### Interview Q&A

**Q: How is a cloud misconfiguration incident different from a malware or intrusion incident?**  
> A: The attack vector is different — there's no exploit, no credential theft, no malware. The vulnerability is access control misconfiguration. The attacker doesn't need to be sophisticated — any scanner can find a public bucket. The investigation focus shifts from "how did they get in" to "what was exposed and for how long." Data exposure assessment and regulatory notification become the primary outputs, not just containment.

**Q: What's the first thing you do when you see a public storage bucket alert?**  
> A: Close the exposure first — remove the public ACL immediately. Then investigate. Unlike an active intruder, a misconfigured bucket is a passive risk. Containment is fast (one IAM change), so you close it before deep investigation. After containment, you pull the audit logs to establish: when did it open, who opened it, what was accessed, from where. That sequence feeds the data breach assessment.

**Q: Why did this bypass CSPM if Defender for Cloud was enabled?**  
> A: CSPM detected it — but the recommendation was marked Exempt. That's a process failure, not a tooling failure. The tool worked. Someone decided the risk was acceptable and exempted it without proper review. This is why periodic CSPM exemption reviews are as important as enabling the tool in the first place. Every Exempt status should have an expiry date and owner.

---

*Portfolio: [github.com/hurlycabalan/Soc-Investigation](https://github.com/hurlycabalan/Soc-Investigation)*  
*Scenario Chain: SC-01 → SC-02 → SC-03 → SC-04 → SC-05*
