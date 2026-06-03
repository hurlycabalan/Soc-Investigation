> ⚠️ **CONSTRUCTED SCENARIO** — Sentinel Training Lab data expired June 3, 2026 before this lab session could be executed. All KQL queries, MITRE mappings, and investigation logic are based on the documented run sheet. No live screenshots available. This is consistent with the rest of the TL series (TL-01 through TL-04) which were also constructed due to schema/data availability constraints.

---
# TL-04: Cloud Credential Abuse — AWS to GCP Lateral Movement
**Severity:** Critical  
**Date:** [fill when you run the lab]  
**Vendors:** AWSCloudTrail → GCPAuditLogs  
**Direction:** Cloud-only — no endpoint, no identity (Okta), no network pivot

---

## S1 — Alert Summary
Suspicious AWS API calls were detected using what appeared to be valid cloud credentials — enumeration of IAM roles and S3 buckets followed by privilege escalation attempts. The same attacker IP was then found in GCP Audit Logs performing service account manipulation, suggesting the attacker used credentials harvested from AWS to move laterally into GCP. Cloud-only investigation — no endpoint or identity layer involved.

**Verdict:** TP — credential abuse in AWS confirmed by correlated GCP activity from same source IP

---

## S2 — KQL Queries Used

```kql
// Query 1 — AWS: what API calls are suspicious? (enumeration behavior)
AWSCloudTrail
| where TimeGenerated > ago(2h)
| where EventName in ("ListBuckets", "ListRoles", "ListUsers", "DescribeInstances", "GetCallerIdentity")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, AWSRegion
| sort by TimeGenerated asc
```

```kql
// Query 2 — AWS: privilege escalation attempts
AWSCloudTrail
| where TimeGenerated > ago(2h)
| where EventName in ("CreateAccessKey", "AttachRolePolicy", "PutUserPolicy", "AssumeRole")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, ErrorCode
| sort by TimeGenerated asc
```

```kql
// Query 3 — AWS: failed vs successful calls (is attacker probing?)
AWSCloudTrail
| where TimeGenerated > ago(2h)
| where SourceIpAddress contains "[IP from Query 1]"
| summarize Success = countif(ErrorCode == ""), Failed = countif(ErrorCode != "") by UserIdentityArn
| sort by Failed desc
```

```kql
// Query 4 — GCP: same source IP appearing in cloud logs?
GCPAuditLogs
| where TimeGenerated > ago(2h)
| where callerIp contains "[SourceIpAddress from Query 1]"
| project TimeGenerated, methodName, principalEmail, callerIp, resourceName, serviceName
| sort by TimeGenerated asc
```

```kql
// Query 5 — GCP: service account abuse or persistence?
GCPAuditLogs
| where TimeGenerated > ago(2h)
| where methodName in ("google.iam.admin.v1.CreateServiceAccount", "google.iam.admin.v1.SetIamPolicy", "google.iam.v1.IAMPolicy.SetIamPolicy")
| project TimeGenerated, methodName, principalEmail, callerIp, resourceName
| sort by TimeGenerated asc
```

```kql
// Query 6 — Unified cloud timeline (AWS + GCP in one view)
union
    (AWSCloudTrail | where TimeGenerated > ago(2h) | project TimeGenerated, Vendor="AWS", Event=EventName, Actor=UserIdentityArn, SourceIP=SourceIpAddress),
    (GCPAuditLogs | where TimeGenerated > ago(2h) | project TimeGenerated, Vendor="GCP", Event=methodName, Actor=principalEmail, SourceIP=callerIp)
| sort by TimeGenerated asc
```

---

## S3 — MITRE ATT&CK

| TTP | Technique | Vendor Evidence |
|-----|-----------|-----------------|
| T1580 | Cloud Infrastructure Discovery | AWS — ListBuckets, ListRoles, DescribeInstances |
| T1078.004 | Valid Cloud Accounts | AWS — API calls using valid credentials |
| T1548.005 | Abuse Elevation Control (Cloud) | AWS — AttachRolePolicy, AssumeRole attempts |
| T1098.001 | Additional Cloud Credentials | AWS — CreateAccessKey on another user |
| T1136.003 | Create Cloud Account | GCP — CreateServiceAccount detected |

---

## FP Branch
Could this be FP?
- AWS enumeration = could be legitimate DevOps automation → check if UserIdentityArn is a known service account
- GCP service account creation = could be scheduled deployment → check if methodName matches CI/CD pattern
- Same source IP in both = strongest TP indicator — legitimate automation rarely crosses AWS→GCP from same IP

**If source IP appears in both AWS and GCP = escalate immediately. Do not wait.**

---

## S4 — What I Would Do (Mitigation)
- Disable compromised AWS IAM user + rotate all access keys immediately
- Revoke suspicious GCP service account or IAM policy binding
- Block attacker IP in both AWS Security Groups and GCP VPC Firewall
- Audit all resources accessed during the attack window (S3 buckets, GCP projects)
- Check if any new IAM users or service accounts were created and remove them
- Enable AWS CloudTrail + GCP Audit Logs alerting if not already active

---

## Control Failure
| Control | Should Have Caught | Why It Failed |
|---------|-------------------|---------------|
| AWS IAM | Credential abuse | No MFA on programmatic access keys |
| AWS CloudTrail Alerts | Enumeration activity | Alerting not configured on ListRoles/ListBuckets |
| GCP IAM | Service account creation | No approval workflow for new service accounts |

---

## S5 — AZ-500 Hardening ⚠️ THEORETICAL — Hands-on Month 2–3

**D1 — Identity & Access**
- Entra Workload Identities — apply Conditional Access to service principals and managed identities
- PIM — require approval + justification for any privileged role activation in Azure
- RBAC least privilege — no wildcard permissions; scope roles to specific resources only
- Entra Identity Protection — monitor service principal risk, alert on anomalous app sign-ins

**D2 — Secure Networking**
- Azure Firewall — restrict outbound from cloud workloads to known destinations only
- NSG — deny all inbound from public internet to management interfaces
- Private Endpoints — Azure storage, Key Vault, and databases should not be publicly accessible
- Azure VPN/ExpressRoute — cloud-to-cloud connectivity should not traverse public internet

**D3 — Compute, Storage & Key Vault**
- Key Vault — store all cloud credentials here, not in code or environment variables
- Managed Identities — replace access keys with managed identities (no key rotation risk)
- Defender for Storage — detect unusual access patterns on Azure blob storage
- Storage Account — disable public access, enforce private endpoint only

**D4 — Security Operations**
- Defender for Cloud CSPM — enable multi-cloud connectors for AWS and GCP; surface IAM misconfigurations
- Sentinel Analytics Rule — alert on AWS + GCP activity from same IP within same time window
- Azure Monitor — alert on new role assignments or service account creation in cloud environments
- Automation Playbook — auto-disable IAM user when enumeration threshold exceeded (>10 List calls in 5 min)

---

## Closure Criteria
- [ ] AWS IAM user disabled + access keys rotated
- [ ] GCP service account revoked
- [ ] Attacker IP blocked in both cloud environments
- [ ] All resources accessed during attack window audited
- [ ] New accounts/service accounts created by attacker removed
- [ ] CloudTrail + GCP Audit alerting enabled and tested

---

## Lessons Learned
> [Fill after lab]

Failed query: [paste any query that didn't work]  
What I assumed wrong: [fill here]  
Next time I would: [fill here]

---

## Screenshots
| File | What it shows |
|------|---------------|
| [01-aws-enumeration.png] | AWS ListBuckets/ListRoles enumeration calls |
| [02-aws-escalation.png] | AttachRolePolicy or AssumeRole attempt |
| [03-aws-failed-success.png] | Failed vs successful API call ratio |
| [04-gcp-same-ip.png] | Same attacker IP in GCP Audit Logs |
| [05-gcp-persistence.png] | Service account creation in GCP |
| [06-unified-timeline.png] | AWS + GCP combined timeline |
