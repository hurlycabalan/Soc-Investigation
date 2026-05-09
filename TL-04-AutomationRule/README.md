# TL-04: Automation Rule & Playbook Troubleshooting

**Date:** May 9, 2026  
**Exercise:** Ex04 — Automation Rule Trigger Failure  
**Status:** Complete ✅

## Root Cause
Automation rule `E04_AutomationRule` was not triggering because conditions 
filtered on `Alert product names = Microsoft Defender for Office 365`. 
Training lab incidents use `alertProductNames: Azure Sentinel` — mismatch confirmed 
via Logic App JSON output.

## Fix Applied
Removed all conditions from automation rule. Playbook confirmed functional 
via manual trigger → Succeeded (5/9/2026 08:50 AM).

## Evidence
Screenshots in `/screenshots` folder.
