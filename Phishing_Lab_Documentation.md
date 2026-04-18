# Case 003: Phishing Email Investigation

**Analyst:** Hurly Cabalan  
**Date:** April 2026  
**Platform:** Manual Analysis — Email Client, Browser, Microsoft Office  
**Severity:** High  
**Status:** ✅ Complete  

---

## Summary

A simulated phishing email was received targeting a corporate user. Manual analysis confirmed the email was fraudulent — the sender domain was typosquatted, the embedded link pointed to a credential harvesting page, and the attachment contained a macro-based payload. SPF validation failed and DMARC had no enforcement policy, explaining why the email bypassed spam filters and reached the inbox. Email was blocked, sender domain blacklisted, and URL added to web filter.

---

## Step 1: Initial Email Review

### Findings

The email arrived with the subject line **"Immediate Action Required: Verify Your Account Now"** — engineered urgency designed to pressure the recipient into acting without thinking. This is one of the most common social engineering triggers in phishing campaigns.

**Sender analysis:**
- Displayed sender: `support@microsofts.com`
- Legitimate Microsoft domain: `microsoft.com`
- Difference: extra **"s"** added — classic typosquatting
- Domain `microsofts.com` has no affiliation with Microsoft Corporation

**Body content:**
- Instructs recipient to click a link to verify their account immediately
- No personalization — generic greeting, no account number reference
- Tone designed to create fear of account suspension

### Screenshot — Phishing Email

[![Phishing Email Screenshot](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Email_Screenshot.jpg)](images/phishing/images/phishing/images/Email_Screenshot.jpg)

---

## Step 2: Link Inspection

### Findings

Hovered over the **"Click here to verify your account"** button without clicking. The status bar revealed the actual destination URL: `http://verify-account.com`

**Red flags identified:**
- Domain has zero relation to Microsoft — not a subdomain, not a redirect, completely unrelated
- HTTP only — no SSL certificate, meaning any credentials entered would be transmitted in plaintext
- Generic domain name designed to appear legitimate at a glance
- Likely a credential harvesting page built to mimic Microsoft login portal

### Screenshot — Hovered Link Revealing Fake URL

[![Hover Link Analysis](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Hoover_Link.jpg)](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Hoover_Link.jpg)

---

## Step 3: Email Header & Authentication Analysis

### SPF Check

Pulled the full email headers and extracted the sending server IP. Checked SPF record for `microsofts.com`:

- **SPF Result: FAIL** — the server that sent this email is not listed as an authorized sender for `microsofts.com`
- This confirms the email did not originate from a legitimate server associated with that domain

### DMARC Check

- **DMARC Policy: None** — the domain owner has set no enforcement policy
- This means even though SPF failed, DMARC does not instruct mail servers to reject or quarantine the message
- Result: email passed through delivery filters and landed in the inbox despite being fraudulent
- This is a known exploitation of domains with weak or missing DMARC configuration

**Key distinction:** DMARC "None" is not the same as DMARC "Pass." None means no action is taken regardless of authentication result.

---

## Step 4: Attachment Analysis — Macro Payload

### Findings

The email contained an attachment: `Account_Review_with_Macro.docx`

Upon opening the file, Microsoft Word immediately displayed a **security warning** prompting the user to enable macros to "view the document content properly." This is a standard macro-based payload delivery technique — the actual malicious code is embedded in the macro and only executes if the user clicks Enable.

**What would happen if macros were enabled:**
- Macro executes automatically on document open
- Payload could include a reverse shell, credential stealer, ransomware dropper, or C2 beacon depending on attacker objective
- No antivirus detection at document open stage — only triggers post-macro execution

### Screenshot — Macro Warning on Attachment Open

[![Macro Warning](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Macro_Warning.jpg)](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Macro_Warning.jpg)

---

## Step 5: Download Security Warning

### Findings

When the attachment was downloaded from the email client, the browser and OS flagged the file as potentially unsafe before it even opened. This is an automated OS-level defense. However this warning alone is insufficient protection — users routinely override it, especially when the email appears to come from a trusted brand like Microsoft.

### Screenshot — Security Warning on Download

[![Message Warning](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Message_Warning.png)](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Message_Warning.png)

---

## IOC Summary

| Indicator | Type | Detail |
|-----------|------|--------|
| `support@microsofts.com` | Sender Domain | Typosquatted Microsoft domain — extra "s" |
| `http://verify-account.com` | Malicious URL | Credential harvesting page, no SSL |
| `Account_Review_with_Macro.docx` | Malicious Attachment | Macro-based payload delivery |
| SPF FAIL | Email Auth Failure | Sending server not authorized for domain |
| DMARC None | Missing Control | No enforcement — email bypassed filters |

---

## Phase 6: Decision & Response

**Verdict: Confirmed Phishing**

- Email quarantined and removed from user inbox
- Sender domain `microsofts.com` added to email gateway blocklist
- URL `http://verify-account.com` submitted to web filter for blocking
- User notified — advised not to open attachment or click any links
- Attachment hash submitted for sandboxed analysis
- No evidence user clicked the link or enabled macros — no further compromise

---

## Problems Encountered

- **DMARC misread:** Initially confused "DMARC: None" with "DMARC: Pass." They are completely different. None means no policy is set — authentication failure has no consequence. Spent time re-reading the header output carefully to confirm this.
- **Hover URL on webmail:** The webmail client did not display hover URLs clearly in the status bar. Had to switch to a desktop email client to confirm the actual destination URL. Lesson: always verify links in a desktop client or by inspecting raw HTML.
- **Macro warning alone is not a finding:** The macro warning is expected behavior for any document with macros — legitimate or malicious. The finding is the combination of macro-enabled document + unsolicited email + fake sender domain. Context is everything.

---

## Lessons Learned

- Typosquatting is effective precisely because the difference is subtle — `microsofts.com` vs `microsoft.com` is easy to miss at a glance, especially on mobile
- DMARC enforcement gaps are a real organizational risk — domains without DMARC policies are routinely abused for impersonation campaigns
- Macro-based payloads remain effective because they rely on user action, not software vulnerabilities — user awareness training is a critical control layer
- Defense in depth matters: SPF failed, DMARC had no enforcement, OS warning appeared — any one of these controls alone is insufficient. Multiple layers working together is the goal

---

*Part of the [SOC Investigation Lab](./README.md) — manual threat analysis using Active Directory and Microsoft Entra ID.*
