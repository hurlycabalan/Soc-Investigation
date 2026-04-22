
# Case 003: Phishing Email Investigation

**Analyst:** Hurly Cabalan  
**Date:** April 2026  
**Platform:** Manual Analysis — Email Client, Browser, Microsoft Office  
**Severity:** High  
**Status:** ✅ Complete

---

## Summary

A simulated phishing email was received targeting a corporate user. Manual analysis confirmed the email was fraudulent — the sender domain was typosquatted, the embedded link pointed to a credential harvesting page, and the attachment contained a macro-based payload. SPF validation failed and DMARC had no enforcement policy, explaining why the email bypassed spam filters and reached the inbox.

---

## Step 1: Initial Email Review

The email arrived with subject line **"Immediate Action Required: Verify Your Account Now"** — engineered urgency to pressure the recipient into acting without thinking.

**Sender analysis:**
- Displayed sender: `support@microsofts.com`
- Legitimate Microsoft domain: `microsoft.com`
- Difference: extra **"s"** added — classic typosquatting
- `microsofts.com` has no affiliation with Microsoft Corporation

![Phishing Email Screenshot](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Email_Screenshot.jpg)

---

## Step 2: Link Inspection

Hovered over the link without clicking. Status bar revealed: `http://verify-account.com`

**Red flags:**
- No relation to Microsoft
- HTTP only — no SSL
- Likely a credential harvesting page

![Hover Link Analysis](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Hoover_Link.jpg)

---

## Step 3: Email Header & Authentication Analysis

Pulled the full email headers and checked authentication results manually.

**SPF Result: FAIL**
- The sending server IP is not listed as an authorized sender for `microsofts.com`
- Confirms the email did not originate from any server legitimately associated with that domain

**DMARC Result: None**
- The domain owner has set no DMARC enforcement policy
- Even though SPF failed, no action is triggered — email passes delivery and lands in inbox
- This is a known weakness exploited by attackers using lookalike domains

> Key distinction: DMARC "None" is not the same as DMARC "Pass." None means no enforcement regardless of SPF/DKIM result.

---

## Step 4: Attachment Analysis — Macro Payload

The email contained attachment: `Account_Review_with_Macro.docx`

Upon opening, Microsoft Word displayed a security warning prompting the user to enable macros to "view the document properly." The malicious code only executes if the user clicks Enable.

**What enabling macros would trigger:**
- Macro executes automatically on document open
- Payload could include a reverse shell, credential stealer, ransomware dropper, or C2 beacon
- No antivirus detection at document open stage — only triggers post-execution

![Macro Warning](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Macro_Warning.jpg)

---

## Step 5: Download Security Warning

When the attachment was downloaded, the OS flagged the file as potentially unsafe. This automated defense is insufficient on its own — users routinely override it, especially when the email appears to come from a trusted brand.

![Message Warning](https://github.com/hurlycabalan/Soc-Investigation/raw/main/images/phishing/Message_Warning.png)

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

## Decision & Response

**Verdict: Confirmed Phishing**

- Email quarantined and removed from user inbox
- Sender domain `microsofts.com` added to email gateway blocklist
- URL `http://verify-account.com` added to web filter blocklist
- User notified — advised not to open attachment or click any links
- No evidence user clicked the link or enabled macros — no further compromise

---

## Problems Encountered

- **DMARC misread:** Initially confused "DMARC: None" with "DMARC: Pass." They are completely different. None means no policy is set — authentication failure has no consequence. Had to re-read the header output carefully to confirm.
- **Hover URL on webmail:** The webmail client did not display hover URLs in the status bar. Had to switch to desktop email client to confirm the actual destination URL. Lesson: always verify links in a desktop client or inspect raw HTML.
- **Macro warning context:** The macro warning alone is not a finding — it appears for any macro-enabled document, legitimate or not. The finding is the combination of macro document + unsolicited email + typosquatted sender. Context matters.

---

## Lessons Learned

- Typosquatting works because the difference is subtle — `microsofts.com` vs `microsoft.com` is easy to miss, especially on mobile
- DMARC enforcement gaps are a real organizational risk — domains without DMARC policies are routinely abused for impersonation
- Macro-based payloads remain effective because they rely on user action, not software exploits — user awareness training is a critical control
- No single control is enough: SPF failed, DMARC had no enforcement, OS warning appeared — defense in depth is the only reliable protection

---

*Part of the [SOC Investigation Lab](./README.md) — manual threat analysis using Active Directory and Microsoft Entra ID.*
