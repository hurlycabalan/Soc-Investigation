# Phishing Investigation Report

## Overview
This document provides an overview of the phishing email investigation conducted to identify suspicious email behavior and actions. The investigation covers indicators such as email sender, subject line, attachment, and links.

## Screenshot 1: Phishing Email Content
![Phishing Email Screenshot](images/phishing/Email_Screenshot.jpg)

**Description**:
- **Subject Line**: "Immediate Action Required: Verify Your Account Now" — This subject line creates a sense of urgency, a common phishing tactic.
- **Sender**: The sender `support@microsofts.com` is a fake email address that mimics the legitimate Microsoft domain.
- **Body Content**: The email urges the recipient to click on a link to verify their account, which is a typical phishing move.

---

## Screenshot 2: Hovered Link Analysis
![Hover Link](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Hoover_Link.jpg?raw=true)

**Description**:
- **Link Inspection**: Upon hovering over the link **"Click here to verify your account"**, it leads to a **fake URL** (`http://verify-account.com`), which is an indication of a phishing attempt.
- **Suspicious Behavior**: The URL does not correspond to the legitimate Microsoft domain and is likely designed to steal credentials.

---

## Screenshot 3: Attachment Macro Warning
![Macro Warning Screenshot](images/phishing/Macro_Warning.jpg)

**Description**:
- **Attachment**: The email contains an attachment titled `Account_Review_with_Macro.docx`, which is a common tactic used to distribute malicious payloads.
- **Macro Warning**: When opening the attachment, a **macro warning** appears, urging the user to enable macros. Enabling macros would trigger malicious behavior, potentially compromising the system.

---

## Additional Warning on File Download
When downloading the attachment, you will likely receive a **security warning** from Microsoft Word about **macros**. This warning indicates that enabling macros could result in malicious behavior, such as executing harmful scripts or downloading additional malware.

**Warning Message**:
- **"Macros have been disabled"** or **"Security warning: Some active content has been disabled"** — This prompt typically appears when opening a file with embedded macros.

**Recommendation**:
- **Do NOT enable macros** from untrusted sources. Always disable macros to prevent malicious code from running on your system.

---

## Email Authentication (SPF/DMARC) – Analysis
While we don't have direct screenshots for **SPF** and **DMARC** results, the analysis of the **email header** could indicate whether the email passed **authentication checks**.

**SPF (Sender Policy Framework)** and **DMARC (Domain-based Message Authentication, Reporting, and Conformance)** are email authentication methods used to detect spoofing and prevent phishing.

1. **SPF Analysis**:
   - The **SPF check** verifies whether the email’s sending server is authorized to send emails for the domain.
   - If **SPF fails**, this indicates that the email may not be coming from a legitimate server, making it more likely to be phishing.

2. **DMARC Analysis**:
   - **DMARC** builds on SPF and DKIM (DomainKeys Identified Mail) to detect and prevent email spoofing.
   - **DMARC failure** in the email headers indicates a potential phishing attempt, as the domain may not be aligned with the legitimate sender’s domain.

### **Conclusion on SPF/DMARC**:
While we don't have direct screenshots of the email's **SPF** or **DMARC** failure, it’s important to **check these results** in the email header for any authentication issues. A failed **SPF/DMARC check** is a strong indicator that the email may be a phishing attempt.

---

## Conclusion and Mitigation Recommendations:
Based on the investigation, the email shows classic phishing tactics, including a fake sender, urgent subject line, suspicious link, and macro-enabled attachment.

### Mitigation Suggestions:
- Enable **SPF** and **DMARC** email filters to prevent spoofed emails.
- **Do not click on suspicious links** or open attachments from untrusted sources.
- **Enable multi-factor authentication (MFA)** to add an additional layer of security.

---
