## Screenshot 1: Phishing Email Content
![Phishing Email Screenshot](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Email_Screenshot.jpg?raw=true)

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
![Macro Warning Screenshot](https://github.com/hurlycabalan/Soc-Investigation/blob/main/images/phishing/Macro_Warning.jpg?raw=true)

**Description**:
- **Attachment**: The email contains an attachment titled `Account_Review_with_Macro.docx`, which is a common tactic used to distribute malicious payloads.
- **Macro Warning**: When opening the attachment, a **macro warning** appears, urging the user to enable macros. Enabling macros would trigger malicious behavior, potentially compromising the system.
