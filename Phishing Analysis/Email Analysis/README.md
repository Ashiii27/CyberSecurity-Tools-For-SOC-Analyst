<div align="center">

# 📧 Email Analysis Guide
### Phishing Investigation for SOC Analysts & Incident Responders

![Category](https://img.shields.io/badge/category-Blue%20Team-0d6efd?style=flat-square)
![Type](https://img.shields.io/badge/type-SOC%20%7C%20IR-20c997?style=flat-square)
![Difficulty](https://img.shields.io/badge/level-Intermediate-f0ad4e?style=flat-square)
![Last Updated](https://img.shields.io/badge/updated-May%202026-6f42c1?style=flat-square)

*A hands-on technical reference covering the full phishing analysis lifecycle — from header inspection to IOC reporting.*

</div>

---

## 📑 Table of Contents

1. [Introduction](#1-introduction)
2. [Understanding Email Architecture](#2-understanding-email-architecture)
3. [Analyzing Email Headers](#3-analyzing-email-headers)
4. [Verifying Authentication Records](#4-verifying-authentication-records)
5. [Investigating the Sender](#5-investigating-the-sender)
6. [Analyzing URLs and Links](#6-analyzing-urls-and-links)
7. [Analyzing Attachments](#7-analyzing-attachments)
8. [Identifying Social Engineering Tactics](#8-identifying-social-engineering-tactics)
9. [Tools Reference](#9-tools-reference)
10. [Analysis Workflow Checklists](#10-analysis-workflow-checklists)
11. [Sample Report Template](#11-sample-report-template)

---

## 1. Introduction

Email remains the **#1 delivery mechanism** for phishing, malware, and business email compromise (BEC). Effective analysis requires understanding how email works under the hood — headers, authentication records, routing paths, and attacker evasion techniques.

This guide covers the full analysis lifecycle: from receiving a suspicious email report to documenting findings and taking remediation actions.

### Prerequisites

- Basic understanding of TCP/IP networking
- Familiarity with DNS record types (MX, TXT, A, CNAME)
- Access to at least one email analysis tool (free options listed in [Section 9](#9-tools-reference))
- A safe, isolated environment for analyzing attachments and links

### Golden Rules

> [!CAUTION]
> **Never** open suspicious attachments on your primary workstation.
> **Never** click suspicious links without using a sandboxed browser or analysis tool.
> **Always** preserve the original email (raw `.eml` or `.msg`) before analysis.

---

## 2. Understanding Email Architecture

### The Email Delivery Path

```
[Sender MUA] → [Sender MTA] → [Intermediate MTAs] → [Recipient MTA] → [Recipient MDA] → [Recipient MUA]
```

| Term | Full Name | Example |
|------|-----------|---------|
| **MUA** | Mail User Agent | Outlook, Gmail, Thunderbird |
| **MTA** | Mail Transfer Agent | Postfix, Exchange, SendGrid |
| **MDA** | Mail Delivery Agent | Delivers to the user's mailbox |

Each MTA **prepends** a `Received:` header — creating a chronological audit trail you can trace.

### Key Header Fields

| Header | Description |
|--------|-------------|
| `From:` | Display name and address shown to recipient — **easily forged** |
| `Reply-To:` | Where replies are directed — often differs from `From:` in phishing |
| `Return-Path:` | Envelope sender; where bounces go |
| `Message-ID:` | Unique ID assigned by the originating MTA |
| `Date:` | Timestamp when sent — can be forged |
| `Received:` | Added by each MTA — **hardest to forge** |
| `X-Originating-IP:` | Often added by webmail services — reveals actual sender IP |
| `X-Mailer:` / `User-Agent:` | Email client or sending software |
| `MIME-Version:` | Indicates MIME encoding; multipart = attachments/HTML |
| `Content-Type:` | Describes the format of body and attachments |

### Envelope vs. Header Sender

> [!IMPORTANT]
> This distinction is critical for understanding spoofing.

- **Envelope sender** (`MAIL FROM` → visible in `Return-Path:`) — used for delivery and bounce handling
- **Header sender** (`From:` header) — displayed to the user in their email client

Attackers set a **legitimate envelope sender** to pass SPF checks, while using a **spoofed `From:`** that appears to be a trusted organization.

---

## 3. Analyzing Email Headers

### Extracting Raw Headers

| Client | Method |
|--------|--------|
| Gmail | Open email → ⋮ menu → **Show original** |
| Outlook Web | Open email → ⋮ menu → **View message source** |
| Outlook Desktop | File → Properties → **Internet headers** |
| Apple Mail | View → Message → **All Headers** |
| Thunderbird | View → Headers → **All** |

### Reading the Received Chain

`Received:` headers are added **bottom-up** — the oldest hop is at the **bottom**, the most recent is at the **top**.

```
Received: from mail.example.com (mail.example.com [203.0.113.42])
        by mx.recipient.com with ESMTPS id abc123
        for <victim@recipient.com>; Mon, 10 May 2026 09:14:22 +0000

Received: from webmail.attacker.net ([45.33.22.11])
        by mail.example.com with ESMTP id xyz789
        for <victim@recipient.com>; Mon, 10 May 2026 09:14:18 +0000
```

**Reading this:**
1. Email originated from `45.33.22.11` (attacker) — bottom `Received:` header
2. Relayed through `mail.example.com` — possibly a compromised relay
3. Delivered by `mx.recipient.com` — top `Received:` header

### Red Flags in the Received Chain

- **Time discrepancies** — large gaps between hops (manipulation or delayed sending)
- **Mismatched hostnames** — PTR of an IP doesn't match the claimed hostname
- **Unexpected geographic routing** — US bank email routed through Eastern Europe
- **Private IPs in external hops** — `10.x.x.x` or `192.168.x.x` = header forgery
- **Single hop from unknown IP** — legitimate org email passes through known infrastructure

### Checking X-Originating-IP

Some providers (Yahoo, older Gmail) include the **actual sending device's IP**:

```
X-Originating-IP: 45.33.22.11
```

Look up in [VirusTotal](https://virustotal.com), [AbuseIPDB](https://abuseipdb.com), or [Shodan](https://shodan.io) to check:
- Geolocation (matches claimed sender?)
- ASN (residential IP, VPS, or bulletproof host?)
- Previous abuse reports

### Checking the Message-ID

A legitimate `Message-ID` looks like:

```
Message-ID: <unique-string@sending-domain.com>
```

**Suspicious signs:**
- Domain in `Message-ID` doesn't match `From:` domain
- Randomly generated strings not following FQDN format
- Missing `Message-ID` entirely (many phishing tools omit it)

---

## 4. Verifying Authentication Records

Modern email authentication uses three complementary standards. Failing any of them is a strong phishing indicator.

### SPF (Sender Policy Framework)

Specifies which IPs are authorized to send on behalf of a domain.

**Check:** Look for `Authentication-Results:` or `Received-SPF:` headers.

```
Received-SPF: Pass (domain of legitimate.com designates 203.0.113.1 as permitted sender)
Received-SPF: Fail (domain of legit.com does not designate 45.33.22.11 as permitted sender)
```

| Result | Meaning |
|--------|---------|
| `pass` | Sending IP is authorized |
| `fail` | Sending IP is **NOT** authorized — strong phishing indicator |
| `softfail` | Probably not authorized (`~all` policy) |
| `neutral` | Domain has no policy stance |
| `none` | No SPF record found |
| `temperror` | Temporary DNS error |
| `permerror` | Permanent SPF misconfiguration |

**Manual lookup:**
```bash
dig TXT example.com +short | grep spf
```

**Example SPF record:**
```
v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 -all
```

> [!NOTE]
> `-all` = strict (reject all unlisted senders). `~all` = softfail. `+all` = dangerous (allows anyone).

---

### DKIM (DomainKeys Identified Mail)

Digitally signs the email with a private key; recipient verifies using a DNS-published public key.

**Check:** Look for `DKIM-Signature:` and `Authentication-Results:`.

```
Authentication-Results: mx.recipient.com;
       dkim=pass header.i=@legitimate.com header.s=selector1 header.b=AbCdEf12
```

| Result | Meaning |
|--------|---------|
| `pass` | Signature valid — email not modified in transit |
| `fail` | Signature invalid — tampered with, or key mismatch |
| `none` | No DKIM signature present |
| `permerror` | Misconfigured record |
| `temperror` | Temporary DNS failure |

**Manual key lookup** (using `s=` selector and `d=` domain from the `DKIM-Signature:` header):
```bash
dig TXT selector1._domainkey.example.com +short
```

---

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

Ties SPF and DKIM together and specifies what to do on failure.

**Check:** Look for `dmarc=` in `Authentication-Results:`.

```
Authentication-Results: mx.recipient.com;
       dmarc=pass (p=REJECT) header.from=legitimate.com
```

**Manual lookup:**
```bash
dig TXT _dmarc.example.com +short
```

**Example record:**
```
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; pct=100
```

| Policy (`p=`) | Action on Failure |
|---|---|
| `none` | No action — monitoring only |
| `quarantine` | Move to spam/junk |
| `reject` | Reject outright |

> [!WARNING]
> A domain with `p=none` provides **zero protection** against spoofing. Attackers frequently target organizations with weak DMARC policies.

---

### Authentication Quick-Reference

| Scenario | SPF | DKIM | DMARC | Verdict |
|----------|-----|------|-------|---------|
| Legitimate email | pass | pass | pass | ✅ Likely legitimate |
| Compromised account | pass | pass | pass | ⚠️ Could still be phishing |
| Display name spoofing | pass | pass | fail | 🚨 Likely phishing |
| Domain spoofing | fail | none | fail | 🚨 Almost certainly phishing |
| Email forwarding | fail | pass | pass | ⚠️ Possibly legitimate (forwarding breaks SPF) |
| Third-party sender | pass | fail | pass | ⚠️ Investigate further |

---

## 5. Investigating the Sender

### Display Name vs. Email Address

Phishers rely on users reading only the display name, not the actual address.

```
From: "PayPal Security" <no-reply@paypa1-secure.net>
```

Check for:
- **Lookalike domains** — `paypa1.com`, `paypal-secure.net`, `paypał.com` (Unicode homograph)
- **Subdomain abuse** — `paypal.attacker.com` (actual domain is `attacker.com`)
- **Free email providers** — `paypal-security@gmail.com`
- **Hyphenated variants** — `pay-pal.com`, `paypal-support.com`

### Domain Age and Registration

Phishing domains are typically registered **days or weeks** before use.

```bash
whois suspicious-domain.com
```

**Red flags:**
- Registered within the past 30 days
- Privacy-protected registrant (Domains by Proxy, WhoisGuard)
- Registrant country doesn't match the impersonated brand

### Reply-To Mismatch

```
From: ceo@legitimate-company.com
Reply-To: ceo-urgent@gmail.com
```

A `Reply-To` differing from `From:` is a classic BEC indicator — the attacker receives replies even if the `From:` address is spoofed.

---

## 6. Analyzing URLs and Links

> [!CAUTION]
> **Never** click links directly. Always extract from raw source first.

### Extracting URLs Safely

1. View raw email source (Section 3)
2. Search for `http://` and `https://` patterns
3. Check HTML anchor tags: `<a href="...">`
4. Decode URL encoding: `%40` = `@`, `%2F` = `/`, `%3A` = `:`

### URL Deobfuscation Techniques

<details>
<summary><strong>URL shorteners</strong></summary>

```
https://bit.ly/3xAbCdE → actually points to malicious site
```
Expand using: https://checkshorturl.com or:
```bash
curl -I https://bit.ly/3xAbCdE
```
</details>

<details>
<summary><strong>Open redirects</strong></summary>

```
https://legitimate-site.com/redirect?url=https://evil.com
```
The link appears trusted but redirects to the attacker's page.
</details>

<details>
<summary><strong>Base64 encoding</strong></summary>

```
aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA== → https://evil.com/phish
```
Decode with:
```bash
echo "aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA==" | base64 -d
```
</details>

<details>
<summary><strong>Homograph / Unicode attacks</strong></summary>

```
https://pаypal.com   ← the 'а' is Cyrillic, not Latin
```
Always inspect the actual Unicode characters in suspicious domains.
</details>

<details>
<summary><strong>Raw IP address URLs</strong></summary>

```
http://45.33.22.11/login
```
Legitimate organizations rarely use raw IPs in email links.
</details>

### Safe URL Analysis Tools

| Tool | Use |
|------|-----|
| [VirusTotal](https://virustotal.com) | Reputation check |
| [URLScan.io](https://urlscan.io) | Screenshot + full network trace |
| [Any.run](https://any.run) | Interactive sandbox |
| [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) | Quick reputation check |

---

## 7. Analyzing Attachments

> [!CAUTION]
> Always analyze in an **isolated VM or online sandbox**. Never open on your primary system.

### Before Opening Anything

1. Note the file type (check extension **and** magic bytes — they may differ)
2. Calculate file hashes
3. Submit to an online sandbox first

```bash
# Linux / macOS
sha256sum suspicious_attachment.pdf

# Windows PowerShell
Get-FileHash suspicious_attachment.pdf -Algorithm SHA256
```

Search hashes in [VirusTotal](https://virustotal.com) or [Hybrid Analysis](https://hybrid-analysis.com).

### Common Malicious Attachment Types

| File Type | Common Threats | Analysis Tool |
|-----------|---------------|---------------|
| `.docx` / `.doc` | Malicious macros, template injection | `olevba` |
| `.xlsm` / `.xls` | Macro-enabled spreadsheets, XLM macros | `xlmdeobfuscator` |
| `.pdf` | Embedded JS, launch actions | PDFiD, pdf-parser |
| `.html` / `.htm` | Credential harvesters, HTML smuggling | Browser sandbox |
| `.zip` / `.rar` | Packed malware, password-protected payloads | Extract and analyze |
| `.iso` / `.img` | Bypasses Mark-of-the-Web; contains LNK or EXE | Mount and analyze |
| `.lnk` | PowerShell/cmd execution | lnkparse, LECmd |
| `.js` / `.vbs` | Dropper scripts | Any.run, manual review |
| `.exe` / `.dll` | Direct malware | Sandbox, Ghidra, x64dbg |

### Analyzing Office Documents (OLETools)

```bash
pip install oletools

mraptor suspicious.docx        # High-level suspicious indicator check
olevba suspicious.docx         # Extract VBA macro code
oleid suspicious.docx          # Check for OLE objects
oledump.py suspicious.docx     # Analyze all streams
```

**Dangerous VBA functions to look for:**

```vba
Shell()           ' Executes system commands
CreateObject()    ' Creates COM objects (often WScript.Shell)
AutoOpen()        ' Runs on document open (Word)
Workbook_Open()   ' Runs on document open (Excel)
Chr()             ' Character encoding — used to obfuscate strings
Environ()         ' Accesses environment variables
```

### Analyzing PDFs

```bash
# Quick overview
python pdfid.py suspicious.pdf

# Extract JavaScript
python pdf-parser.py -s JavaScript suspicious.pdf

# Analyze all streams
python pdf-parser.py -a suspicious.pdf
```

**Suspicious PDF flags:**

| Flag | Meaning |
|------|---------|
| `/JS` or `/JavaScript` | Contains JavaScript |
| `/AA` | Additional Actions (auto-triggers) |
| `/OpenAction` | Runs automatically on open |
| `/Launch` | Can launch applications |
| `/EmbeddedFile` | Contains embedded files |
| `/URI` | Contains URLs |

### HTML Attachment Analysis

HTML attachments can host complete phishing pages locally — bypassing URL filters entirely.

```bash
# Look for these patterns in HTML source:
grep -i "atob\|fromCharCode\|eval\|unescape" suspicious.html
```

---

## 8. Identifying Social Engineering Tactics

### Common Psychological Triggers

| Tactic | Example | Look For |
|--------|---------|----------|
| **Urgency** | "Your account will be suspended in 24 hours" | Time pressure, countdowns |
| **Fear** | "Unauthorized access detected" | Alarm language, security alerts |
| **Authority** | Impersonation of CEO, IT, IRS | Executive names, official logos |
| **Scarcity** | "Only 2 spots remaining" | Limited time/quantity claims |
| **Social proof** | "Your colleagues have already verified" | Peer pressure language |
| **Curiosity** | "You have a pending document" | Vague, enticing subject lines |
| **Reciprocity** | "You've been selected for a reward" | Gift cards, prizes, refunds |

### Subject Line Red Flags

```
"Urgent: Action Required"
"Your account has been compromised"
"Invoice #[number] attached"
"Shared document: [believable filename]"
"RE: [meeting or project name]"          ← reply-chain spoofing
"[Your company name] IT Security Alert"
"You have a new voicemail"
```

### BEC (Business Email Compromise) Indicators

- Spoofed or look-alike executive email address
- Request to change vendor banking/payment details
- Urgent wire transfer outside normal approval workflows
- *"Confidential — don't tell anyone else about this"*
- Company executive using a free email provider
- Gift card requests (common in lower-value BEC scams)

---

## 9. Tools Reference

<details>
<summary><strong>Free / Open Source Tools</strong></summary>

| Tool | Purpose | Link |
|------|---------|------|
| MXToolbox | Header analysis, DNS checks, blacklist | https://mxtoolbox.com |
| Google Messageheader | Header parsing and visualization | https://toolbox.googleapps.com/apps/messageheader/ |
| URLScan.io | Safe URL scanning + screenshot | https://urlscan.io |
| VirusTotal | File and URL reputation | https://virustotal.com |
| Any.run | Interactive sandbox | https://any.run |
| Hybrid Analysis | Behavioral analysis | https://hybrid-analysis.com |
| PhishTank | Known phishing URL database | https://phishtank.com |
| AbuseIPDB | IP reputation | https://abuseipdb.com |
| Shodan | Infrastructure intelligence | https://shodan.io |
| AlienVault OTX | Threat intelligence | https://otx.alienvault.com |
| DNSDumpster | DNS reconnaissance | https://dnsdumpster.com |
| OLETools | Office document analysis | `pip install oletools` |
| PDFiD / pdf-parser | PDF analysis | https://blog.didierstevens.com |

</details>

<details>
<summary><strong>Commercial / Enterprise Tools</strong></summary>

| Tool | Purpose | Link |
|------|---------|------|
| PhishTool | End-to-end phishing triage | https://phishtool.com |
| DomainTools | Domain/IP intelligence | https://domaintools.com |
| Cofense Triage | Phishing incident management | https://cofense.com |
| Proofpoint | Email security + TAP | https://proofpoint.com |
| Joe Sandbox | Deep malware analysis | https://joesandbox.com |
| MISP | Threat intel sharing | https://misp-project.org |

</details>

### Command-Line Quick Reference

```bash
# DMARC record
dig TXT _dmarc.example.com +short

# SPF record
dig TXT example.com +short | grep spf

# DKIM public key
dig TXT selector1._domainkey.example.com +short

# MX records
dig MX example.com +short

# WHOIS
whois suspicious-domain.com
whois 45.33.22.11

# File hashing
sha256sum malicious.pdf

# Base64 decode
echo "aHR0cHM6Ly9ldmlsLmNvbQ==" | base64 -d

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('https%3A%2F%2Fevil.com'))"

# PDF analysis
python pdfid.py suspicious.pdf
python pdf-parser.py -s JavaScript suspicious.pdf

# Office document analysis
olevba suspicious.docx
oleid suspicious.docx
mraptor suspicious.docx
```

---

## 10. Analysis Workflow Checklists

<details>
<summary><strong>⚡ Quick Triage Checklist (5 minutes)</strong></summary>

```
[ ] Extract raw email headers
[ ] Check SPF, DKIM, DMARC in Authentication-Results
[ ] Verify From: domain matches Received: chain
[ ] Check if Reply-To: differs from From:
[ ] Note suspicious subject line patterns
[ ] Identify links — do they match the sender's domain?
[ ] Note any attachments and file types
[ ] Check sender domain age (WHOIS)
[ ] Check sender IP in AbuseIPDB or VirusTotal
```

</details>

<details>
<summary><strong>🔍 Deep Investigation Checklist (30–60 minutes)</strong></summary>

**Headers**
```
[ ] Trace full Received: chain bottom to top
[ ] Identify originating IP and geolocate
[ ] Check IP reputation (VirusTotal, AbuseIPDB, Shodan)
[ ] Verify Message-ID domain matches From: domain
[ ] Check for X-Originating-IP header
[ ] Look for forged timestamps or private IPs in external hops
```

**Authentication**
```
[ ] Document SPF result; check record manually (dig TXT)
[ ] Document DKIM result; verify selector key exists
[ ] Document DMARC result and policy (p=none/quarantine/reject)
[ ] Verify RFC5322.From aligns with SPF/DKIM domain for DMARC pass
```

**Sender Investigation**
```
[ ] Check domain registration date (WHOIS)
[ ] Check domain reputation (VirusTotal, Cisco Talos)
[ ] Verify sender IP is authorized by SPF record
[ ] Check domain in OpenPhish / PhishTank
[ ] Search related infrastructure (PassiveTotal, RiskIQ)
```

**URL Analysis**
```
[ ] Extract all URLs from raw email source
[ ] Expand any URL shorteners
[ ] Scan each URL in VirusTotal
[ ] Screenshot each URL in URLScan.io
[ ] Check SSL certificate details
[ ] Identify if page is a credential harvester
[ ] Check for redirects and final landing page
```

**Attachment Analysis**
```
[ ] Calculate SHA256 of each attachment
[ ] Search hash in VirusTotal / Hybrid Analysis
[ ] Identify true file type (magic bytes vs. extension)
[ ] Submit to Any.run or Cuckoo for behavioral analysis
[ ] If Office doc: run olevba to extract macros
[ ] If PDF: run pdfid.py and pdf-parser.py
[ ] Document any C2 comms or dropped files
```

**Impact Assessment**
```
[ ] Identify how many users received the email
[ ] Determine if any users clicked links
[ ] Determine if any users opened attachments
[ ] Check email gateway logs for similar campaigns
[ ] Identify any credential submissions or data exfil
```

</details>

<details>
<summary><strong>🛡️ Response Actions Checklist</strong></summary>

```
[ ] Preserve original email (.eml / .msg)
[ ] Block sender IP at email gateway
[ ] Block sender domain at gateway and DNS
[ ] Block malicious URLs at web proxy / DNS filter
[ ] Submit URLs to Google Safe Browsing / Microsoft SSCS
[ ] Submit URLs to PhishTank / OpenPhish
[ ] Add IOCs (domains, IPs, hashes, URLs) to SIEM
[ ] Recall / delete email from all user mailboxes
[ ] Notify affected users; instruct password reset if they clicked
[ ] Escalate to IR if credential compromise is suspected
[ ] Document findings in ticketing system
[ ] Share IOCs with threat intel community (MISP, OTX)
```

</details>

---

## 11. Sample Report Template

<details>
<summary><strong>📋 Click to expand full report template</strong></summary>

```
============================================================
PHISHING EMAIL ANALYSIS REPORT
============================================================
Date of Analysis:     [YYYY-MM-DD]
Analyst:              [Name / Handle]
Ticket/Case ID:       [ID]
Severity:             [Low / Medium / High / Critical]

------------------------------------------------------------
1. EMAIL SUMMARY
------------------------------------------------------------
Date Received:        [timestamp]
Subject:              [subject line]
From (Display):       [display name]
From (Address):       [actual email address]
Reply-To:             [if different from From:]
Reported By:          [user / automated system]
Recipients Affected:  [number]

------------------------------------------------------------
2. AUTHENTICATION RESULTS
------------------------------------------------------------
SPF:    [ PASS / FAIL / SOFTFAIL / NONE ]  →  [details]
DKIM:   [ PASS / FAIL / NONE ]             →  [details]
DMARC:  [ PASS / FAIL / NONE ]  Policy: [p=?]  →  [details]

------------------------------------------------------------
3. SENDER ANALYSIS
------------------------------------------------------------
Originating IP:       [IP address]
IP Geolocation:       [country / city / ASN]
IP Reputation:        [clean / suspicious / malicious]
Sending Domain:       [domain.com]
Domain Age:           [registration date]
Domain Reputation:    [clean / suspicious / malicious]
Infrastructure Notes: [related IPs, domains, hosting info]

------------------------------------------------------------
4. URL ANALYSIS
------------------------------------------------------------
URL 1:  [full URL]
  Reputation:         [VirusTotal result]
  Screenshot:         [URLScan.io link]
  Landing Page:       [description]
  SSL Cert:           [issuer, validity, subject]

------------------------------------------------------------
5. ATTACHMENT ANALYSIS
------------------------------------------------------------
File Name:            [filename.ext]
File Type:            [true file type]
MD5:                  [hash]
SHA256:               [hash]
VirusTotal:           [X/XX detections]
Sandbox Result:       [behavior summary]
Macros/Scripts:       [yes/no — summary if yes]
Dropped Files:        [list if any]
C2 Contacted:         [list if any]

------------------------------------------------------------
6. SOCIAL ENGINEERING TACTICS
------------------------------------------------------------
Primary Tactic:       [urgency / fear / authority / etc.]
Impersonated Brand:   [brand/organization name]
Target of Attack:     [credentials / wire transfer / malware]
Notes:                [other observations]

------------------------------------------------------------
7. INDICATORS OF COMPROMISE (IOCs)
------------------------------------------------------------
IPs:
  - 45.33.22.11

Domains:
  - suspicious-domain.com

URLs:
  - https://suspicious-domain.com/login

File Hashes (SHA256):
  - abc123... (malicious.docx)

Email Addresses:
  - attacker@gmail.com

------------------------------------------------------------
8. VERDICT
------------------------------------------------------------
Classification:   [PHISHING / MALWARE / BEC / SPAM / LEGITIMATE]
Confidence:       [Low / Medium / High]
Summary:          [2-3 sentence summary of findings]

------------------------------------------------------------
9. RESPONSE ACTIONS TAKEN
------------------------------------------------------------
[ ] Email recalled from mailboxes
[ ] Sender domain blocked at gateway
[ ] Malicious URLs blocked at proxy/DNS
[ ] Affected users notified
[ ] IOCs added to SIEM
[ ] Ticket escalated to: [IR team / management]
[ ] IOCs shared with threat intel community

------------------------------------------------------------
10. REFERENCES
------------------------------------------------------------
[List relevant threat reports, CVEs, or related campaigns]
============================================================
```

</details>

---

## Additional Resources

| Resource | Link |
|----------|------|
| RFC 5321 – SMTP | https://tools.ietf.org/html/rfc5321 |
| RFC 7208 – SPF | https://tools.ietf.org/html/rfc7208 |
| RFC 6376 – DKIM | https://tools.ietf.org/html/rfc6376 |
| RFC 7489 – DMARC | https://tools.ietf.org/html/rfc7489 |
| MITRE ATT&CK – Phishing (T1566) | https://attack.mitre.org/techniques/T1566/ |
| Didier Stevens Blog (PDF/Office tools) | https://blog.didierstevens.com |
| OLETools | https://github.com/decalage2/oletools |
| Google Messageheader | https://toolbox.googleapps.com/apps/messageheader/ |

---

<div align="center">

*Version 1.0 — May 2026*

</div>
