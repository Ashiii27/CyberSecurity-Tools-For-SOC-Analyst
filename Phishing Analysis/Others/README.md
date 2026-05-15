# 🎣 Phishing Attack Methods — Beyond Email

A comprehensive overview of non-email phishing attack vectors used by threat actors. This README serves as a reference companion to the Email Analysis Guide, covering every major phishing method, how they work, what to look for, and how to defend against them.

---

## Table of Contents

1. [Smishing (SMS Phishing)](#1-smishing-sms-phishing)
2. [Vishing (Voice Phishing)](#2-vishing-voice-phishing)
3. [SEO Poisoning (Search Engine Phishing)](#3-seo-poisoning-search-engine-phishing)
4. [Social Media Phishing](#4-social-media-phishing)
5. [Instant Messaging & Chat Phishing](#5-instant-messaging--chat-phishing)
6. [Quishing (QR Code Phishing)](#6-quishing-qr-code-phishing)
7. [Wi-Fi & Network Phishing](#7-wi-fi--network-phishing)
8. [Website-Based Phishing Techniques](#8-website-based-phishing-techniques)
9. [Spear Phishing Variants](#9-spear-phishing-variants)
10. [Platform-Specific Phishing](#10-platform-specific-phishing)
11. [AI-Powered & Emerging Phishing](#11-ai-powered--emerging-phishing)
12. [Quick Reference — Detection & Defense](#12-quick-reference--detection--defense)

---

## 1. Smishing (SMS Phishing)

### What It Is
Smishing is phishing delivered via SMS text messages. Attackers send fraudulent texts impersonating banks, courier services, government agencies, or mobile carriers to trick victims into clicking malicious links or calling fake numbers.

### How It Works
1. Attacker acquires a bulk SMS service or SIM card
2. Sends mass texts or targeted messages with a spoofed sender ID
3. Message contains urgency (missed delivery, suspicious login, tax refund)
4. Victim clicks a link → lands on credential harvester or downloads malware
5. Or victim calls a number → reaches a vishing agent (see Section 2)

### Common Lures
- "Your package could not be delivered. Reschedule here: [link]"
- "ALERT: Suspicious login to your bank account. Verify now: [link]"
- "You are owed a tax refund of $380. Claim it here: [link]"
- "Your Netflix subscription has expired. Update payment: [link]"
- "[Bank Name]: Your card has been temporarily locked. Tap to unlock: [link]"

### Red Flags
- Unsolicited texts with shortened URLs (bit.ly, tinyurl, t.co)
- Generic greetings not using your name
- Mismatched sender IDs (number doesn't match the brand)
- Urgent or threatening language
- Links that don't match the claimed organization's official domain

### Key Tools for Analysis
| Tool | Purpose |
|------|---------|
| [URLScan.io](https://urlscan.io) | Safely scan SMS links |
| [VirusTotal](https://www.virustotal.com) | Check URL reputation |
| [PhoneScam.info](https://www.phonescam.info) | Check reported scam numbers |
| [7726 (SPAM)](sms:7726) | Forward smishing texts to your carrier |

### Defense
- Never click links in unsolicited texts — go directly to the official website
- Enable SMS filtering on iOS (Settings → Messages → Filter Unknown Senders) and Android
- Register with the Do Not Call registry
- Deploy mobile threat defense (MTD) solutions in enterprise environments
- Report smishing texts by forwarding to **7726** (spells SPAM)

---

## 2. Vishing (Voice Phishing)

### What It Is
Vishing uses phone calls to manipulate victims into revealing credentials, transferring funds, or installing remote access tools. Attackers impersonate tech support agents, bank fraud departments, government officials, or even company executives.

### How It Works
1. Attacker spoofs a legitimate caller ID (bank, IRS, Microsoft, internal company number)
2. Uses social engineering scripts to build trust
3. Creates urgency or fear ("Your account has been hacked", "You owe back taxes")
4. Requests sensitive info, remote access, gift card purchases, or wire transfers
5. May follow up a smishing message to add legitimacy

### Common Scenarios
- **Tech Support Scam** — "Microsoft" calling about a virus on your computer; asks you to install remote access software (AnyDesk, TeamViewer)
- **Bank Fraud Call** — "Fraud department" asking you to verify your full card number, PIN, or OTP
- **IRS/Tax Scam** — Threatening arrest unless you pay back taxes immediately via gift cards or wire transfer
- **CEO/Executive Impersonation** — Calling an employee pretending to be the CEO, requesting urgent wire transfer
- **IT Help Desk Impersonation** — Calling an employee to "reset their password" and capturing the new credentials

### Red Flags
- Caller requests remote access to your device
- Requests payment via gift cards, cryptocurrency, or wire transfer
- Extreme urgency and threats ("You will be arrested if you hang up")
- Caller ID matches a known organization but the request feels unusual
- Requests for OTP/2FA codes over the phone (legitimate organizations never ask for this)
- Heavy accent combined with scripted, robotic responses

### AI Voice Cloning Threat
Modern vishing attacks now use **AI-generated voice clones** of executives or family members. A 3-second audio clip from social media is enough to clone a voice convincingly.

> A CFO received a call that sounded exactly like the CEO, requesting an urgent $25M wire transfer. The voice was AI-generated. This is a documented attack pattern.

### Defense
- Establish a **verbal codeword** for executive wire transfer requests
- Never provide OTPs, PINs, or passwords over the phone — no legitimate organization asks for this
- Hang up and call back on the **official number** from the company's website
- Enable call screening features (Google Call Screen, carrier spam filters)
- Implement callback verification procedures for financial requests
- Train employees on vishing scenarios during security awareness programs

---

## 3. SEO Poisoning (Search Engine Phishing)

### What It Is
Attackers create convincing fake websites and manipulate search engine rankings to place them at the top of results for high-value search terms. Victims believe they are clicking a legitimate result.

### How It Works
1. Attacker registers a lookalike or typosquatted domain
2. Builds a convincing fake website (login page, support page, download page)
3. Uses black-hat SEO techniques to boost rankings:
   - Keyword stuffing
   - Backlink farms
   - Cloaking (shows different content to Googlebot vs. real users)
   - Exploiting trending search terms
4. Victim searches for "PayPal login" or "Adobe Acrobat download" and clicks the top result
5. Victim enters credentials or downloads malware

### Common Targets
- Banking and financial institution login pages
- Software download pages (delivering trojanized installers)
- Government service portals (tax filing, benefits)
- Crypto exchange login pages
- Customer support pages for major brands

### Red Flags
- URL doesn't match the official domain exactly
- Site appears at the top but has a recently registered domain
- Page asks for login credentials on a domain different from the brand
- Download links serve `.exe` or `.msi` files from unofficial domains
- SSL certificate not issued to the expected organization

### Defense
- Bookmark official websites instead of searching each time
- Always verify the URL before entering credentials
- Use browser extensions like **uBlock Origin** or **Malwarebytes Browser Guard**
- Enable Google Safe Browsing in your browser
- Use DNS filtering (Cloudflare 1.1.1.1, Cisco Umbrella) to block malicious domains

---

## 4. Social Media Phishing

### What It Is
Phishing attacks conducted through social media platforms including Facebook, Instagram, Twitter/X, LinkedIn, TikTok, and others. Attackers exploit the trust users place in social connections and brand accounts.

### Types of Social Media Phishing

#### Fake Brand Accounts
Attackers create accounts mimicking official brand profiles with similar usernames, logos, and content. They then send DMs to users who have complained about a service, offering "support."

#### Angler Phishing
A targeted form of social media phishing where attackers monitor social media for customer complaints directed at brands, then respond from a fake support account.

> Customer tweets: "@BankOfAmerica my card is not working!"
> Attacker (fake account): "@user Hi! Sorry for the trouble. Please DM us your card details to verify your account."

#### Fake Giveaways & Contests
Posts or ads offering prizes, gift cards, or exclusive access in exchange for clicking a link, entering personal information, or "logging in to verify eligibility."

#### Malicious DMs
Direct messages containing links to phishing pages, fake login prompts, or malware downloads. Often come from compromised accounts of known contacts.

#### LinkedIn Spear Phishing
Attackers use LinkedIn to research targets, then send highly personalized connection requests and messages impersonating recruiters, colleagues, or vendors.

### Red Flags
- Account has very few followers, recent creation date, or inconsistent posting history
- Unsolicited DM from a brand account asking for personal details
- Giveaway requiring login credentials or payment info
- LinkedIn message offering a job with a suspicious external link
- Message contains urgency ("Your account will be suspended — verify now")

### Defense
- Verify account authenticity (blue checkmark, follower count, join date)
- Never provide personal information via social media DMs
- Report and block fake accounts using the platform's reporting tools
- Enable login alerts and 2FA on all social accounts
- Educate users about angler phishing, especially customer service staff

---

## 5. Instant Messaging & Chat Phishing

### What It Is
Phishing attacks delivered through messaging platforms such as WhatsApp, Telegram, Discord, Slack, and Microsoft Teams. These channels are increasingly trusted by users and have fewer security controls than email.

### Common Attack Patterns

#### WhatsApp & Telegram
- Forwarded messages with fake news or urgent warnings containing malicious links
- Fake crypto investment groups promising high returns
- Impersonation of family members claiming to be in trouble ("Hi Mum, I've lost my phone, can you send money?")
- Fake lottery win notifications

#### Discord
- Malicious bots sending DMs to server members with fake Nitro offers
- Compromised accounts spreading malware via file sharing
- Fake NFT or crypto investment servers with phishing links
- Trojanized game mods or software shared in gaming communities

#### Slack & Microsoft Teams (Enterprise)
- Compromised external accounts messaging internal employees
- Fake IT helpdesk bots requesting credentials or MFA codes
- Malicious file attachments shared in channels
- Impersonation of executives via display name manipulation

### Red Flags
- Unsolicited messages from unknown contacts with links or files
- Unusual requests from known contacts (account may be compromised)
- Bot messages offering free gifts, Nitro, crypto, or investment opportunities
- Requests for MFA codes or passwords via chat
- External Teams/Slack accounts with urgent financial requests

### Defense
- Disable DMs from strangers in Discord and Telegram
- Restrict external communication in Microsoft Teams (allow-listing)
- Enable enterprise DLP (Data Loss Prevention) policies in collaboration tools
- Treat chat-based financial requests with the same scrutiny as email BEC
- Verify unusual requests from colleagues via a second channel (phone call)

---

## 6. Quishing (QR Code Phishing)

### What It Is
Quishing uses malicious QR codes to redirect victims to phishing websites, credential harvesters, or malware download pages. Because most email security tools cannot analyze the URL embedded in a QR code image, it bypasses many filters effectively.

### How It Works
1. Attacker generates a QR code linking to a malicious URL
2. Embeds it in an email, physical flyer, parking meter sticker, restaurant table, or document
3. Victim scans QR code with their phone camera
4. Phone opens the malicious URL in a mobile browser
5. Victim is redirected to a credential harvester or malware download

### Common Delivery Methods
- **Email** — "Scan this QR code to verify your Microsoft account" (bypasses email URL filters)
- **Physical locations** — Fake QR codes placed over legitimate ones at restaurants, parking meters, charging stations
- **Malicious documents** — PDF or Word attachments containing QR codes
- **Social media posts** — QR codes embedded in images advertising fake promotions
- **Package inserts** — QR codes in shipments claiming to offer "exclusive discounts"

### Red Flags
- QR code received via unsolicited email asking you to scan instead of click
- Physical QR code that appears to be a sticker placed over an original
- URL revealed after scanning doesn't match the expected organization
- Immediate request for login credentials after scanning
- Short redirect chains that obscure the final destination

### Defense
- Use a QR scanner app that previews the URL before opening it
- Never scan QR codes from unsolicited emails — type the URL manually instead
- Check physical QR codes for signs of tampering (stickers, poor alignment)
- Deploy email security solutions that can analyze QR code content
- Train users specifically on QR code risks — this is a newer and underappreciated vector

---

## 7. Wi-Fi & Network Phishing

### What It Is
Attackers exploit wireless networks or local network access to intercept traffic, steal credentials, or redirect victims to phishing pages.

### Evil Twin Attack
The most common Wi-Fi phishing technique. An attacker sets up a rogue access point with the same SSID (network name) as a legitimate Wi-Fi network (coffee shop, hotel, airport).

**How it works:**
1. Attacker identifies target network SSID (e.g., "Starbucks_WiFi")
2. Sets up a stronger rogue AP with the same name
3. Devices auto-connect or victims manually connect
4. All traffic passes through the attacker's device
5. Attacker captures credentials via SSL stripping or serves a fake captive portal

### Captive Portal Phishing
Fake Wi-Fi login pages that mimic hotel, airport, or coffee shop portals. Victims enter email addresses and passwords to "authenticate" — which are captured by the attacker.

> Real captive portals never require your email password — only an access code or agreement click.

### ARP Spoofing
On a local network, attacker sends falsified ARP messages to associate their MAC address with the IP address of the gateway, intercepting all network traffic from targeted devices.

### Red Flags
- Two networks with the same or similar name in the same location
- Captive portal asking for email password (not just email address)
- SSL certificate warnings when connecting to familiar sites
- Unusually slow connection despite strong signal
- Requests to install certificates or software to access the network

### Defense
- Always use a **VPN** on public Wi-Fi networks
- Disable auto-connect to open networks on all devices
- Verify the correct network name with staff before connecting
- Use HTTPS-only mode in your browser
- Never enter sensitive credentials on public Wi-Fi without a VPN
- Prefer mobile data over unknown public Wi-Fi for sensitive transactions

---

## 8. Website-Based Phishing Techniques

### Typosquatting
Registering domains that are common misspellings or near-duplicates of legitimate sites.

| Legitimate | Typosquatted |
|------------|-------------|
| google.com | gogle.com, googel.com, g00gle.com |
| paypal.com | paypa1.com, paypall.com, paypa-l.com |
| amazon.com | arnazon.com, amazom.com, amazon.co (wrong TLD) |
| microsoft.com | mircosoft.com, microsofft.com |

### Homograph / IDN Attacks
Using Unicode characters that visually resemble Latin letters to create convincing lookalike domains. The browser may display them identically to the legitimate domain.

```
аpple.com  ← the 'а' is Cyrillic U+0430, not Latin 'a'
pаypal.com ← same trick
```

Detection: Paste the domain into a punycode converter. `аpple.com` becomes `xn--pple-43d.com`.

### Watering Hole Attacks
Rather than attacking the target directly, attackers compromise a legitimate website that the target is known to visit regularly. Any visitor is then exposed to malware or credential harvesting.

**Common targets for watering holes:**
- Industry association websites
- Government contractor portals
- Niche forums and communities
- Supplier or partner websites

### Credential Harvester Pages
Fake login pages that perfectly mimic legitimate services (Microsoft 365, Google Workspace, banking portals). Built using phishing kits — pre-packaged tools that clone entire websites.

Modern phishing kits include:
- Reverse proxy tools (Evilginx2, Modlishka) that bypass MFA by relaying sessions in real-time
- Antibot mechanisms to block security scanners
- Geofencing to only serve phishing content to targeted regions

### Defense
- Use a password manager — it won't autofill on lookalike domains
- Enable browser warnings for dangerous sites (Google Safe Browsing)
- Use DNS filtering (Umbrella, NextDNS, Pi-hole) to block known phishing domains
- Implement FIDO2/hardware security keys — immune to real-time phishing proxies
- Keep browsers and OS patched to prevent drive-by download exploits

---

## 9. Spear Phishing Variants

### Spear Phishing
Unlike mass phishing, spear phishing is **highly targeted**. Attackers research the victim extensively (LinkedIn, social media, company website, previous data breaches) and craft personalized messages.

**Characteristics:**
- References real names, projects, colleagues, or recent events
- Comes from a spoofed address of a known contact
- Tailored lure specific to the target's role or industry
- Much higher success rate than mass phishing

### Whaling
Spear phishing specifically targeting **senior executives** (CEO, CFO, CISO, Board members). The goal is usually financial fraud, credential theft, or access to sensitive corporate data.

> A CFO receives an email appearing to come from the CEO: "I need you to process an urgent wire transfer of $2.3M before end of day — I'm in a meeting and can't be reached by phone."

### Business Email Compromise (BEC)
A sophisticated attack where criminals impersonate executives, vendors, or employees to authorize fraudulent financial transactions. BEC causes billions of dollars in losses annually.

**Common BEC scenarios:**
- **CEO fraud** — Executive impersonation requesting wire transfers
- **Vendor impersonation** — Changing payment bank details for an existing supplier
- **Payroll diversion** — HR/payroll impersonation to change direct deposit details
- **Attorney impersonation** — Fake lawyer claiming a confidential acquisition requires immediate payment
- **Invoice fraud** — Sending fake invoices from lookalike vendor domains

### Clone Phishing
Attacker takes a **legitimate email** the victim has previously received, replaces links or attachments with malicious ones, and resends it — appearing to be a follow-up or re-send of the original.

### Defense Against Spear Phishing & BEC
- Implement **callback verification** for all wire transfer requests (call the requester on a known number)
- Establish a **verbal codeword** for out-of-band financial authorizations
- Use **dual-authorization** for any payment above a threshold
- Enable **DMARC with p=reject** to prevent your domain from being spoofed
- Train executives specifically — they are high-value targets
- Deploy email banners for messages from external senders

---

## 10. Platform-Specific Phishing

### Gaming Platform Phishing
Attackers target gaming accounts (Steam, PlayStation Network, Xbox Live, Epic Games) which may hold significant value in virtual currency, rare items, or stored payment methods.

**Common methods:**
- Fake Steam trade offers with impersonated profiles
- "Free game key" or "free in-game currency" sites requiring login
- Fake CS:GO, Fortnite, or Roblox skin trading sites
- Malicious game mods or cheats bundled with RATs (Remote Access Trojans)

### Cryptocurrency & Web3 Phishing
One of the fastest-growing phishing categories due to the irreversible nature of crypto transactions.

**Common methods:**
- Fake wallet sites (MetaMask, Ledger, Trezor clones)
- **Seed phrase stealers** — sites claiming to "verify" or "restore" your wallet requiring entry of seed phrase
- Malicious NFT smart contracts that drain wallets on approval
- Fake crypto exchange login pages
- Airdrop scams requiring wallet connection to malicious contracts
- Discord/Telegram fake announcements of "exclusive mints"

> **Remember:** Anyone asking for your seed phrase (12/24 words) is always a scammer. No legitimate service ever needs it.

### Fake Software & App Phishing
- Trojanized software installers (Adobe, VLC, 7-Zip, game clients)
- Fake browser extensions that steal passwords and session cookies
- Malicious Android APKs distributed outside official app stores
- Fake iOS profiles distributed via MDM phishing

### Defense
- Enable Steam Guard / PSN 2FA / Xbox 2FA
- Only download software from official sources and app stores
- Never enter your seed phrase on any website
- Use a hardware wallet for significant crypto holdings
- Check browser extension permissions carefully before installing

---

## 11. AI-Powered & Emerging Phishing

### AI-Generated Spear Phishing
Large language models (LLMs) can now generate highly personalized, grammatically perfect phishing emails at scale. Traditional indicators (grammar errors, generic greetings) are no longer reliable.

**What AI enables:**
- Bulk generation of personalized emails using scraped OSINT data
- Multilingual phishing with no accent or grammar artifacts
- Dynamic lures that adapt to the target's industry, role, and recent activity
- Automated A/B testing of subject lines and lures

### AI Voice Cloning (Vishing 2.0)
Using as little as 3–10 seconds of publicly available audio (social media, YouTube, earnings calls), attackers can clone voices convincingly.

**Documented use cases:**
- Cloning a CEO's voice to authorize emergency wire transfers
- Cloning family members' voices for grandparent scams
- Fake video call participants using real-time face-swap deepfakes

### Deepfake Video Phishing
Attackers use real-time deepfake tools during video calls to impersonate executives, clients, or colleagues. Increasingly used in high-value BEC and fraud scenarios.

> In 2024, a finance employee in Hong Kong was tricked into transferring $25M after a video call with deepfaked "colleagues" — all AI-generated.

### Adversarial AI Against Filters
Attackers use AI to:
- Generate text that bypasses NLP-based spam and phishing filters
- Embed phishing content in images (bypassing text analysis)
- Rotate infrastructure faster than blocklists can track
- Craft subject lines specifically optimized to maximize open rates

### Defense Against AI Phishing
- Establish **out-of-band verification** for any unusual or high-value requests
- Use a **shared codeword** for video calls when identity must be confirmed
- Implement **FIDO2 hardware security keys** — immune to credential phishing regardless of how convincing the lure is
- Train employees that polished, well-written communication is no longer a sign of legitimacy
- Deploy behavioral AI security tools that detect anomalies rather than relying on signature matching

---

## 12. Quick Reference — Detection & Defense

### Universal Red Flags (Any Channel)

```
⚠️  Urgency or threats ("Act now or lose access")
⚠️  Requests for credentials, OTPs, or seed phrases
⚠️  Requests for wire transfers, gift cards, or crypto payments
⚠️  Links or QR codes that don't match the claimed organization
⚠️  Unusual contact from a known person via an unfamiliar channel
⚠️  Requests to bypass normal approval or verification processes
⚠️  Any request to install remote access software
```

### Defense-in-Depth Summary

| Layer | Control |
|-------|---------|
| **Identity** | MFA everywhere; prefer FIDO2/hardware keys |
| **Email** | DMARC p=reject; email gateway with sandboxing |
| **Endpoint** | EDR/AV; browser isolation; DNS filtering |
| **Network** | VPN on public Wi-Fi; network-level phishing filters |
| **Process** | Callback verification for financial requests; dual authorization |
| **People** | Regular phishing simulations; security awareness training |
| **Detection** | SIEM alerting on phishing IOCs; threat intelligence feeds |
| **Response** | Incident response playbooks for each phishing type |

### Reporting Channels

| Threat Type | Where to Report |
|-------------|----------------|
| Smishing | Forward to **7726** (SPAM) |
| Vishing | FTC: reportfraud.ftc.gov |
| Email phishing | reportphishing@apwg.org |
| Phishing URLs | Google: safebrowsing.google.com/safebrowsing/report_phish |
| Phishing URLs | Microsoft: microsoft.com/en-us/wdsi/support/report-unsafe-site |
| Phishing URLs | PhishTank: phishtank.com/report |
| Crypto scams | FTC: reportfraud.ftc.gov; IC3: ic3.gov |
| Social media | Use platform's built-in "Report" feature |

---

## Additional Resources

- [APWG Phishing Activity Trends Report](https://apwg.org/resources/apwg-reports/)
- [FBI IC3 BEC Statistics](https://www.ic3.gov)
- [MITRE ATT&CK — Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
- [CISA Phishing Guidance](https://www.cisa.gov/phishing)
- [Anti-Phishing Working Group (APWG)](https://apwg.org)
- [FTC — How to Recognize and Avoid Phishing Scams](https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams)
- [NIST Phishing-Resistant MFA Guidance](https://pages.nist.gov/800-63-4/)

---

*Part of the Phishing Analysis Series | Version 1.0 — May 2026*

| Guide | Topic |
|-------|-------|
| `README.md` | Phishing Analysis Tools Overview |
| `email-analysis-guide.md` | Email Analysis Deep Dive |
| `phishing-methods-overview-README.md` | **This document — All Phishing Methods** |
