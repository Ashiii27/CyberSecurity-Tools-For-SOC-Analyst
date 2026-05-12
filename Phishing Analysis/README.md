# 🎣 Phishing Analysis Tools

A comprehensive reference guide for cybersecurity professionals investigating and analyzing phishing attacks.

---

## Table of Contents

- [Overview](#overview)
- [Email Analysis](#email-analysis)
- [URL & Link Analysis](#url--link-analysis)
- [Domain & IP Intelligence](#domain--ip-intelligence)
- [Attachment & File Analysis](#attachment--file-analysis)
- [Threat Intelligence Platforms](#threat-intelligence-platforms)
- [SIEM & Log Analysis](#siem--log-analysis)
- [Browser & Network Forensics](#browser--network-forensics)
- [Simulation & Awareness Training](#simulation--awareness-training)
- [Recommended Workflow](#recommended-workflow)
- [Contributing](#contributing)

---

## Overview

Phishing remains one of the most prevalent attack vectors in cybersecurity. This repository documents the tools and methodologies used by security analysts, SOC teams, and incident responders to identify, analyze, and mitigate phishing campaigns.

### Who This Is For

- Security Operations Center (SOC) analysts
- Incident responders
- Threat intelligence researchers
- Penetration testers and red teamers
- Security awareness trainers

---

## Email Analysis

Tools for parsing email headers, verifying authentication records, and detecting spoofed senders.

### MXToolbox
- **URL**: https://mxtoolbox.com
- **Type**: Web-based / Free & Paid
- **Use**: Analyzes email headers, checks SPF, DKIM, and DMARC records, identifies spoofed or misconfigured domains.

### Google Admin Toolbox – Messageheader
- **URL**: https://toolbox.googleapps.com/apps/messageheader/
- **Type**: Web-based / Free
- **Use**: Parses raw email headers to trace message routing and identify delivery anomalies.

### PhishTool
- **URL**: https://www.phishtool.com
- **Type**: Web-based / Free & Enterprise
- **Use**: Purpose-built phishing analysis and triage platform with automated IOC extraction, MITRE ATT&CK mapping, and case management.

### EmailRep.io
- **URL**: https://emailrep.io
- **Type**: API / Free & Paid
- **Use**: Queries email reputation based on breach exposure, social media presence, and known malicious activity.

---

## URL & Link Analysis

Tools for safely inspecting, detonating, and assessing suspicious URLs.

### VirusTotal
- **URL**: https://www.virustotal.com
- **Type**: Web-based + API / Free & Paid
- **Use**: Scans URLs and files against 70+ antivirus engines and threat intelligence feeds. Provides relationship graphs between URLs, domains, IPs, and files.

### URLScan.io
- **URL**: https://urlscan.io
- **Type**: Web-based + API / Free & Paid
- **Use**: Safely browses and screenshots suspicious URLs, captures network requests, DNS records, and rendered page content without exposing the analyst.

### Any.run
- **URL**: https://any.run
- **Type**: Web-based / Free & Paid
- **Use**: Interactive online malware sandbox. Analysts can interact in real time with phishing pages or malicious attachments in a safe environment.

### Joe Sandbox
- **URL**: https://www.joesandbox.com
- **Type**: Web-based + On-Premise / Paid
- **Use**: Deep behavioral and static analysis of URLs, files, and scripts with detailed reports including MITRE ATT&CK coverage.

### Browserling
- **URL**: https://www.browserling.com
- **Type**: Web-based / Free & Paid
- **Use**: Cross-browser testing tool repurposed for safely visiting suspicious URLs in an isolated browser session.

---

## Domain & IP Intelligence

Tools for investigating domain registration, infrastructure, and ownership history.

### WHOIS / DomainTools
- **URL**: https://whois.domaintools.com
- **Type**: Web-based + API / Free & Paid
- **Use**: Investigates domain registration details, ownership history, and related infrastructure. DomainTools adds passive DNS, reverse WHOIS, and risk scoring.

### Shodan
- **URL**: https://www.shodan.io
- **Type**: Web-based + API / Free & Paid
- **Use**: Searches internet-facing infrastructure. Useful for profiling phishing kit hosting servers and identifying shared infrastructure across campaigns.

### PassiveTotal / RiskIQ (Microsoft Defender EASM)
- **URL**: https://community.riskiq.com
- **Type**: Web-based + API / Free Community & Paid
- **Use**: Passive DNS, WHOIS history, SSL certificate records, and host-pair relationships. Excellent for tracking phishing infrastructure over time.

### VirusTotal Graph
- **URL**: https://www.virustotal.com/graph
- **Type**: Web-based / Free & Paid
- **Use**: Visualizes relationships between domains, IP addresses, URLs, and files to surface phishing campaign infrastructure patterns.

### DNSDumpster
- **URL**: https://dnsdumpster.com
- **Type**: Web-based / Free
- **Use**: Discovers DNS records, subdomains, and mail server configurations for a given domain.

---

## Attachment & File Analysis

Tools for examining malicious documents, executables, and payloads delivered via phishing.

### Cuckoo Sandbox
- **URL**: https://cuckoosandbox.org
- **Type**: Open Source / Self-hosted
- **Use**: Automated malware analysis system that executes suspicious files in an isolated environment and reports on behavior, network activity, and artifacts.

### Hybrid Analysis
- **URL**: https://www.hybrid-analysis.com
- **Type**: Web-based / Free & Paid
- **Use**: Powered by CrowdStrike Falcon Sandbox. Provides detailed static and behavioral analysis reports for files and URLs.

### OLETools
- **URL**: https://github.com/decalage2/oletools
- **Type**: Open Source CLI / Free
- **Use**: Analyzes malicious Microsoft Office documents. Detects VBA macros, OLE streams, embedded objects, and obfuscated payloads.

  ```bash
  pip install oletools
  olevba suspicious_document.docx
  ```

### PDFiD & pdf-parser
- **URL**: https://blog.didierstevens.com/programs/pdf-tools/
- **Type**: Open Source CLI / Free
- **Use**: Inspects suspicious PDF files for embedded JavaScript, launch actions, URIs, and other potentially malicious structures.

  ```bash
  python pdfid.py suspicious.pdf
  python pdf-parser.py -s JavaScript suspicious.pdf
  ```

### CAPE Sandbox
- **URL**: https://capesandbox.com
- **Type**: Open Source / Self-hosted
- **Use**: Fork of Cuckoo with advanced malware configuration extraction, unpacking, and YARA integration.

---

## Threat Intelligence Platforms

Platforms for sharing, consuming, and operationalizing phishing-related threat intelligence.

### MISP (Malware Information Sharing Platform)
- **URL**: https://www.misp-project.org
- **Type**: Open Source / Self-hosted
- **Use**: Collaborative threat intelligence sharing platform. Supports IOC ingestion, correlation, and sharing across trusted communities.

### OpenPhish
- **URL**: https://openphish.com
- **Type**: Web-based + Feed / Free & Commercial
- **Use**: Community-sourced and automated feed of active phishing URLs. Useful for blocklist enrichment and campaign detection.

### PhishTank
- **URL**: https://www.phishtank.com
- **Type**: Web-based + API / Free
- **Use**: Crowdsourced database of verified phishing sites. Allows lookup and submission of suspicious URLs.

### Cofense Intelligence
- **URL**: https://cofense.com/product-services/threat-intelligence/
- **Type**: Commercial / Paid
- **Use**: Enterprise phishing threat intelligence including IOC feeds, campaign analysis, and real-time phishing site monitoring.

### AlienVault OTX (Open Threat Exchange)
- **URL**: https://otx.alienvault.com
- **Type**: Web-based + API / Free
- **Use**: Open community threat intelligence sharing platform. Pulses contain IOCs (domains, IPs, hashes) that can be correlated against phishing investigations.

---

## SIEM & Log Analysis

Platforms for correlating email, proxy, DNS, and endpoint logs to detect phishing at scale.

### Splunk
- **URL**: https://www.splunk.com
- **Type**: Enterprise / Paid (Free trial available)
- **Use**: Industry-leading SIEM for correlating email gateway logs, proxy logs, DNS queries, and endpoint data. Phishing detection via SPL queries and pre-built security content.

### Microsoft Sentinel
- **URL**: https://azure.microsoft.com/en-us/products/microsoft-sentinel
- **Type**: Cloud-based / Paid (Azure)
- **Use**: Cloud-native SIEM with built-in phishing detection rules, Microsoft 365 Defender integration, and automated playbooks via Logic Apps.

### IBM QRadar
- **URL**: https://www.ibm.com/qradar
- **Type**: Enterprise / Paid
- **Use**: SIEM with phishing-specific use cases, threat intelligence integration, and SOAR capabilities for automated response.

### Elastic SIEM (Elastic Security)
- **URL**: https://www.elastic.co/security
- **Type**: Open Source Core / Free & Paid
- **Use**: Built on the Elastic Stack. Provides detection rules for phishing indicators, email header analysis, and ML-based anomaly detection.

---

## Browser & Network Forensics

Tools for capturing and analyzing network traffic and web behavior triggered by phishing links.

### Wireshark
- **URL**: https://www.wireshark.org
- **Type**: Open Source / Free
- **Use**: Captures and dissects network traffic. Useful for analyzing credential exfiltration, C2 communications, and redirect chains triggered by phishing links.

### Burp Suite
- **URL**: https://portswigger.net/burp
- **Type**: Community (Free) & Professional (Paid)
- **Use**: HTTP/S intercepting proxy. Allows analysts to inspect and modify traffic from phishing pages, capture form submissions, and analyze redirect behavior.

### mitmproxy
- **URL**: https://mitmproxy.org
- **Type**: Open Source / Free
- **Use**: Interactive HTTPS proxy for inspecting and modifying traffic from phishing pages in a CLI or web interface.

---

## Simulation & Awareness Training

Tools for conducting authorized phishing simulations and security awareness programs.

### GoPhish
- **URL**: https://getgophish.com
- **Type**: Open Source / Free
- **Use**: Open-source phishing simulation framework. Supports campaign creation, email templates, landing pages, and real-time result tracking.

  ```bash
  ./gophish
  # Access dashboard at https://localhost:3333
  ```

### KnowBe4
- **URL**: https://www.knowbe4.com
- **Type**: Commercial / Paid
- **Use**: Enterprise security awareness training platform with automated phishing simulation, real-world template library, and risk scoring.

### Proofpoint Security Awareness Training
- **URL**: https://www.proofpoint.com/us/products/security-awareness-training
- **Type**: Commercial / Paid
- **Use**: Phishing simulation and awareness training integrated with Proofpoint's email security platform for data-driven campaign analysis.

### Lucy Security (now SANS Security Awareness)
- **URL**: https://www.sans.org/security-awareness-training/
- **Type**: Commercial / Paid
- **Use**: Phishing simulation, awareness training, and behavioral risk measurement.

---

## Recommended Workflow

A typical phishing investigation follows these stages:

```
1. TRIAGE
   └── Parse email headers (MXToolbox, Google Toolbox)
   └── Extract IOCs (sender, URLs, attachments, reply-to)

2. URL ANALYSIS
   └── Check URL reputation (VirusTotal, URLScan.io)
   └── Screenshot and browse safely (URLScan.io, Any.run)

3. DOMAIN INTELLIGENCE
   └── WHOIS lookup (DomainTools)
   └── Passive DNS and infrastructure (PassiveTotal, RiskIQ)

4. ATTACHMENT ANALYSIS
   └── Static analysis (OLETools, PDFiD)
   └── Behavioral sandbox (Any.run, Hybrid Analysis, Cuckoo)

5. THREAT INTEL ENRICHMENT
   └── Cross-reference IOCs (MISP, AlienVault OTX, VirusTotal)
   └── Check phishing databases (PhishTank, OpenPhish)

6. REPORTING & RESPONSE
   └── Document findings and IOCs
   └── Block domains/IPs in email gateway, firewall, DNS
   └── Notify affected users
   └── Submit to threat intel feeds
```

---

## Contributing

Contributions are welcome! If you know of a tool that should be included or have updates to existing entries:

1. Fork this repository
2. Add your tool entry following the existing format
3. Include: name, URL, type (open source / commercial), and a concise use case description
4. Submit a pull request with a brief description of the addition

Please ensure all tools listed are legitimate, actively maintained, and relevant to phishing analysis workflows.

---

## License

This reference guide is provided under the [MIT License](LICENSE). Tool names and trademarks belong to their respective owners.

---

*Last updated: May 2026*
