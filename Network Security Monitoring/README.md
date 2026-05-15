# 🛡️ Network Security Monitoring (NSM)

A comprehensive reference guide for understanding, implementing, and operating Network Security Monitoring — from foundational concepts to advanced detection engineering.

---

## Table of Contents

1. [What is Network Security Monitoring?](#1-what-is-network-security-monitoring)
2. [Core NSM Concepts](#2-core-nsm-concepts)
3. [NSM Data Types](#3-nsm-data-types)
4. [NSM Architecture](#4-nsm-architecture)
5. [Key Protocols to Monitor](#5-key-protocols-to-monitor)
6. [Threat Detection Approaches](#6-threat-detection-approaches)
7. [Tools & Platforms](#7-tools--platforms)
8. [NSM in the SOC Workflow](#8-nsm-in-the-soc-workflow)
9. [Common Attack Patterns & Network Indicators](#9-common-attack-patterns--network-indicators)
10. [Log Sources & Data Collection](#10-log-sources--data-collection)
11. [Metrics & KPIs](#11-metrics--kpis)
12. [Learning Path](#12-learning-path)
13. [Further Reading & Resources](#13-further-reading--resources)

---

## 1. What is Network Security Monitoring?

Network Security Monitoring (NSM) is the practice of **collecting, analyzing, and responding to network data** to detect and investigate security threats. It provides visibility into what is happening across an organization's network infrastructure in real time and historically.

> *"NSM is the collection, analysis, and escalation of indications and warnings to detect and respond to intrusions."*
> — Richard Bejtlich, *The Practice of Network Security Monitoring*

### Why NSM Matters

No perimeter is perfect. Attackers will get in — through phishing, compromised credentials, supply chain attacks, or zero-days. NSM operates on the assumption that **breach is inevitable** and focuses on:

- **Detecting** threats that bypass preventive controls
- **Investigating** incidents with full network context
- **Responding** faster by reducing dwell time (the time an attacker operates undetected)
- **Understanding** normal network behavior to spot anomalies

### NSM vs. Related Disciplines

| Discipline | Focus |
|------------|-------|
| **NSM** | Continuous monitoring, detection, and investigation of network activity |
| **IDS/IPS** | Signature and anomaly-based detection/prevention at the network layer |
| **SIEM** | Aggregation and correlation of logs from multiple sources (network + endpoint + application) |
| **Threat Hunting** | Proactive, hypothesis-driven search for hidden threats |
| **Incident Response** | Structured process to contain, eradicate, and recover from a confirmed incident |
| **Packet Analysis** | Deep inspection of raw network traffic (PCAP) for forensic or diagnostic purposes |

NSM encompasses and feeds all of these disciplines.

---

## 2. Core NSM Concepts

### The NSM Cycle

```
  COLLECT → DETECT → ANALYZE → RESPOND
     ↑                              |
     └──────────────────────────────┘
              (continuous loop)
```

- **Collect** — Capture network data (packets, flows, logs, metadata)
- **Detect** — Identify anomalies, known bad indicators, or behavioral outliers
- **Analyze** — Investigate alerts to determine scope, severity, and attacker intent
- **Respond** — Contain the threat, eradicate access, recover, and improve detection

### Visibility is Everything

NSM effectiveness is directly proportional to **visibility**. You cannot detect what you cannot see. Key visibility gaps include:

- **Encrypted traffic** — TLS/SSL hides payload content (metadata analysis is still possible)
- **East-West traffic** — Internal lateral movement between systems (often missed if only monitoring perimeter)
- **Cloud and SaaS** — Traffic that never touches on-premise infrastructure
- **Remote workers** — Endpoints not connected to monitored network segments
- **Shadow IT** — Unauthorized devices and services on the network

### The Pyramid of Pain

Developed by David Bianco, the Pyramid of Pain describes how difficult it is for attackers to change different types of indicators when defenders act on them:

```
         /\
        /  \   TTPs (Tactics, Techniques, Procedures) ← Hardest for attacker to change
       /----\
      / Tools \  ← Hard
     /----------\
    / Network/Host \  ← Medium
   /  Artifacts     \
  /------------------\
 /   Domain Names     \  ← Easy for attacker to change
/----------------------\
/    IP Addresses       \  ← Trivial
/------------------------\
/    Hash Values          \  ← Trivial
/--------------------------\
```

NSM should aim to detect at the **TTP level**, not just IOC (Indicator of Compromise) matching.

### Dwell Time

**Dwell time** is the number of days an attacker operates in your environment before detection. The global median dwell time has historically been measured in weeks to months. NSM is the primary tool for reducing dwell time.

---

## 3. NSM Data Types

NSM relies on three primary data types, each offering different levels of detail and storage requirements.

### Full Packet Capture (FPC) — The Gold Standard

Raw network traffic captured in **PCAP (Packet Capture)** format. Contains complete payload data.

```
Pros:  Complete forensic record; can reconstruct sessions, extract files, decode protocols
Cons:  Extremely high storage requirements; difficult to query at scale; complex to analyze
Tools: Wireshark, tcpdump, Zeek, Arkime (formerly Moloch), NetworkMiner
```

```bash
# Capture traffic on interface eth0 to file
tcpdump -i eth0 -w capture.pcap

# Capture only HTTP traffic
tcpdump -i eth0 port 80 -w http_capture.pcap

# Read a PCAP file
tcpdump -r capture.pcap
```

### Session/Flow Data — The Workhouse

Summary records of network conversations without payload content. Includes source/destination IPs, ports, protocol, bytes transferred, duration, and timestamps.

```
Pros:  Compact storage; fast querying; excellent for baseline and anomaly detection
Cons:  No payload visibility; cannot reconstruct files or commands
Standards: NetFlow (Cisco), IPFIX (RFC 7011), sFlow, J-Flow
Tools: Zeek (conn.log), ntopng, SiLK, nfdump, Argus, Elastic Flow
```

**Example NetFlow record:**
```
Src IP          Dst IP          Proto  Src Port  Dst Port  Bytes    Packets  Duration
192.168.1.45    203.0.113.22    TCP    52341     443       145,230  98       00:02:34
```

### Metadata / Protocol Logs — The Analyst's Friend

Parsed, protocol-aware logs that extract meaningful fields from network traffic. Sits between FPC and flow data in detail and storage cost.

```
Pros:  Rich context (DNS queries, HTTP URIs, TLS certs, file hashes); queryable; moderate storage
Cons:  Requires protocol-aware sensor; blind to unknown/custom protocols
Tools: Zeek (generates dns.log, http.log, ssl.log, files.log, etc.), Suricata (EVE JSON logs)
```

**Example Zeek HTTP log entry:**
```
ts          uid       orig_h        resp_h        method  host              uri               status_code  resp_mime_type
1715000000  CAbcDe1   192.168.1.45  203.0.113.22  GET     evil-domain.com   /payload.exe      200          application/octet-stream
```

### Alert Data

Events generated by IDS/IPS or other detection systems when a rule or signature matches observed traffic.

```
Pros:  Actionable; pre-filtered; mapped to known threats
Cons:  Only catches known threats; prone to false positives; no context without underlying data
Tools: Suricata, Snort, Zeek (with scripts), commercial NGFW/IDS platforms
```

---

## 4. NSM Architecture

### Sensor Placement

Where you place your sensors determines what you can see.

```
Internet
    |
[Firewall / Edge Router]
    |
[TAP or SPAN Port] ← NSM Sensor (perimeter visibility)
    |
[Core Switch]
    |        \
[Servers]  [Internal Switch]
                |
           [TAP or SPAN Port] ← NSM Sensor (east-west visibility)
                |
           [User Workstations]
```

**TAP (Test Access Point):** Passive hardware device that copies all traffic without affecting the network. Preferred for production environments.

**SPAN Port (Switch Port Analyzer):** Mirror port configured on a managed switch. Lower cost but may drop packets under high load.

### Sensor Types

| Sensor Type | Description | Typical Placement |
|-------------|-------------|-------------------|
| **Perimeter sensor** | Monitors traffic crossing the network boundary | Between firewall and core switch |
| **Internal sensor** | Monitors east-west (lateral) traffic | On core internal switches |
| **Cloud sensor** | Monitors traffic in cloud environments | VPC Flow Logs, cloud-native tools |
| **Endpoint sensor** | Host-based network monitoring | On critical servers and endpoints |
| **Wireless sensor** | Monitors 802.11 wireless traffic | Near wireless access points |

### Centralized vs. Distributed Architecture

```
Distributed Collection:
[Sensor A] ──┐
[Sensor B] ──┼──→ [Central Manager / SIEM] → [Analyst Workstation]
[Sensor C] ──┘

Benefits: Scales to large networks; sensors process locally; central correlation
Challenges: Bandwidth for log shipping; sensor management overhead
```

---

## 5. Key Protocols to Monitor

### Layer 3–4 (Network & Transport)

| Protocol | Port(s) | What to Monitor |
|----------|---------|----------------|
| **ICMP** | — | Ping sweeps, tunneling, unusual type/code combinations |
| **TCP** | — | SYN scans, unusual flag combinations, long-lived connections |
| **UDP** | — | DNS, NTP amplification, unusual high-port activity |

### Layer 7 (Application)

| Protocol | Port(s) | What to Monitor |
|----------|---------|----------------|
| **DNS** | 53 | Unusual query types, DGA domains, DNS tunneling, high query volume |
| **HTTP** | 80 | URIs, user agents, POST bodies, unusual response codes |
| **HTTPS/TLS** | 443 | Certificate details, JA3 fingerprints, SNI, unusual cipher suites |
| **SMTP** | 25, 587 | Sender/recipient, attachment names, relay behavior |
| **FTP** | 20, 21 | File transfers, anonymous login, lateral movement |
| **SMB** | 445 | Lateral movement, ransomware propagation, credential relay |
| **RDP** | 3389 | Brute force, remote access, unusual source IPs |
| **SSH** | 22 | Brute force, tunneling, unusual source IPs |
| **Kerberos** | 88 | Kerberoasting, Pass-the-Ticket, Golden Ticket attacks |
| **LDAP** | 389, 636 | Enumeration, credential stuffing, DCSync attacks |
| **NTP** | 123 | Amplification DDoS, time manipulation |
| **DHCP** | 67, 68 | Rogue DHCP servers, scope exhaustion, new device detection |

---

## 6. Threat Detection Approaches

### Signature-Based Detection

Matches network traffic against a database of known attack patterns (signatures/rules).

```
Pros:  Low false positive rate for known threats; fast; easy to implement
Cons:  Cannot detect unknown/novel threats; requires constant signature updates; easily evaded
Tools: Suricata, Snort
```

**Example Suricata rule:**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible Cobalt Strike Beacon";
  http.user_agent; content:"Mozilla/5.0 (compatible|3b| MSIE 9.0|3b|";
  sid:2025123; rev:1;
)
```

### Anomaly-Based Detection

Establishes a baseline of normal behavior and alerts on deviations.

```
Pros:  Can detect unknown threats; effective for insider threats and novel malware
Cons:  Higher false positive rate; requires time to baseline; complex to tune
Approaches: Statistical analysis, machine learning, behavioral profiling
```

**Examples of anomalies to detect:**
- A workstation that never communicated externally suddenly beaconing to a foreign IP every 60 seconds
- DNS query volume from a single host 10x higher than its 30-day baseline
- A user account authenticating from two geographically impossible locations within 1 hour

### Threat Intelligence-Based Detection

Matching observed network activity against known bad indicators (IPs, domains, file hashes, URLs) from threat intelligence feeds.

```
Pros:  Directly actionable; maps to known threat actors and campaigns
Cons:  Only covers known indicators; indicators have short shelf life; high volume of feeds
Sources: MISP, AlienVault OTX, Mandiant, Recorded Future, CISA feeds, ISACs
```

### Behavioral / TTP-Based Detection

Detecting attacker techniques based on *how* they behave rather than *what* tools they use. Mapped to the MITRE ATT&CK framework.

```
Pros:  Resilient to tool changes; catches novel malware using known techniques
Cons:  Complex to implement; requires deep understanding of attacker behavior
Framework: MITRE ATT&CK (https://attack.mitre.org)
```

**Example:** Detecting DNS tunneling not by signature, but by:
- High entropy in DNS query strings
- Unusually long DNS labels
- High query rate to a single domain
- TXT record responses with large data payloads

---

## 7. Tools & Platforms

### Packet Capture & Analysis

| Tool | Type | Description |
|------|------|-------------|
| **Wireshark** | Open Source | GUI-based packet analyzer; industry standard for deep packet inspection |
| **tcpdump** | Open Source | CLI packet capture tool; lightweight and universally available |
| **tshark** | Open Source | CLI version of Wireshark; scriptable and pipeline-friendly |
| **Arkime** | Open Source | Full packet capture, indexing, and search platform at scale |
| **NetworkMiner** | Free/Commercial | Passive network sniffer and forensic analyzer |

### Protocol Analysis & Metadata

| Tool | Type | Description |
|------|------|-------------|
| **Zeek** | Open Source | Network analysis framework generating rich protocol logs |
| **Suricata** | Open Source | High-performance IDS/IPS/NSM engine with EVE JSON logging |
| **Snort** | Open Source | Original network IDS; large rule community |
| **ntopng** | Open Source/Commercial | Flow analysis, traffic visualization, and anomaly detection |

### SIEM & Log Management

| Tool | Type | Description |
|------|------|-------------|
| **Elastic Stack (ELK)** | Open Source | Elasticsearch + Logstash + Kibana; popular NSM platform |
| **Splunk** | Commercial | Industry-leading SIEM with powerful SPL query language |
| **Microsoft Sentinel** | Commercial | Cloud-native SIEM with Azure integration |
| **Graylog** | Open Source/Commercial | Centralized log management and analysis |
| **OpenSearch** | Open Source | AWS-maintained Elasticsearch fork |

### Threat Detection Platforms

| Tool | Type | Description |
|------|------|-------------|
| **Security Onion** | Open Source | NSM distro bundling Zeek, Suricata, Elastic, and more |
| **HELK** | Open Source | Hunting ELK stack with Jupyter notebooks for threat hunting |
| **Arkime + Zeek + Suricata** | Open Source | Common combination for full NSM visibility |
| **Vectra AI** | Commercial | AI-based network detection and response (NDR) |
| **Darktrace** | Commercial | AI-driven anomaly detection |
| **ExtraHop** | Commercial | Network detection and response with ML |

### Threat Intelligence Integration

| Tool | Type | Description |
|------|------|-------------|
| **MISP** | Open Source | Threat intelligence sharing and IOC management |
| **OpenCTI** | Open Source | Open Cyber Threat Intelligence platform |
| **TAXII/STIX** | Standard | Protocol/format for threat intel sharing |
| **AlienVault OTX** | Free/Commercial | Community threat intelligence feeds |

---

## 8. NSM in the SOC Workflow

### Alert Triage Process

```
Alert Generated
      |
      ▼
[1. VALIDATE]
Is this a true positive or false positive?
Check alert context, source/dest reputation, protocol behavior
      |
      ▼
[2. SCOPE]
How far has this spread?
Check related alerts, other hosts, time range, lateral movement
      |
      ▼
[3. CLASSIFY]
What type of threat is this?
Map to MITRE ATT&CK; determine attacker stage in kill chain
      |
      ▼
[4. PRIORITIZE]
What is the severity and urgency?
Consider asset criticality, data sensitivity, active vs. dormant threat
      |
      ▼
[5. ESCALATE / RESPOND]
Notify IR team, contain affected systems, collect evidence
```

### Analyst Tiers

| Tier | Role | Responsibilities |
|------|------|----------------|
| **Tier 1** | Alert Analyst | Monitor dashboards, triage alerts, basic investigation, escalate |
| **Tier 2** | Incident Responder | Deep investigation, containment, root cause analysis |
| **Tier 3** | Threat Hunter / SME | Proactive hunting, detection engineering, advanced forensics |

### Key Analyst Questions for Every Alert

```
1. WHO    — What source IP / user / host is involved?
2. WHAT   — What action was taken? What data was accessed or transferred?
3. WHEN   — When did it start? Is it ongoing? What happened before and after?
4. WHERE  — What destination IPs, domains, or internal systems are involved?
5. WHY    — Is there a plausible legitimate explanation?
6. HOW    — What technique was used? Where does it sit on the kill chain?
```

---

## 9. Common Attack Patterns & Network Indicators

### Reconnaissance
```
Network Indicators:
- Port scans (sequential ports, many ports in short time from one IP)
- ICMP ping sweeps across subnets
- ARP scans on local network
- Service banner grabbing (unusual connections to many ports)
- DNS zone transfer attempts (AXFR queries)
```

### Initial Access
```
Network Indicators:
- Phishing email with malicious attachment (SMTP + HTTP/S download)
- Drive-by download (HTTP redirect chains, unusual content types)
- Exploitation of public-facing services (unusual payloads in HTTP/SSH/RDP)
- Brute force login attempts (many auth failures in short period)
```

### Command & Control (C2)
```
Network Indicators:
- Regular, periodic outbound connections (beaconing) — e.g. every 60 seconds
- Connections to newly registered or low-reputation domains
- High entropy domain names (DGA — Domain Generation Algorithm)
- DNS tunneling (long labels, high TXT query volume, unusual record types)
- HTTP C2 with unusual User-Agent strings or URI patterns
- HTTPS to IP addresses instead of domain names
- Long-lived connections with low data transfer (keep-alive beaconing)
- Use of legitimate services for C2 (Slack, GitHub, Twitter, Dropbox — LOLBAS)
```

### Lateral Movement
```
Network Indicators:
- SMB connections between workstations (not normal in most environments)
- RDP connections originating from non-admin workstations
- WMI or PsExec-style connections (port 445 + admin shares)
- Pass-the-Hash / Pass-the-Ticket (Kerberos anomalies, NTLM in Kerberos environment)
- Unusual authentication patterns (single account accessing many systems rapidly)
- Internal port scanning from compromised host
```

### Exfiltration
```
Network Indicators:
- Unusually large outbound data transfers (especially to cloud storage or uncommon destinations)
- DNS exfiltration (high volume of long TXT queries or encoded A record queries)
- HTTPS POST with large body to unusual destination
- Compression and archiving activity followed by outbound transfer
- Outbound FTP, SCP, or other file transfer protocols to external IPs
- Data exfiltration via legitimate services (OneDrive, Google Drive, Pastebin)
```

---

## 10. Log Sources & Data Collection

### Essential Log Sources for NSM

| Source | What It Provides |
|--------|----------------|
| **Firewall logs** | Allow/deny decisions, NAT translations, connection state |
| **DNS logs** | All queries and responses — critical for C2 and exfiltration detection |
| **DHCP logs** | IP-to-hostname-to-MAC mappings; essential for attribution |
| **Proxy logs** | HTTP/S requests including URIs, user agents, referrers |
| **NetFlow/IPFIX** | Session-level summaries from routers and switches |
| **IDS/IPS alerts** | Signature matches and anomaly detections |
| **VPN logs** | Remote access connections, authentication events |
| **Email gateway logs** | Inbound/outbound email, attachment analysis, URL filtering |
| **Authentication logs** | AD/LDAP events, failed logins, Kerberos tickets |
| **Endpoint logs** | Process creation, network connections, file access (EDR) |

### Log Retention Recommendations

| Log Type | Recommended Retention |
|----------|----------------------|
| Full PCAP | 3–7 days (storage-intensive) |
| Flow/session data | 30–90 days |
| Protocol metadata (Zeek) | 30–90 days |
| IDS alerts | 1 year |
| Firewall logs | 1 year |
| DNS logs | 1 year |
| Authentication logs | 1–3 years |

---

## 11. Metrics & KPIs

Measuring NSM program effectiveness is essential for continuous improvement.

### Operational Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Mean Time to Detect (MTTD)** | Average time from intrusion to detection | < 24 hours |
| **Mean Time to Respond (MTTR)** | Average time from detection to containment | < 4 hours |
| **Alert Volume** | Total alerts generated per day | Track trend; reduce noise |
| **True Positive Rate** | % of alerts that are genuine threats | > 50% (higher = better tuning) |
| **False Positive Rate** | % of alerts that are benign | Lower is better |
| **Coverage** | % of network segments monitored | > 95% |
| **Dwell Time** | Days attacker was present before detection | Minimize |

### Visibility Metrics

| Metric | Description |
|--------|-------------|
| **Network segments monitored** | % of segments with active sensors |
| **Protocols decoded** | # of protocols with metadata logging |
| **Log source availability** | % uptime of critical log sources |
| **Data freshness** | Lag between event occurrence and SIEM ingestion |

---

## 12. Learning Path

### Beginner
- [ ] Understand TCP/IP fundamentals (OSI model, IP addressing, routing)
- [ ] Learn how DNS, HTTP, TLS, and SMTP work
- [ ] Get comfortable with Wireshark — capture and analyze basic traffic
- [ ] Understand what firewalls and IDS/IPS do
- [ ] Read: *The Practice of Network Security Monitoring* — Richard Bejtlich
- [ ] Complete: TryHackMe — "Network Security" learning path
- [ ] Complete: Wireshark Udemy courses or Wireshark University resources

### Intermediate
- [ ] Deploy Security Onion in a lab environment
- [ ] Learn Zeek log structure and write basic queries
- [ ] Understand Suricata rule syntax and write custom rules
- [ ] Practice with packet challenges (malware-traffic-analysis.net)
- [ ] Learn Elastic/Kibana or Splunk for log querying
- [ ] Study the MITRE ATT&CK framework and map techniques to network indicators
- [ ] Read: *Applied Network Security Monitoring* — Chris Sanders & Jason Smith
- [ ] Complete: SANS SEC503 (Intrusion Detection In-Depth)

### Advanced
- [ ] Implement full NSM pipeline: TAP → Zeek/Suricata → ELK/Splunk
- [ ] Write detection rules and analytics from scratch based on TTPs
- [ ] Practice threat hunting with real datasets (EVTX/PCAP challenges)
- [ ] Study adversarial tradecraft (C2 frameworks: Cobalt Strike, Sliver, Havoc)
- [ ] Contribute to open-source detection rule sets (Emerging Threats, Sigma)
- [ ] Learn network forensics and PCAP analysis for incident response
- [ ] Read: *The Art of Intrusion* — Kevin Mitnick
- [ ] Certifications: GCIA (GIAC Certified Intrusion Analyst), GCIH, CCD

---

## 13. Further Reading & Resources

### Books
- *The Practice of Network Security Monitoring* — Richard Bejtlich
- *Applied Network Security Monitoring* — Chris Sanders & Jason Smith
- *Network Forensics: Tracking Hackers Through Cyberspace* — Sherri Davidoff
- *Intrusion Detection Honeypots* — Chris Sanders

### Online Resources
- [Security Onion Documentation](https://docs.securityonion.net)
- [Zeek Documentation](https://docs.zeek.org)
- [Suricata Documentation](https://suricata.readthedocs.io)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Malware Traffic Analysis (PCAP exercises)](https://www.malware-traffic-analysis.net)
- [PacketLife Cheat Sheets](https://packetlife.net/library/cheat-sheets/)
- [Elastic SIEM Detection Rules](https://github.com/elastic/detection-rules)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Emerging Threats Suricata Rules](https://rules.emergingthreats.net)

### Practice Labs
- [TryHackMe — Network Security paths](https://tryhackme.com)
- [Hack The Box — Sherlocks (blue team challenges)](https://www.hackthebox.com)
- [Blue Team Labs Online](https://blueteamlabs.online)
- [CyberDefenders](https://cyberdefenders.org)
- [PCAP challenges on malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)

### Certifications
| Certification | Level | Focus |
|---------------|-------|-------|
| CompTIA Network+ | Beginner | Networking fundamentals |
| CompTIA CySA+ | Intermediate | Security analyst skills |
| GIAC GCIA | Advanced | Intrusion analysis |
| GIAC GCIH | Advanced | Incident handling |
| SANS SEC503 | Advanced | In-depth intrusion detection |
| Cisco CyberOps Associate | Intermediate | SOC analyst skills |

---

## NSM Series — Guide Index

| # | Guide | Status |
|---|-------|--------|
| 1 | NSM Overview (this document) | ✅ Complete |
| 2 | Traffic Analysis & Packet Inspection | 🔜 Coming Next |
| 3 | Zeek — Protocol Logging & Analysis | 🔜 Planned |
| 4 | Suricata — Signature & Rule Writing | 🔜 Planned |
| 5 | Threat Hunting with NSM Data | 🔜 Planned |
| 6 | C2 Detection & Beaconing Analysis | 🔜 Planned |
| 7 | NSM for Cloud Environments | 🔜 Planned |

---

*Network Security Monitoring Series | Version 1.0 — May 2026*
*Part of the Blue Team Reference Documentation*
