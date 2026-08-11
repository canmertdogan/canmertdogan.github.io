# L1 SOC Readiness Checklist — Final Assessment

**Priority: P0 — Use this to validate interview readiness**

---

## How to Use This Checklist

- **✅ Mastered** = You can explain it, demonstrate it, and answer scenario questions about it
- **🟡 Learning** = You understand the concept but need more practice
- **❌ Gap** = You don't know this yet — prioritize study

**Goal**: 90%+ ✅ before interview. 100% ✅ before first day on job.

---

## MODULE-BY-MODULE READINESS

### Module 0: SOC & MXDR Fundamentals
- [ ] Define SOC, purpose, architecture (people/process/technology)
- [ ] Explain L1/L2/L3/SOC Manager/Threat Hunter/IR roles
- [ ] Describe 24/7, follow-the-sun, shift operations
- [ ] **Event → Alert → Triage → Investigation → Incident → Escalation → Response → Closure → Documentation**
- [ ] Distinguish: Event vs Alert vs Detection vs Incident vs Case vs Finding vs IOC vs IOA vs TTP

### Module 1: MDR/XDR/MXDR/SIEM/EDR/NDR/SOAR
- [ ] Define each: MDR, XDR, MXDR, SIEM, EDR, NDR, SOAR, UEBA, TIP, Data Lake
- [ ] Explain differences: SIEM vs XDR, EDR vs XDR, MDR vs MXDR, EDR vs AV, SIEM vs SOAR, SOC vs MXDR
- [ ] Describe realistic MXDR architecture (Endpoint→EDR→XDR/SIEM→Correlation→MXDR→L1→L2→IR)

### Module 2: Alert Triage Methodology
- [ ] Apply 20-question investigation framework to ANY alert
- [ ] Perform: Alert enrichment, Context gathering, Timeline construction
- [ ] Analyze: User context, Asset criticality, Process context, Network context, Auth context
- [ ] Use: Threat intel enrichment, IOC enrichment, Correlation, Evidence collection
- [ ] Classify: False Positive, True Positive, Benign Positive, Suspicious/Inconclusive

### Module 3: Incident Severity & Escalation
- [ ] Define and differentiate: Severity, Priority, Impact, Urgency, Confidence
- [ ] Apply severity matrix (Critical/High/Medium/Low/Info) with asset/data modifiers
- [ ] Use escalation matrix: who, when, how for each severity
- [ ] Identify Critical escalation triggers: DC compromise, Admin compromise, Ransomware, Exfil, Golden Ticket

### Module 4: Windows Security & Event Logs
- [ ] Explain Windows architecture: Users, Groups, Services, Processes, Registry, Tasks, WMI, PowerShell
- [ ] **Know top 20 Event IDs cold** (4624, 4625, 4634, 4647, 4672, 4688, 4698, 4720, 4728, 4732, 4768, 4769, 4771, 4776, 1102, 7045, 4104, 5140, 4662, 4703)
- [ ] For each: What it means, Why SOC cares, Suspicious patterns, Example scenario, Correlation
- [ ] Interpret Logon Types (2,3,4,5,7,8,9,10,11) and SubStatus codes (0xC000006A, 0xC0000064, etc.)

### Module 5: Sysmon
- [ ] Know key Sysmon Event IDs: 1, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 22, 23, 25, 26
- [ ] Analyze Process Trees: Parent → Child, Command Lines, Image Paths, Hashes, User, Integrity Level
- [ ] Identify suspicious chains: WINWORD→PS→CMD→RUNDLL32, Explorer→PS (encoded), SVCHOST masquerading

### Module 6: PowerShell Security
- [ ] Explain: Execution, Encoded commands (-enc), Base64, Execution Policy, Script Block Logging (4104), Module Logging (4103), AMSI
- [ ] Identify: Download cradles (IEX + WebClient/iwr), Obfuscation (Base64, string concat), LOLBins
- [ ] Investigate suspicious PS: Decode, Analyze command, Check parent, Network, Files, Persistence

### Module 7: Active Directory
- [ ] Define: AD, Domain, DC, Users, Groups, OUs, GPO, Service Accounts, Privileged Accounts, Domain Admins, Machine Accounts, LDAP, DNS in AD
- [ ] Explain: Authentication vs Authorization

### Module 8: Kerberos & NTLM
- [ ] Describe Kerberos flow: AS-REQ → AS-REP (TGT) → TGS-REQ → TGS-REP (Service Ticket)
- [ ] Define: TGT, TGS, SPN, KDC, Service Accounts
- [ ] Explain attacks: Kerberoasting, AS-REP Roasting, Pass-the-Ticket, Golden Ticket, Silver Ticket
- [ ] Explain NTLM: Challenge-response, NTLM Relay, Pass-the-Hash, NTLM vs Kerberos
- [ ] Map to Event IDs: 4768, 4769, 4771, 4776, 4624/4625 (NTLM)

### Module 9: Networking for SOC
- [ ] Explain: OSI, TCP/IP, TCP vs UDP, 3-way handshake, IP, ICMP, ARP, MAC, Routing, NAT, DHCP, DNS
- [ ] Know ports cold: 21,22,23,25,53,80,110,143,389,443,445,3389,5985/5986, 8080/8443
- [ ] Explain why each matters to SOC

### Module 10: DNS Security
- [ ] Explain: Resolution, Record types (A, AAAA, CNAME, MX, TXT, NS, PTR), Caching, DoH
- [ ] Detect: DNS Tunneling, DGA, Suspicious domains, Fast Flux
- [ ] Investigate: High-volume TXT, High-entropy subdomains, Newly registered domains

### Module 11: HTTP/HTTPS/TLS
- [ ] Explain: Request/Response, Methods, Headers, User-Agent, Cookies, Status codes
- [ ] Explain: TLS basics, Certificates, HTTPS visibility, Proxy logs

### Module 12: Network Traffic Analysis
- [ ] Analyze: Flows (src/dst IP/port, protocol), Frequency, Beaconing, C2, Data transfer
- [ ] Use: PCAP, Wireshark, tcpdump concepts
- [ ] Identify: Periodicity, JA3, Long-lived connections, Suspicious outbound

### Module 13: Endpoint Security
- [ ] Differentiate: AV, EPP, EDR, XDR
- [ ] Explain: Signature vs Behavioral vs Heuristic detection
- [ ] Analyze: Process trees, Command lines, File hashes, Parent/child relationships

### Module 14: Malware Fundamentals
- [ ] Classify: Virus, Worm, Trojan, RAT, Ransomware, Spyware, Rootkit, Loader, Dropper, Downloader, Backdoor, Web shell
- [ ] Explain lifecycle: Initial Access → Execution → Persistence → PrivEsc → Defense Evasion → C2 → Collection → Exfil → Impact
- [ ] Understand: Static vs Dynamic analysis, Sandbox, Hashes, PE, Strings, Imports

### Module 15: Command & Control
- [ ] Explain: C2, Beaconing, Callback, HTTP/HTTPS/DNS/TCP C2, Domain fronting
- [ ] Detect: Periodic comms, Long-lived connections, Suspicious outbound
- [ ] Recognize C2 in logs: Periodicity, JA3, Low volume, High duration

### Module 16: Phishing & Email Security
- [ ] Classify: Phishing, Spear phishing, Whaling, BEC, Malicious attachment/URL, Credential phishing, QR phishing
- [ ] Investigate: Headers (Return-Path, Received, SPF, DKIM, DMARC), URLs, Domains, Attachments, Hashes, Reputation

### Module 17: Threat Intelligence
- [ ] Define: IOC, IOA, TTP, IP/Domain/Hash reputation, WHOIS, DNS intel, Threat feeds, Malware reputation, Actors, Campaigns, Families
- [ ] Apply TI during triage: Enrichment, Confidence scoring, Campaign attribution

### Module 18: MITRE ATT&CK
- [ ] Know all 14 Tactics in order
- [ ] Map key techniques: PowerShell (T1059.001), RDP (T1021.001), SMB (T1021.002), Scheduled Tasks (T1053.005), Service Execution (T1569.002), Credential Dumping (T1003.001), Kerberoasting (T1558.003), Pass-the-Hash (T1550.002), Pass-the-Ticket (T1550.003), WMI (T1047), Command/Scripting (T1059), Valid Accounts (T1078)
- [ ] Map alerts to MITRE

### Module 19: Common Attacks
- [ ] Recognize detection/triage for: Brute Force, Password Spray, Credential Stuffing, Phishing, Malware, Ransomware, SQLi, XSS, Web Shell, Lateral Movement, PrivEsc, Credential Dumping, Data Exfil

### Module 20: Web Security
- [ ] Explain: SQLi, XSS, IDOR, LFI, RFI, SSRF, CSRF, Command Injection, Path Traversal, Auth attacks, Session hijacking, JWT, Web shells
- [ ] For each: What, How, Logs, What L1 looks for, Example alert/investigation

### Module 21: Linux Security
- [ ] Navigate /var/log, journalctl, audit.log
- [ ] Analyze SSH auth (success/failed/key), sudo usage
- [ ] Enumerate processes, spot anomalies, find deleted binaries
- [ ] Check persistence: Cron, Systemd, SSH keys, Shell RC, SUID/SGID
- [ ] Use: ss/netstat, lsof, find, ps, grep
- [ ] Map to MITRE: T1110.001, T1555.004, T1053.003, T1543.002, T1548.001

### Module 22: SOAR & Automation
- [ ] Define: Orchestration, Automation, Response, Playbooks
- [ ] Know L1 use cases: Enrichment, FP suppression, Ticket creation, Containment (pre-approved)
- [ ] Distinguish: Safe to automate (enrichment, known FP close) vs Human approval (containment) vs Never automate (legal, destructive)

### Module 23: Query & Log Analysis
- [ ] Core ops: Filter, Search, Regex, Time range, Project, Aggregate, Sort, Limit, Join, Stats
- [ ] **KQL fluency**: where, summarize, join, lookup, parse, extend, make_set, arg_max, bin, render
- [ ] **SPL fluency**: stats, eval, rex, lookup, transaction, timechart, chart
- [ ] SQL basics for data lakes
- [ ] Field extraction: Base64 decode, Regex parsing, URL/DNS parsing
- [ ] Time handling: Relative time, Timezones, Bucketing
- [ ] Optimization: Filter early, Project early, Summarize before join
- [ ] Investigation method: Pivot entities → Timeline → Hypothesis testing

### Module 24: Incident Response
- [ ] NIST 7 phases: Preparation → Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned
- [ ] L1 role in each phase
- [ ] 20-question framework, Evidence collection BEFORE containment
- [ ] Containment authority: Pre-approved vs Needs approval vs Never
- [ ] Severity classification with examples
- [ ] Communication templates (Slack, Email, Stakeholder)
- [ ] When L1 must NOT act independently (DC, Ransomware, Admin, Exfil, Insider)

### Module 25: Forensics Basics
- [ ] Chain of custody: What, Where, When, Who, How, Hash, Storage
- [ ] Preservation order: Volatile first (processes, network, memory) → Non-volatile
- [ ] Key artifacts: Prefetch, Amcache, Shimcache, UserAssist, LNK, Jump Lists, SRUM, BAM, Event Logs, MFT/$LogFile/$UsnJrnl
- [ ] Linux: auth.log, audit.log, bash_history, cron, systemd, SSH keys, /tmp
- [ ] Browser/Email artifacts awareness
- [ ] Timestamp forensics: MAC times, Timestomping, MFT Entry Modified
- [ ] ADS awareness
- [ ] Memory forensics value (request, don't perform)
- [ ] Evidence package structure for IR handoff

### Module 26: Security Products
- [ ] Telemetry & L1 use for: AV/EPP, EDR, XDR, Firewall, NDR, IDS/IPS, WAF, IdP (Entra/Okta), PAM, Email Security, DLP, Vuln Mgmt, CSPM/CWPP/CIEM
- [ ] Normalized field names across products (src_ip, user, host, timestamp)
- [ ] MXDR data flow: Sources → Normalization → SIEM/XDR → SOAR/Ticketing/Analyst
- [ ] Cross-product pivot questions

### Module 27: Cloud Security Basics
- [ ] Shared Responsibility Model
- [ ] Identity: IAM User/Role (AWS), User/SP/Managed Identity (Azure), Service Account (GCP)
- [ ] Audit logs: CloudTrail, Activity Log + Sign-in Logs, Cloud Audit Logs
- [ ] Key fields: eventName/operationName, userIdentity/caller, sourceIPAddress, userAgent, errorCode
- [ ] Common alerts: Impossible travel, Suspicious role assumption, Public exposure, Crypto mining, Data exfil, Persistence
- [ ] Investigation workflow: Identify → Collect Context → Enrich → Correlate → Determine
- [ ] Containment: Disable keys, Revoke sessions, Modify SGs/NSGs, Block public access
- [ ] Cloud MITRE techniques

### Module 28: Real SOC Case Studies (20 Cases)
- [ ] Case 1: Brute Force → Success
- [ ] Case 2: Password Spraying
- [ ] Case 3: Suspicious PowerShell (Encoded)
- [ ] Case 4: Malicious Office Document
- [ ] Case 5: Phishing Email (Click + Compromise)
- [ ] Case 6: Malware Execution (LOLBin)
- [ ] Case 7: C2 Beaconing
- [ ] Case 8: Ransomware Behavior
- [ ] Case 9: Suspicious RDP
- [ ] Case 10: Lateral Movement
- [ ] Case 11: Pass-the-Hash
- [ ] Case 12: Kerberoasting
- [ ] Case 13: Golden Ticket
- [ ] Case 14: DNS Tunneling
- [ ] Case 15: Data Exfiltration
- [ ] Case 16: Privileged Account Abuse
- [ ] Case 17: Impossible Travel (MFA Fatigue)
- [ ] Case 18: Endpoint Compromise (Full Chain)
- [ ] Case 19: Web Attack (Blocked SQLi)
- [ ] Case 20: False Positive (The Crucial One)

### Module 29: Interview Preparation
- [ ] 10 Fundamental definitions (SOC, SIEM, XDR, MXDR, EDR, MDR, SOAR, IOC/IOA/TTP, MITRE)
- [ ] 15 Technical concepts explained clearly (TCP, DNS, Kerberos, NTLM, TGT/TGS, PtH, Kerberoast, Golden Ticket, PS, Sysmon, Process Tree, C2, DNS Tunneling)
- [ ] 50 Scenario questions with STAR method answers
- [ ] Common trap questions and how to avoid them
- [ ] Smart questions to ask interviewer

### Module 30: Practical Labs
- [ ] Lab 1: Windows Event ID Analysis (15 min)
- [ ] Lab 2: Brute Force vs Password Spray (10 min)
- [ ] Lab 3: PowerShell Command Analysis (15 min)
- [ ] Lab 4: Process Tree Analysis (10 min)
- [ ] Lab 5: DNS Log Analysis (15 min)
- [ ] Lab 6: HTTP/Proxy Log Analysis (15 min)
- [ ] Lab 7: Phishing Header Analysis (10 min)
- [ ] Lab 8: Suspicious Hash Investigation (10 min)
- [ ] Lab 9: MITRE ATT&CK Mapping (10 min)
- [ ] Lab 10: SOC Ticket Writing (20 min)
- [ ] Lab 11: Severity Determination (5 min)
- [ ] Lab 12: Escalation Decisions (5 min)

### Module 31: SOC Ticketing
- [ ] Complete standard ticket template (all fields)
- [ ] Write in objective, evidence-based language
- [ ] Structure IOCs, Timeline, MITRE as tables
- [ ] Document containment with approval chain
- [ ] Justify severity with specific reasoning
- [ ] Categorize recommended actions (Immediate/Short/Long-term)
- [ ] Write clear escalation handoff notes
- [ ] Produce professional shift handoff
- [ ] Self-audit against quality checklist

### Module 32: Advanced Optional (Awareness Only)
- [ ] APT, Threat Hunting, Detection Engineering, Sigma, YARA, Suricata/Snort
- [ ] KQL/SPL Advanced, Memory Forensics (Volatility), Reverse Engineering
- [ ] Malware Analysis Advanced, Cloud Detection Engineering
- [ ] Career path: L1 → L2 → L3 → Principal
- [ ] Certifications: CySA+ (L1), GCIH (L2), GCFA/GREM (L3)

---

## CHEAT SHEET MASTERY

- [ ] Windows Event ID Cheat Sheet (Top 20 IDs, Logon Types, SubStatus, KQL/SPL queries)
- [ ] Common Ports Cheat Sheet (Critical/High/Medium, Malware defaults, KQL/SPL queries)
- [ ] MITRE ATT&CK Cheat Sheet (14 Tactics, Must-know Techniques, Quick Mapping, Navigator)
- [ ] IOC/IOA/TTP Cheat Sheet (Definitions, Types, Confidence, IOA Patterns, TTP Groups, Lifecycle, TLP, Export)
- [ ] SIEM/EDR/XDR/MXDR Comparison (Definitions, Capabilities, Data Flow, Vendors, L1 Workflow)
- [ ] Incident Severity Cheat Sheet (5 Levels, Asset/Data/Velocity Modifiers, Decision Tree, Scenarios, SLA)
- [ ] SOC Escalation Cheat Sheet (Authority Matrix, Pre-approved/Needs Approval/Never, Scenario Paths, Communication)

---

## PRACTICAL SKILLS DEMONSTRATION

Can you do these in the time limit?

- [ ] **Decode base64 PowerShell** in < 30 seconds
- [ ] **Analyze process tree** (Office → PS → LOLBin) in < 2 minutes
- [ ] **Write KQL query** for failed logons + success in < 2 minutes
- [ ] **Write SPL query** for beaconing detection in < 3 minutes
- [ ] **Triage phishing email** (headers, SPF/DKIM/DMARC, URLs) in < 5 minutes
- [ ] **Triage file hash** (VT, behavior, MITRE, actions) in < 5 minutes
- [ ] **Map attack chain** to MITRE (10+ techniques) in < 5 minutes
- [ ] **Write complete SOC ticket** from notes in < 15 minutes
- [ ] **Assign severity** to 10 scenarios in < 3 minutes
- [ ] **Make escalation decisions** for 8 scenarios in < 2 minutes
- [ ] **Answer 10 scenario questions** using STAR method in < 10 minutes

---

## FINAL READINESS SCORE

```
Count your ✅ Mastered items:

Modules (0-32):        ____ / 33
Cheat Sheets (7):      ____ / 7
Practical Skills (11): ____ / 11
──────────────────────────────
TOTAL:                 ____ / 51

PERCENTAGE: ____%

TARGET: ≥ 90% (46+/51) for interview
TARGET: 100% (51/51) for Day 1 on job
```

---

## IF NOT READY — 7-Day Cram Plan

| Day | Focus |
|-----|-------|
| **Day 1** | Modules 0, 1, 2, 3 (SOC Fundamentals, Alert Triage, Severity) |
| **Day 2** | Modules 4, 5, 6, 7, 8 (Windows, Sysmon, PowerShell, AD, Kerberos/NTLM) |
| **Day 3** | Modules 9, 10, 11, 12, 13, 14, 15 (Networking, DNS, HTTP, Net Traffic, Endpoint, Malware, C2) |
| **Day 4** | Modules 16, 17, 18, 19, 20 (Phishing, TI, MITRE, Common Attacks, Web) |
| **Day 5** | Modules 21, 22, 23, 24, 25 (Linux, SOAR, Queries, IR, Forensics) |
| **Day 6** | Modules 26, 27, 28 (Products, Cloud, Case Studies — do ALL 20) |
| **Day 7** | Modules 29, 30, 31 (Interview, Labs, Ticketing) + All Cheat Sheets + Mock Interview |

---

## DAY-OF-INTERVIEW CHECKLIST

- [ ] Printed resume (3 copies)
- [ ] Notebook + pen
- [ ] Mental cheat sheet: TCP handshake, Kerberos flow, Event IDs, MITRE tactics, Ports
- [ ] 3 questions prepared for them
- [ ] STAR method practiced for scenarios
- [ ] Calm breathing: You've prepared for this

---

## AFTER INTERVIEW — CONTINUOUS LEARNING

- [ ] Join r/blueteamsec, r/socanalyst
- [ ] TryHackMe SOC Level 1/2 paths
- [ ] LetsDefend / Blue Team Labs Online practice
- [ ] Read MITRE ATT&CK blog, Detection Engineering Weekly
- [ ] Target: CySA+ certification within 3 months
- [ ] Target: GCIH within 12 months

---

**You've got this. The curriculum is complete. Now go crush that interview.**

---

*End of MXDR L1 SOC Crash Course*