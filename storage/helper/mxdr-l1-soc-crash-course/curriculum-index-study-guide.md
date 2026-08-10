# MXDR L1 SOC Crash Course — Curriculum Index & Study Guide

**Complete Structured Curriculum for L1 SOC Analyst Interview & Job Readiness**

---

## 📚 Curriculum Overview

| Metric | Value |
|--------|-------|
| **Total Modules** | 32 (0-31 core + 32 advanced) |
| **Core Modules (P0/P1)** | 31 |
| **Advanced Module (P2/P3)** | 1 |
| **Cheat Sheets** | 7 |
| **Case Studies** | 20 realistic scenarios |
| **Practical Labs** | 12 hands-on exercises |
| **Interview Questions** | 10 fundamental + 15 technical + 50 scenarios |
| **Estimated Study Time** | 80-120 hours (depending on background) |

---

## 🎯 Priority Classification

| Priority | Label | Description | Modules |
|----------|-------|-------------|---------|
| **P0** | Must Know Before Interview | Non-negotiable for passing L1 interview | 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 23, 24, 28, 29, 30, 31 |
| **P1** | Important for First Months | Critical for job performance | 21, 22, 25, 26, 27 |
| **P2** | Useful Advanced | Good to know, deepens expertise | 20, 32 (parts) |
| **P3** | Optional/Specialized | Career growth, not required for L1 | 32 (full) |

---

## 📅 Recommended Study Order

### Phase 1: Foundations (Week 1-2) — P0
```
1. Module 0: SOC & MXDR Fundamentals
2. Module 1: MDR/XDR/MXDR/SIEM/EDR/SOAR
3. Module 2: Alert Triage Methodology ⭐
3. Module 3: Incident Severity & Escalation ⭐
```

### Phase 2: Windows Core (Week 2-3) — P0
```
4. Module 4: Windows Security & Event Logs ⭐
5. Module 5: Sysmon ⭐
6. Module 6: PowerShell Security ⭐
7. Module 7: Active Directory
8. Module 8: Kerberos & NTLM ⭐
```

### Phase 3: Network & Web (Week 3-4) — P0
```
9. Module 9: Networking for SOC
10. Module 10: DNS Security
11. Module 11: HTTP/HTTPS/TLS
12. Module 12: Network Traffic Analysis
13. Module 13: Endpoint Security
14. Module 14: Malware Fundamentals
15. Module 15: Command & Control
16. Module 16: Phishing & Email Security ⭐
17. Module 17: Threat Intelligence
18. Module 18: MITRE ATT&CK ⭐
19. Module 19: Common Attacks
```

### Phase 4: Advanced Platforms (Week 4-5) — P0/P1
```
20. Module 20: Web Security (P1)
21. Module 21: Linux Security (P1)
22. Module 22: SOAR & Automation (P1)
23. Module 23: Query & Log Analysis ⭐
24. Module 24: Incident Response ⭐
25. Module 25: Forensics Basics (P1)
```

### Phase 5: Products, Cloud & Cases (Week 5-6) — P0/P1
```
26. Module 26: Security Products (P1)
27. Module 27: Cloud Security Basics (P1)
28. Module 28: Real SOC Case Studies ⭐ (ALL 20)
```

### Phase 6: Interview & Practice (Week 6-7) — P0
```
29. Module 29: Interview Preparation ⭐
30. Module 30: Practical Labs ⭐ (ALL 12)
31. Module 31: SOC Ticketing ⭐
```

### Phase 7: Advanced & Review (Week 7+) — P2/P3
```
32. Module 32: Advanced Optional Topics (Awareness only)
```

---

## ⏱️ Time Allocation Guide

| Module | Est. Hours | Priority |
|--------|------------|----------|
| 0: SOC Fundamentals | 2 | P0 |
| 1: MDR/XDR/MXDR | 2 | P0 |
| 2: Alert Triage | 4 | P0 ⭐ |
| 3: Severity/Escalation | 3 | P0 ⭐ |
| 4: Windows Security | 5 | P0 ⭐ |
| 5: Sysmon | 4 | P0 ⭐ |
| 6: PowerShell | 4 | P0 ⭐ |
| 6: Active Directory | 2 | P0 |
| 8: Kerberos/NTLM | 4 | P0 ⭐ |
| 9: Networking | 3 | P0 |
| 10: DNS Security | 3 | P0 |
| 11: HTTP/HTTPS/TLS | 2 | P0 |
| 12: Net Traffic Analysis | 3 | P0 |
| 13: Endpoint Security | 2 | P0 |
| 14: Malware | 3 | P0 |
| 15: C2 | 3 | P0 |
| 16: Phishing/Email | 4 | P0 ⭐ |
| 17: Threat Intel | 2 | P0 |
| 18: MITRE ATT&CK | 4 | P0 ⭐ |
| 19: Common Attacks | 3 | P0 |
| 20: Web Security | 3 | P1 |
| 21: Linux Security | 4 | P1 |
| 22: SOAR | 3 | P1 |
| 23: Query/Log Analysis | 5 | P0 ⭐ |
| 24: Incident Response | 4 | P0 ⭐ |
| 25: Forensics Basics | 3 | P1 |
| 26: Security Products | 3 | P1 |
| 27: Cloud Security | 4 | P1 |
| 28: Case Studies | 8 | P0 ⭐ |
| 29: Interview Prep | 5 | P0 ⭐ |
| 30: Practical Labs | 6 | P0 ⭐ |
| 31: SOC Ticketing | 3 | P0 ⭐ |
| 32: Advanced Topics | 2 | P3 |
| **Cheat Sheets** | 4 | P0 |
| **Total** | **~110** | |

---

## 🎓 Learning Objectives by Module

### Module 0: SOC Fundamentals
- [ ] Explain SOC purpose, architecture, roles
- [ ] Describe L1 workflow and shift operations
- [ ] Distinguish Event/Alert/Incident/Case/Finding/IOC/IOA/TTP

### Module 1: MDR/XDR/MXDR
- [ ] Define each technology and service model
- [ ] Explain key differences (SIEM vs XDR, EDR vs XDR, etc.)
- [ ] Describe MXDR data flow architecture

### Module 2: Alert Triage ⭐
- [ ] Apply 20-question investigation framework
- [ ] Perform enrichment, context gathering, timeline construction
- [ ] Classify FP/TP/Benign/Suspicious with evidence

### Module 3: Severity & Escalation ⭐
- [ ] Differentiate Severity/Priority/Impact/Urgency/Confidence
- [ ] Apply severity matrix with asset/data modifiers
- [ ] Use escalation matrix correctly

### Module 4: Windows Security ⭐
- [ ] Know top 20 Event IDs, Logon Types, SubStatus codes
- [ ] Interpret 4624/4625/4688/4698/4768/4769/4771/4776/1102/7045

### Module 5: Sysmon ⭐
- [ ] Know key Event IDs (1, 3, 7, 8, 10, 11, 13, 22, 25, 26)
- [ ] Analyze process trees and command lines

### Module 6: PowerShell ⭐
- [ ] Decode base64, identify download cradles, obfuscation
- [ ] Know logging (4103, 4104), AMSI, LOLBins

### Module 7: Active Directory
- [ ] Understand AD structure, trusts, GPOs, privileged accounts

### Module 8: Kerberos & NTLM ⭐
- [ ] Explain Kerberos flow (AS-REQ, TGT, TGS-REQ, TGS-REP)
- [ ] Explain attacks: Kerberoasting, AS-REP Roasting, PtH, PtT, Golden/Silver Ticket
- [ ] Map to Event IDs

### Module 9-12: Networking
- [ ] TCP/IP, ports, DNS, HTTP/HTTPS, traffic analysis
- [ ] Identify beaconing, DNS tunneling, C2 patterns

### Module 13-15: Endpoint/Malware/C2
- [ ] AV vs EDR vs XDR, malware lifecycle, C2 detection

### Module 16: Phishing ⭐
- [ ] Header analysis (SPF/DKIM/DMARC), URL/attachment triage

### Module 17: Threat Intel
- [ ] IOC/IOA/TTP, enrichment workflow, confidence scoring

### Module 18: MITRE ATT&CK ⭐
- [ ] 14 tactics, key techniques, mapping alerts

### Module 19: Common Attacks
- [ ] Detection/triage for top attack types

### Module 20: Web Security
- [ ] SQLi, XSS, SSRF, etc. — detection concepts

### Module 21: Linux Security
- [ ] Logs, SSH, persistence, process analysis, auditd

### Module 22: SOAR
- [ ] Playbooks, automation boundaries, L1 role

### Module 23: Query & Log Analysis ⭐
- [ ] KQL/SPL fluency, investigation methodology, optimization

### Module 24: Incident Response ⭐
- [ ] NIST phases, L1 role, containment authority, communication

### Module 25: Forensics Basics
- [ ] Chain of custody, preservation order, key artifacts, evidence packaging

### Module 26: Security Products
- [ ] Telemetry per product, normalized fields, cross-product pivot

### Module 27: Cloud Security
- [ ] Shared responsibility, IAM, audit logs, common alerts, containment

### Module 28: Case Studies ⭐
- [ ] Work through all 20 cases using framework

### Module 29: Interview Prep ⭐
- [ ] Fundamental Qs, Technical Qs, 50 Scenarios, STAR method

### Module 30: Practical Labs ⭐
- [ ] Complete all 12 labs within time limits

### Module 31: SOC Ticketing ⭐
- [ ] Write complete tickets, handoffs, self-audit

### Module 32: Advanced (Awareness)
- [ ] Know terms: APT, Hunting, Sigma, YARA, Volatility, RE

---

## 📋 Study Resources by Module

| Module | Primary Resource | Practice |
|--------|------------------|----------|
| 0-3 | This curriculum + NIST SP 800-61 | Case Studies 1-3 |
| 4-8 | Microsoft Docs (Event IDs), Sysmon Guide | Labs 1-4 |
| 9-12 | TCP/IP Guide, Wireshark tutorials | Labs 5-6 |
| 13-15 | MITRE ATT&CK, Malware analysis blogs | Case Studies 4-8 |
| 16 | Email header analysis tools | Lab 7 |
| 17 | ATT&CK, Vendor TI blogs | Lab 8 |
| 18 | attack.mitre.org, Navigator | Lab 9 |
| 19-20 | OWASP Top 10, Web hacking guides | — |
| 21 | Linux man pages, auditd docs | — |
| 22 | Vendor SOAR docs (XSOAR, Phantom) | — |
| 23 | KQL/SPL reference, practice environments | Labs 1-6, 9 |
| 24 | NIST SP 800-61, IR playbooks | Case Studies 9-18 |
| 25 | SANS FOR500/508 summaries | — |
| 26 | Vendor documentation | — |
| 27 | AWS/Azure/GCP security docs | — |
| 28 | This curriculum | All Case Studies |
| 29 | This curriculum + mock interviews | All 50 Scenarios |
| 30 | This curriculum | All 12 Labs |
| 31 | This curriculum | Lab 10 |
| 32 | Certifications, practice platforms | — |

---

## 🔑 Key Concepts That Appear Repeatedly

### The "Big 5" Investigation Questions (Every Alert)
1. **What triggered it?** (Detection logic, rule, indicator)
2. **Who/What is involved?** (Host, User, IP, Process, File)
3. **What happened before/after?** (Timeline ± 1-2 hours)
4. **Is it malicious, benign, or inconclusive?** (Evidence-based)
5. **Should it be escalated?** (Severity, containment, scope)

### The "Big 5" MITRE Tactics for L1
1. **Initial Access** (T1566, T1078, T1190)
2. **Execution** (T1059, T1053, T1204)
3. **Persistence** (T1547, T1053, T1505)
4. **Credential Access** (T1003, T1558, T1555)
5. **Command & Control** (T1071, T1090, T1572)

### The "Big 5" Event IDs to Memorize
1. **4624/4625** — Logon Success/Failure
2. **4688** — Process Creation (with CommandLine!)
3. **4698/4702** — Scheduled Task Created/Modified
4. **4768/4769/4771** — Kerberos (TGT, TGS, Pre-Auth Fail)
5. **1102** — Audit Log Cleared

### The "Big 5" Ports to Know Cold
1. **22** — SSH
2. **53** — DNS
3. **80/443** — HTTP/HTTPS
4. **445** — SMB
5. **3389** — RDP

### The "Big 5" Containment Actions (L1 Pre-Approved)
1. Block IP at Firewall/Proxy
2. Block Domain at Proxy/DNS
3. Quarantine Email
4. Block File Hash at EDR
5. Delete Malicious Scheduled Task

---

## 🧠 Memory Techniques

### For Event IDs: Group by Category
```
AUTH:     4624, 4625, 4634, 4647, 4672, 4768, 4769, 4771, 4776
PROCESS:  4688, 4689, 4698, 4699, 4700, 4701, 4702
ACCOUNT:  4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4738, 4740
SYSTEM:   7045, 7036, 7040, 1074, 6005, 6006, 6008, 6009, 6013
AUDIT:    1102, 4719, 4907
POWERSHELL: 4103, 4104
SHARE:    5140
DS:       4662
TOKEN:    4703, 4964
```

### For MITRE Tactics: Use Acronym
```
R R I E P P D C D L C E I
E E S X R R E R I A O X F
C C O E I I F E S T L F R
O O U C S S E D C E A S A
N N R T T T E E T R T T C
N C E I O O N N L M T O T
  E R   N N     L
```

**Recon → Resource Dev → Initial Access → Execution → Persistence → PrivEsc → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfil → Impact**

### For Severity: Use "CHIMP"
```
C — Critical (Active threat to Tier 0/1, exfil, ransomware)
H — High (Confirmed malware, C2, cred theft, lateral)
I — Informational (No threat, compliance, scans)
M — Medium (Suspicious, probable compromise)
P — Low (Anomalous, likely benign, blocked)
```

---

## ✅ Final Interview Readiness Check

### Can you do ALL of these without notes?

#### Definitions (10/10)
- [ ] SOC, SIEM, XDR, MXDR, EDR, MDR, SOAR, IOC, IOA, TTP, MITRE ATT&CK

#### Technical Explanations (15/15)
- [ ] TCP 3-way handshake
- [ ] DNS resolution
- [ ] TCP vs UDP
- [ ] Kerberos (AS-REQ, TGT, TGS, SPN, KDC)
- [ ] NTLM (challenge-response, PtH, Relay)
- [ ] TGT vs TGS
- [ ] Kerberoasting
- [ ] Pass-the-Hash
- [ ] Golden Ticket
- [ ] PowerShell (execution, logging, AMSI)
- [ ] Sysmon (key Event IDs)
- [ ] Process Tree (parent/child, cmdline)
- [ ] C2 (beaconing, protocols)
- [ ] DNS Tunneling (TXT, entropy, subdomains)

#### Scenario Answers (50/50) — STAR Method
- [ ] 40 failed → 1 success from different country
- [ ] Encoded PowerShell command
- [ ] WINWORD → PowerShell
- [ ] Beaconing every 60 seconds
- [ ] Admin login from 2 countries in 10 min
- [ ] Ransomware alert — first action
- [ ] ... (all 50 from Module 29)

#### Practical Skills
- [ ] Decode base64 PS in 30 sec
- [ ] Write KQL for brute force in 2 min
- [ ] Write SPL for beaconing in 3 min
- [ ] Triage phishing headers in 5 min
- [ ] Triage hash in 5 min
- [ ] Map attack chain to MITRE in 5 min
- [ ] Write SOC ticket in 15 min
- [ ] Assign severity to 10 scenarios in 3 min
- [ ] Make escalation decisions for 8 scenarios in 2 min

---

## 🎯 Final Words

This curriculum is designed to be **comprehensive but focused**. Every module, lab, case study, and cheat sheet serves the single purpose: **make you a competent L1 SOC analyst who can handle real alerts in a real MXDR environment.**

**The test of readiness**: When an alert fires at 03:00 AM, do you know exactly what to look at, what to investigate, what evidence to collect, what decision to make, and when to escalate?

If **YES** → You're ready.
If **NO** → Find the gap in this curriculum and study it.

**Good luck. The SOC needs you.**

---

*MXDR L1 SOC Crash Course — Complete Curriculum*
*Version 1.0 | 2024*