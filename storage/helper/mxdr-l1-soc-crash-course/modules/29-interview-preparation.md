# Module 29: L1 SOC / MXDR Interview Preparation

**Priority: P0 — Must know before L1 interview**

> This module contains the exact questions asked in L1 SOC interviews. Practice answering each out loud. If you can't answer in 60 seconds, study that topic more.

---

## 29.1 Fundamental Questions (Must Know Cold)

### Q1: What is a SOC?
**Answer**: A Security Operations Center is a centralized team that monitors, detects, analyzes, and responds to cybersecurity threats 24/7. It combines people (analysts, engineers), processes (playbooks, escalation), and technology (SIEM, EDR, SOAR) to protect the organization.

### Q2: What is SIEM?
**Answer**: Security Information and Event Management. Collects logs from across the environment, normalizes them, correlates events to generate alerts, and provides a search interface for investigation. Examples: Splunk, Sentinel, QRadar, Elastic.

### Q3: What is XDR?
**Answer**: Extended Detection and Response. Extends EDR beyond endpoints by natively integrating network, cloud, identity, and email telemetry into a single platform for cross-layer detection and response. Example: Cortex XDR, Defender XDR.

### Q4: What is MXDR?
**Answer**: Managed XDR. A service model where a vendor provides the XDR platform PLUS a managed SOC team (L1/L2/L3) that monitors, triages, and responds on your behalf. Different from MDR which typically only manages EDR.

### Q5: What is EDR?
**Answer**: Endpoint Detection and Response. Continuously monitors endpoint activity (processes, network, files, registry), detects behavioral threats, provides investigation tools (process trees, timelines), and enables response (isolation, file blocking, process kill).

### Q6: What is MDR?
**Answer**: Managed Detection and Response. A service where a vendor manages EDR detection and response for you. Typically EDR-focused, less cross-layer than MXDR.

### Q7: What is SOAR?
**Answer**: Security Orchestration, Automation, and Response. Connects security tools via APIs, automates repetitive tasks (enrichment, containment), and standardizes response through playbooks. Reduces MTTR and analyst workload.

### Q8: What is IOC / IOA / TTP?
**Answer**: 
- **IOC** (Indicator of Compromise): Static artifact — IP, hash, domain, URL. "What did we see?"
- **IOA** (Indicator of Attack): Behavioral pattern — sequence of actions indicating intent. "What are they doing?"
- **TTP** (Tactics, Techniques, Procedures): MITRE ATT&CK framework. "How do they operate?"

### Q9: What is MITRE ATT&CK?
**Answer**: A knowledge base of adversary tactics (why) and techniques (how) based on real-world observations. 14 tactics from Reconnaissance to Impact. Used to map detections, communicate threats, and identify coverage gaps.

---

## 29.2 Technical Questions (Must Explain Clearly)

### Q10: Explain the TCP three-way handshake.
**Answer**: 
1. **SYN**: Client sends SYN (seq=x) to initiate connection
2. **SYN-ACK**: Server responds with SYN (seq=y) + ACK (ack=x+1)
3. **ACK**: Client sends ACK (ack=y+1), connection established

**Why SOC cares**: Incomplete handshakes = port scans (SYN scan); RST responses = closed ports; half-open connections = potential DoS.

### Q11: What happens during DNS resolution?
**Answer**: 
1. Client checks local cache → hosts file
2. Recursive resolver (ISP/corporate DNS) queries root → TLD → Authoritative
3. Response returns A/AAAA record (IP) to client
4. Client connects to IP

**SOC relevance**: DNS tunneling (data in subdomains), DGA (algorithmic domains), fast flux (rapid IP changes), sinkholing.

### Q12: Difference between TCP and UDP?
**Answer**: 
- **TCP**: Connection-oriented, reliable, ordered, flow control, congestion control. Overhead. Ports: 80, 443, 22, 3389.
- **UDP**: Connectionless, unreliable, no ordering, low latency. Ports: 53 (DNS), 123 (NTP), 161 (SNMP), 500 (IPsec).

**SOC relevance**: UDP = harder to trace, used for DNS, NTP amplification, some C2.

### Q13: What is Kerberos?
**Answer**: Default Windows domain authentication protocol. Uses tickets (TGT, service tickets) instead of sending passwords. Key components: KDC (AS + TGS), SPNs, encryption (AES/RC4). Single sign-on within domain.

### Q14: What is NTLM?
**Answer**: Legacy challenge-response authentication. Used when Kerberos unavailable (local accounts, cross-forest without trust, workgroup). Vulnerable to Pass-the-Hash, Relay. No mutual authentication by default.

### Q15: What is a TGT?
**Answer**: Ticket Granting Ticket. Issued by AS after AS-REQ (user proves identity). Contains user's PAC (groups, SIDs). Used to request service tickets (TGS-REQ) without re-entering password. Lifetime 10h default, renewable 7d.

### Q16: What is a TGS?
**Answer**: Ticket Granting Service (part of KDC). Issues service tickets (ST) when client presents TGT + SPN. Service ticket encrypted with service account's key. Client presents ST to service for access.

### Q17: What is Kerberoasting?
**Answer**: Requesting service tickets (TGS-REQ) for SPNs, then offline cracking the ticket (encrypted with service account's password hash). Targets service accounts with weak passwords. Detection: high volume of 4769 events for SPNs with RC4 encryption.

### Q18: What is Pass-the-Hash?
**Answer**: Using stolen NTLM hash (not password) to authenticate via NTLM. Attacker dumps hash from LSASS (Mimikatz), then uses it for NTLM auth to other systems. Works because NTLM uses hash as secret. Mitigation: restrict NTLM, LAPS, credential guard.

### Q19: What is Golden Ticket?
**Answer**: Forged TGT created with stolen krbtgt hash. Can impersonate any user, any SID history, any lifetime (years). Full domain compromise. Requires DC compromise (DCSync) to get krbtgt hash. Detection: unusual TGT lifetime, injected SID history.

### Q20: What is PowerShell?
**Answer**: Task automation framework with shell and scripting language. Built on .NET. Used by admins AND attackers. Key security features: Script Block Logging (4104), Module Logging (4103), AMSI, Constrained Language Mode, Execution Policy (bypassable).

### Q21: What is Sysmon?
**Answer**: System Monitor (Microsoft Sysinternals). Windows service that logs detailed events to Event Log: Process Create (1), Network (3), File Create (11), Registry (12/13/14), DNS (22), Process Access (10), etc. Critical for EDR/SIEM visibility.

### Q22: What is a process tree?
**Answer**: Visual representation of parent-child process relationships. Shows how a process was spawned (who launched what). Critical for identifying suspicious chains: `winword.exe → powershell.exe → cmd.exe → rundll32.exe`.

### Q23: What is C2 (Command and Control)?
**Answer**: Covert channel attacker uses to communicate with compromised systems. Patterns: beaconing (regular intervals), long-lived connections, domain fronting, encrypted (HTTPS/DNS), peer-to-peer. Detection: periodicity, JA3, rare domains, data volume.

### Q24: What is DNS tunneling?
**Answer**: Abusing DNS protocol to exfiltrate data or establish C2. Encodes data in subdomain queries (TXT/CNAME/MX). Bypasses firewalls since DNS is almost always allowed. Detection: high query volume, long subdomains, unusual record types, entropy in subdomains.

---

## 29.3 Scenario Questions (50+ Realistic)

### Scenario 1
> **"A user has 40 failed logins followed by a successful login from a different country. What do you do?"**

**Strong Answer**:
1. Verify alert: Query 4624/4625 for that user/IP. Confirm pattern.
2. Check source IPs: Geo, reputation, VPN/proxy?
3. Check user baseline: Normal locations, devices, MFA?
4. Check MFA status: Was MFA satisfied for the success?
5. Check subsequent activity: What happened after login? Processes, network, file access?
6. Check for impossible travel: Time between locations physically possible?
7. If compromise confirmed: Reset password, revoke sessions, force MFA re-registration, isolate host if needed, escalate.

**Weak Answer**: "I'd block the IP and reset the password." (Missing investigation, context, MFA check, scope)

**Common Mistake**: Assuming the successful login = compromise without checking MFA or user context. Could be legitimate (VPN, travel).

**Follow-up**: "What if MFA was satisfied?" → Could be MFA fatigue, push bombing, or attacker already enrolled a device. Check MFA enrollment changes.

---

### Scenario 2
> **"PowerShell executed with an encoded command. What do you investigate?"**

**Strong Answer**:
1. Decode the base64 command (`echo <encoded> | base64 -d`)
2. Analyze decoded command: download cradle? obfuscation? AMSI bypass?
3. Check process context: Parent process (Office? Explorer? svchost?), user, host role
4. Check network: Did it make outbound connections? To where? Reputation?
5. Check file activity: Files created/modified? Persistence?
6. Check EDR behavior: Any detections? Tampering?
7. Check prevalence: Same command on other hosts? (Baseline = FP?)

**Weak Answer**: "Encoded PowerShell is always bad, I'd isolate the host."

**Common Mistake**: Not decoding the command. Legitimate admin scripts sometimes use -enc. Windows Update uses encoded PS at startup.

**Follow-up**: "Parent is svchost.exe at 7am." → Likely Windows Update maintenance (FP). Check baseline across fleet.

---

### Scenario 3
> **"winword.exe spawned powershell.exe. What does this suggest?"**

**Strong Answer**: Highly suspicious. Office applications should not spawn scripting interpreters. Classic macro malware pattern. Investigate: command line, what PowerShell did, file source (email attachment?), network connections, persistence. Check email gateway for the attachment.

**Weak Answer**: "It's malware, isolate immediately." (Missing investigation steps, could be legitimate add-in)

**Common Mistake**: Not checking if it's a signed/approved add-in. Some legitimate Office add-ins use PowerShell.

**Follow-up**: "What if the command line is empty?" → Could be process hollowing or AMSI bypass. Check EDR for memory injection.

---

### Scenario 4
> **"An endpoint communicates with a known malicious IP every 60 seconds. What do you do?"**

**Strong Answer**:
1. Confirm beaconing: Regular interval, same size, duration
2. Identify process: What process on the endpoint? (EDR process+network correlation)
3. Check process legitimacy: Signed? Known good? Masquerading?
4. Block IP at firewall/proxy (pre-approved)
5. Isolate host if high confidence (EDR network quarantine)
6. Capture memory if capability exists
7. Trace initial infection: How did malware get there?
8. Escalate to L2

**Weak Answer**: "Block the IP and close the alert."

**Common Mistake**: Not identifying the process. Blocking IP doesn't remove malware from host.

**Follow-up**: "Process is 'svchost.exe' but from AppData." → Masquerading. Real svchost is in System32.

---

### Scenario 5
> **"An admin account logs in from two countries within 10 minutes. What do you investigate?"**

**Strong Answer**:
1. Impossible travel check: Physically possible?
2. Check both logins: MFA status, device, app, location, IP reputation
3. Check for MFA bypass: Push bombing, new MFA method enrolled?
4. Check session activity: What did each session access? Data accessed?
5. Check for token theft: Pass-the-cookie, session hijacking?
4. If compromise: Revoke all sessions, reset password, remove attacker MFA, re-enroll
5. Escalate CRITICAL (admin account)

**Weak Answer**: "Block both IPs and reset password."

**Common Mistake**: Not checking if MFA was satisfied on BOTH. Could be legitimate (VPN exit in different country) or MFA fatigue.

**Follow-up**: "What if one login used MFA push and the other used password only?" → Conditional Access gap or legacy auth protocol (IMAP/SMTP/POP).

---

### Scenario 6
> **"An EDR alert says 'Ransomware behavior detected.' What is your first action?"**

**Strong Answer**: **ISOLATE THE HOST IMMEDIATELY** (pre-approved action for ransomware). Then: verify encryption in progress, alert L2/L3, check scope (file shares), identify ransomware family (ransom note, extension), preserve evidence.

**Weak Answer**: "Investigate first to confirm."

**Common Mistake**: Delaying containment to investigate. Every minute = more files encrypted.

**Follow-up**: "What if it's a false positive?" → Better to isolate and verify than let ransomware spread. Isolation is reversible.

---

### Scenario 7
> **"You see Event ID 4625 with SubStatus 0xC000006A. What does this mean?"**

**Answer**: 0xC000006A = "Wrong password" (STATUS_WRONG_PASSWORD). Other common codes: 0xC0000064 = user doesn't exist, 0xC0000072 = account disabled, 0xC0000193 = account expired, 0xC0000224 = password must change.

---

### Scenario 8
> **"What is the difference between Event ID 4624 Logon Type 3 and Type 10?"**

**Answer**: 
- **Type 3 (Network)**: Network logon — SMB, RPC, IIS, WinRM, scheduled tasks, service accounts
- **Type 10 (RemoteInteractive)**: RDP / Remote Desktop — interactive session with GUI

**SOC relevance**: Type 10 from external IP = external RDP (high risk). Type 3 from external = SMB/WinRM exposure.

---

### Scenario 9
> **"You see a scheduled task created (Event ID 4698) running as SYSTEM with a PowerShell command from AppData. Thoughts?"**

**Answer**: Suspicious persistence. SYSTEM tasks from user context = privilege escalation or malware. PowerShell from AppData = user-writable path. Check: task name, command, creator (EventID 4698 includes creator SID), correlation with other alerts.

---

### Scenario 10
> **"What is the difference between a False Positive and a Benign Positive?"**

**Answer**: 
- **False Positive**: Alert triggered but NO malicious activity occurred (rule too broad, benign behavior matched)
- **Benign Positive** (True Benign): Alert triggered on REAL activity but it's LEGITIMATE (admin script, vulnerability scan, approved tool). Both closed as "not malicious" but Benign Positive = rule worked correctly.

---

### Scenarios 11-50 (Rapid-Fire Key Scenarios)

| # | Scenario | Key Investigation Points |
|---|----------|-------------------------|
| 11 | 4625 → 4624 (success) from same IP | Brute force success? Check MFA, subsequent activity, password reuse |
| 12 | 4769 (TGS) spike for service accounts | Kerberoasting. Check RC4 encryption, SPN enumeration, service account perms |
| 13 | 4768 (TGT) with 20yr lifetime + SID history | Golden Ticket. krbtgt compromise. CRITICAL |
| 14 | 4720 (user created) + 4728 (added to Domain Admins) | Privilege escalation. Who created? When? Legitimate? |
| 15 | 7045 (service installed) unsigned binary in Temp | Malware persistence. Check service path, hash, creator |
| 16 | 4688: cmd.exe /c whoami from service account | Recon. Service account shouldn't run interactive cmds |
| 17 | 4688: rundll32.exe from AppData with DLL | LOLBin execution. Check DLL hash, parent, network |
| 18 | 4688: certutil.exe -decode / -urlcache | LOLBin for download/decode. Check source file, output |
| 19 | 4688: wmic.exe process call create | Lateral movement / execution. Check target, command |
| 20 | 5140 (share access) C$ from workstation | Admin share access. Requires admin rights. Lateral movement |
| 21 | 4624 Type 3 NTLM from unexpected host | Pass-the-Hash. Check source host for compromise |
| 22 | 4672 (special privileges) for standard user | Privilege use. SeDebugPrivilege = can dump LSASS |
| 23 | 1102 (audit log cleared) | Anti-forensics. Who? What else happened? |
| 24 | 4662 (directory access) for krbtgt object | DCSync. DC compromise. CRITICAL |
| 25 | Large outbound from workstation (GB) | Data exfil. Check process, files, destination, compression |
| 26 | DNS queries to single domain, high entropy subs | DNS tunneling. Check process, response data, volume |
| 27 | Beaconing: 60s interval, same bytes, hours | C2. Check process, JA3, destination reputation |
| 28 | PowerShell -enc with IEX download cradle | Malicious execution. Decode, check URL, download |
| 29 | Winword → PowerShell → cmd → certutil | Macro malware chain. Check email source, attachment |
| 30 | Suspicious RDP (Type 10) from external IP | Exposed RDP? Credential theft? Check VPN, MFA |
| 31 | Impossible travel (NY → HK in 1hr) | Account compromise. Check MFA, device, session activity |
| 32 | New MFA method enrolled for admin | Persistence. Check who enrolled, when, from where |
| 33 | EDR: Process injection (remote thread) | Defense evasion. Check source/target process, payload |
| 34 | EDR: LSASS access (OpenProcess) | Credential dumping. Check tool (Mimikatz, comsvcs.dll) |
| 35 | EDR: AMSI bypass attempt | Defense evasion. Check script content, obfuscation |
| 36 | EDR: Disabling Defender/EDR via WMI/PowerShell | Defense evasion. Check who, persistence |
| 37 | Firewall: SMB (445) from internet to DC | Exposure. Should be blocked. Check if succeeded |
| 38 | Proxy: Large POST to unknown domain | Exfil/C2. Check process, user, file source |
| 39 | Email: DMARC fail, SPF fail, credential phishing | Phishing. Check clicks, credential entry, subsequent logins |
| 40 | Email: Malicious attachment, delivered | Email security gap. Check recipients, clicks, execution |
| 41 | CloudTrail: AssumeRole from new IP/geo | Cloud credential theft. Check role perms, subsequent API |
| 42 | CloudTrail: CreateAccessKey for old user | Persistence/credential theft. Check key usage |
| 43 | CloudTrail: ModifySecurityGroup open 0.0.0.0/0:22 | Misconfig/backdoor. Check who, attached instances |
| 44 | CloudTrail: PutBucketPolicy public read | Data exposure. Check bucket contents, duration |
| 45 | Entra ID: Risky sign-in (anon IP, unfamiliar) | Compromise. Check MFA, device, session activity |
| 46 | Linux: SSH key added to authorized_keys | Persistence. Check who, when, from where |
| 47 | Linux: Cron job running curl \| bash | Persistence/malware. Check script content, schedule |
| 48 | Linux: SUID binary in /tmp | Privilege escalation. Check binary, creator |
| 49 | Linux: Process in /dev/shm, deleted exe | Fileless malware. Check memory, network |
| 50 | Multiple alerts on same host/user in 1hr | Campaign. Correlate: initial access → execution → C2 |

---

## 29.4 Interview Answer Framework (STAR Method)

For every scenario question, structure your answer:

```
S - SITUATION: "I'd first verify the alert by querying..."
T - TASK: "My goal is to determine if this is TP/FP and scope"
A - ACTION: "I would check X, then Y, then Z..."
R - RESULT: "Based on findings, I'd escalate/close/contain..."
```

**Always mention**: Evidence collection, containment authority, escalation path, documentation.

---

## 29.5 Common "Trick" Questions

| Question | Trap | Correct Approach |
|----------|------|------------------|
| "What port does DNS use?" | Saying only 53 | "53 UDP for queries, 53 TCP for zone transfers/large responses" |
| "How do you detect Pass-the-Hash?" | "Event ID 4624" | "4624 Type 3 NTLM from unexpected host + no 4624 Type 10 + check source host for LSASS access" |
| "User clicked phishing link. Compromised?" | "Yes" | "Not necessarily. Check: did they enter credentials? MFA? Subsequent anomalous login?" |
| "Ransomware alert. First step?" | "Investigate" | "ISOLATE HOST (pre-approved). Then investigate." |
| "Alert: Encoded PowerShell. Malicious?" | "Yes" | "Decode first. Check parent, time, baseline. Could be Windows Update (FP)." |
| "What's the most important log?" | "Security log" | "Depends on scenario. But for endpoint: Sysmon + EDR telemetry. For auth: Security + IdP." |
| "How do you prioritize alerts?" | "By severity" | "By: 1) Confidence (TP likelihood), 2) Asset criticality, 3) Blast radius, 4) Severity" |

---

## 29.6 Questions to Ask THE Interviewer

Shows engagement and maturity:

1. "What does the L1→L2 escalation process look like here?"
2. "What SIEM/EDR/XDR stack do you use? Any homegrown tools?"
3. "How does the team handle alert fatigue / rule tuning?"
4. "What's the typical shift structure? Follow-the-sun?"
5. "How much autonomy does L1 have for containment actions?"
6. "What does the onboarding/training program look like for new L1s?"
7. "How are false positives tracked and fed back into detection engineering?"
8. "What's the most common attack vector you see in this environment?"

---

## 29.7 Pre-Interview Checklist

**Night Before**:
- [ ] Review this entire module
- [ ] Practice 10 scenario answers out loud (record yourself)
- [ ] Know your resume projects cold (be ready to map to MITRE)
- [ ] Research the company: industry, likely threats, tech stack
- [ ] Prepare 3 questions to ask them

**Day Of**:
- [ ] Bring printed resume + notebook
- [ ] Have a "cheat sheet" mentally: TCP handshake, Kerberos flow, Event IDs, MITRE tactics
- [ ] Calm breathing: you've prepared for this

---

## Summary: What L1 Must Know for Interview

- [ ] 10 fundamental definitions (SOC, SIEM, XDR, MXDR, EDR, MDR, SOAR, IOC/IOA/TTP, MITRE)
- [ ] 15 technical concepts explained clearly (TCP, DNS, Kerberos, NTLM, TGT/TGS, PtH, Kerberoast, Golden Ticket, PowerShell, Sysmon, Process Tree, C2, DNS Tunneling)
- [ ] 50 scenario questions with structured answers
- [ ] STAR method for answering
- [ ] Common trap questions and how to avoid them
- [ ] Smart questions to ask the interviewer