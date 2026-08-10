# Module 18: MITRE ATT&CK

**Priority: P0 — Universal language for threat behavior. L1 maps every alert to ATT&CK.**

---

## 18.1 What is MITRE ATT&CK?

**Adversarial Tactics, Techniques, and Common Knowledge** — Globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

### Core Philosophy
- **Tactics** = *Why* (Goal)
- **Techniques** = *How* (Method)
- **Procedures** = *Specific implementation* (Tool/Code)
- **Sub-techniques** = *Granular variants* (.001, .002, etc.)

### Matrices
| Matrix | Scope | Platforms |
|--------|-------|-----------|
| **Enterprise** | Traditional IT networks | Windows, macOS, Linux, Azure AD, Office 365, Google Workspace, SaaS, IaaS, Network, Containers |
| **Mobile** | Mobile devices | iOS, Android |
| **ICS** | Industrial Control Systems | PLC, RTU, HMI, SCADA, Historian |
| **PRE-ATT&CK** (Deprecated) | Pre-compromise | Recon, Resource Development |

**L1 Focus**: **Enterprise Matrix** (Windows, Linux, Azure AD, Office 365, Network).

---

## 18.2 Enterprise Tactics (14) — In Attack Order

| # | Tactic | ID | Goal | Example Techniques |
|---|--------|----|------|-------------------|
| 1 | **Reconnaissance** | TA0043 | Gather target info | T1590 (Active Scanning), T1598 (Phishing for Info) |
| 2 | **Resource Development** | TA0042 | Build/acquire capabilities | T1583 (Acquire Infrastructure), T1587 (Develop Capabilities) |
| 3 | **Initial Access** | TA0001 | Get into network | T1566 (Phishing), T1190 (Exploit Public App), T1078 (Valid Accounts) |
| 4 | **Execution** | TA0002 | Run malicious code | T1059 (Command/Scripting), T1204 (User Execution), T1106 (Native API) |
| 5 | **Persistence** | TA0003 | Maintain foothold | T1547 (Boot/Logon), T1053 (Scheduled Task), T1543 (Service) |
| 6 | **Privilege Escalation** | TA0004 | Gain higher permissions | T1068 (Exploit), T1134 (Token Manipulation), T1548 (Bypass UAC) |
| 7 | **Defense Evasion** | TA0005 | Avoid detection | T1055 (Process Injection), T1036 (Masquerading), T1562 (Disable Tools) |
| 8 | **Credential Access** | TA0006 | Steal credentials | T1003 (OS Credential Dumping), T1558 (Kerberos), T1550 (Use Alt Auth) |
| 9 | **Discovery** | TA0007 | Learn environment | T1082 (System Info), T1083 (File/Dir), T1018 (Remote System) |
| 10 | **Lateral Movement** | TA0008 | Move through network | T1021 (Remote Services), T1550 (Alt Auth), T1080 (Taint Shared) |
| 11 | **Collection** | TA0009 | Gather data of interest | T1005 (Local System), T1039 (Network Shares), T1114 (Email) |
| 12 | **Command & Control** | TA0011 | Communicate with controlled systems | T1071 (App Layer Protocol), T1090 (Proxy), T1573 (Encrypted Channel) |
| 13 | **Exfiltration** | TA0010 | Steal data | T1567 (Web Service), T1041 (C2 Channel), T1048 (Alt Protocol) |
| 14 | **Impact** | TA0040 | Manipulate/destroy | T1486 (Data Encrypted), T1485 (Data Destruction), T1529 (Shutdown) |

---

## 18.3 Critical Techniques for L1 — Must Know Cold

### Initial Access (TA0001)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Phishing** | T1566 | .001 Spearphishing Attachment, .002 Spearphishing Link, .003 Spearphishing via Service | Email gateway, User report, Sandbox, EDR (Office→Script) |
| **Exploit Public-Facing App** | T1190 | — | WAF, NDA, App logs, Vuln scan correlation |
| **Valid Accounts** | T1078 | .001 Default, .002 Domain, .003 Local, .004 Cloud | Auth logs (impossible travel, MFA bypass, new device) |
| **External Remote Services** | T1133 | VPN, Citrix, RDP Gateway | VPN logs, MFA logs, Geo/IP reputation |
| **Drive-by Compromise** | T1189 | — | Proxy, EDR (browser exploit), Threat intel |
| **Supply Chain** | T1195 | .001 Compromise Software, .002 Compromise Hardware | Hash verification, Vendor advisory, SBOM |
| **Trusted Relationship** | T1199 | — | Third-party access logs, Contract review |

### Execution (TA0002)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Command & Scripting Interpreter** | T1059 | .001 PowerShell, .002 AppleScript, .003 Windows CMD, .004 Unix Shell, .005 Visual Basic, .006 Python, .007 JavaScript/JScript | **EDR (process tree), 4688, Sysmon EID 1, 4104 (PS), AMSI** |
| **User Execution** | T1204 | .001 Malicious Link, .002 Malicious File | Email gateway, Proxy, EDR, User report |
| **Scheduled Task/Job** | T1053 | .005 Scheduled Task, .003 Cron, .006 Systemd Timer | 4698, Sysmon EID 1/4/5, cron logs |
| **Native API** | T1106 | — | EDR (API monitoring), ETW |
| **Inter-Process Communication** | T1559 | .001 DCOM, .002 Port Monitors | Sysmon EID 8/10, EDR |
| **System Services** | T1569 | .001 Launchctl, .002 Systemd | Service logs, EDR |

### Persistence (TA0003) — **High-Value Detections**
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Boot/Logon Autostart** | T1547 | .001 Registry Run Keys, .002 Startup Folder, .003 Shortcut Modification, .004 Winlogon, .005 Services, .006 Kernel Modules | Sysmon EID 11/12/13, 4657, 7045, EDR |
| **Scheduled Task/Job** | T1053 | .005 Scheduled Task, .003 Cron | 4698, Sysmon EID 1, cron |
| **Create/Modify System Process** | T1543 | .003 Windows Service, .002 Systemd | 7045, Sysmon EID 4, systemd |
| **Event Triggered Execution** | T1546 | .003 WMI, .007 .NET Profiler, .008 Accessibility, .011 AppInit, .012 Image Hijack, .015 Component Firmware | Sysmon EID 19/20/21, 4657, EDR |
| **Hijack Execution Flow** | T1574 | .001 DLL Search Order, .002 DLL Side-Loading, .004 Dylib Hijacking | Sysmon EID 7/11, EDR |
| **Account Manipulation** | T1098 | .001 Additional Cloud Credentials, .003 Additional Email Delegates | AD/Entra ID audit logs |

### Privilege Escalation (TA0004)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Exploitation for Privilege Escalation** | T1068 | — | EDR (exploit behavior), Patch status |
| **Access Token Manipulation** | T1134 | .001 Token Impersonation, .002 Create Process with Token, .003 Make/Impersonate Token, .004 Parent PID Spoofing | Sysmon EID 8/10, EDR (token APIs), 4672 |
| **Abuse Elevation Control** | T1548 | .002 Bypass UAC, .003 Sudo, .004 Elevated Execution with Prompt | Sysmon EID 1 (High IL from Medium), EDR |

### Defense Evasion (TA0005) — **Critical for EDR**
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Process Injection** | T1055 | .001 Dynamic-link Library, .002 Portable Executable, .003 Thread Execution, .004 Asynchronous Procedure Call, .005 Thread Local Storage, .008 Process Hollowing, .009 Process Doppelgänging, .011 Process Herpaderping, .012 Process Ghosting | **Sysmon EID 8/10/25, EDR (memory APIs, RWX)** |
| **Masquerading** | T1036 | .001 Invalid Code Signature, .002 Right-to-Left Override, .003 Rename System Utilities, .004 Masquerade Task/Service, .005 Match Legitimate Name/Location | Sysmon EID 1 (OriginalFileName), EDR |
| **Disable/Modify Tools** | T1562 | .001 Disable Security Tools, .002 Disable Windows Event Logging, .003 Impair Defenses, .004 Disable Syslog, .007 Modify Registry | 1102, 4719, 4657, Sysmon EID 12/13, EDR (tamper alerts) |
| **Indicator Removal** | T1070 | .001 Clear Windows Event Logs, .002 Clear Linux Logs, .004 File Deletion, .006 Timestomp | 1102, Sysmon EID 2/23, EDR |
| **Obfuscated/Stored Files** | T1027 | .001 Binary Padding, .002 Software Packing, .003 Steganography, .004 Compile After Delivery, .005 HTML Smuggling | Static analysis (entropy, packer), EDR |
| **Subvert Trust Controls** | T1553 | .001 Code Signing, .002 SIP/Trust Provider, .003 Install Root Cert, .004 Code Signing Policy | Cert logs, EDR |

### Credential Access (TA0006) — **Crown Jewels**
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **OS Credential Dumping** | T1003 | .001 LSASS Memory, .002 SAM, .003 NTDS, .004 LSA Secrets, .005 Cached Creds, .006 DCSync, .008 /etc/passwd & /etc/shadow | **Sysmon EID 10 (LSASS), EDR, 4624/4672, NTDS.dit access** |
| **Kerberoasting** | T1558 | .003 Kerberoasting | 4769 (RC4), EDR, BloodHound |
| **AS-REP Roasting** | T1558 | .004 AS-REP Roasting | 4768 (no pre-auth), 4771 |
| **Pass the Hash** | T1550 | .002 Pass the Hash | 4624 Type 3/9, 4776, NDR (SMB) |
| **Pass the Ticket** | T1550 | .003 Pass the Ticket | 4624 Type 9, Kirbi files, EDR |
| **Golden/Silver Ticket** | T1550 | .001 Golden Ticket, .002 Silver Ticket | 4768/4769 anomalies, krbtgt age |
| **Unsecured Credentials** | T1552 | .001 Credentials in Files, .002 Registry, .003 Bash History, .004 Private Keys | EDR (file/reg access), Git secrets |

### Discovery (TA0007)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **System Information Discovery** | T1082 | — | EDR (systeminfo, whoami, hostname) |
| **File and Directory Discovery** | T1083 | — | EDR (dir, ls, Get-ChildItem) |
| **System Network Configuration** | T1016 | .001 Internet Connection Discovery | EDR (ipconfig, ifconfig, netsh) |
| **Remote System Discovery** | T1018 | — | EDR (net view, nmap, AD Find) |
| **Account Discovery** | T1087 | .001 Domain Account, .002 Local Account, .003 Email Account, .004 Cloud Account | EDR (net user, Get-ADUser, Graph API) |
| **Permission Groups Discovery** | T1069 | .001 Local Groups, .002 Domain Groups, .003 Cloud Groups | EDR (net localgroup, Get-ADGroupMember) |
| **Network Share Discovery** | T1135 | — | EDR (net share, SMB enumeration) |

### Lateral Movement (TA0008)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Remote Services** | T1021 | .001 RDP, .002 SMB/Windows Admin Shares, .003 Distributed Component Object Model, .004 SSH, .005 VNC, .006 WinRM | 4624 Type 10/3, Sysmon EID 3, NDR (SMB/RDP/RPC/WinRM) |
| **Lateral Tool Transfer** | T1570 | — | Sysmon EID 11 (copy), NDR (SMB write), EDR |
| **Use Alternate Authentication Material** | T1550 | .001 Pass the Hash, .002 Pass the Ticket, .003 Web Session Cookie | As above |

### Collection (TA0009)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Data from Local System** | T1005 | — | EDR (file reads, staging) |
| **Data from Network Shares** | T1039 | — | NDR (SMB read), File audit (4663) |
| **Data from Information Repositories** | T1213 | .001 Confluence, .002 SharePoint | Cloud logs, EDR |
| **Email Collection** | T1114 | .001 Local Email Collection, .002 Remote Email Collection | EDR (MAPI, OWA, Graph API), Mailbox audit |
| **Archive Collected Data** | T1560 | .001 Archive via Utility, .002 Archive via Library | EDR (7z, rar, tar, zip, Compress-Archive) |

### Command & Control (TA0011)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Application Layer Protocol** | T1071 | .001 Web Protocols, .002 File Transfer, .003 Mail, .004 DNS, .005 SMB/Windows Admin Shares | Proxy, DNS logs, NDR, EDR netconns |
| **Proxy** | T1090 | .001 Internal, .002 External, .003 Multi-hop, .004 Domain Fronting | NDR, Proxy logs |
| **Encrypted Channel** | T1573 | .001 Symmetric, .002 Asymmetric | JA3/JA3S, TLS cert analysis |
| **Ingress Tool Transfer** | T1105 | — | EDR (download), Proxy, Sysmon EID 3/11 |
| **Dynamic Resolution** | T1568 | .001 Fast Flux, .002 Domain Generation Algorithms, .003 DNS Calculation | DNS logs, NDR |

### Exfiltration (TA0010)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Exfiltration Over Web Service** | T1567 | .001 Exfil to Code Repository, .002 Exfil to Cloud Storage | Proxy, Cloud logs, DLP |
| **Exfiltration Over C2 Channel** | T1041 | — | NDR, EDR netconns |
| **Exfiltration Over Alternative Protocol** | T1048 | .001 Exfil over DNS, .002 Exfil over SMB | DNS logs, NDR |

### Impact (TA0040)
| Technique | ID | Sub-techniques | Detection |
|-----------|----|----------------|-----------|
| **Data Encrypted for Impact** | T1486 | — | EDR (mass file modify, entropy, ransom notes) |
| **Data Destruction** | T1485 | — | EDR (mass delete, wiper) |
| **Inhibit System Recovery** | T1490 | .001 Disable Backup, .002 Delete Shadow Copies | EDR (vssadmin, wbadmin, bcdedit) |
| **Service Stop** | T1489 | — | EDR (net stop, sc stop) |
| **System Shutdown/Reboot** | T1529 | — | EDR (shutdown, reboot) |

---

## 18.4 MITRE Mapping Workflow for L1

```
ALERT TRIAGED AS TRUE POSITIVE
            │
            ▼
┌─────────────────────────────────────────┐
│  IDENTIFY OBSERVED BEHAVIORS            │
│  - Process tree: WINWORD → POWERSHELL   │
│  - Command: -enc DownloadString         │
│  - Network: HTTP to malicious.com       │
│  - File: %TEMP%\payload.exe created     │
│  - Persistence: Run key added           │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│  MAP TO TECHNIQUES (Use ATT&CK Navigator)│
│  - T1566.001 (Phishing Attachment)      │
│  - T1059.001 (PowerShell)               │
│  - T1105 (Ingress Tool Transfer)        │
│  - T1071.001 (HTTP C2)                  │
│  - T1547.001 (Registry Run Key)         │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│  MAP TO TACTICS                         │
│  - Initial Access (TA0001)              │
│  - Execution (TA0002)                   │
│  - Persistence (TA0003)                 │
│  - Command & Control (TA0011)           │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│  DOCUMENT IN CASE                       │
│  - Technique IDs + Names                │
│  - Evidence per technique               │
│  - Confidence (Observed/Inferred)       │
│  - MITRE ATT&CK Navigator Layer URL     │
└─────────────────────────────────────────┘
```

---

## 18.5 ATT&CK Navigator — Visualization

### Creating a Layer
1. Go to https://attack.mitre.org/ (or internal instance)
2. Select **Enterprise** matrix
3. Click **Create Layer** → **New Layer**
4. **Search/Select** techniques from your investigation
5. **Color-code**:
   - **Red** = Observed (direct evidence)
   - **Orange** = Inferred (strong indicator)
   - **Yellow** = Possible (weak indicator)
   - **Green** = Not observed (coverage gap)
6. **Add Metadata**: Case ID, Analyst, Date, Confidence
7. **Export** → JSON (for case attachment) / SVG (for report)

### Example Layer for Phishing → C2
```json
{
  "name": "INC-2024-001234 - Phishing to C2",
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1566.001", "score": 100, "comment": "Malicious .docm delivered via email"},
    {"techniqueID": "T1059.001", "score": 100, "comment": "PowerShell -enc DownloadString"},
    {"techniqueID": "T1105", "score": 100, "comment": "Payload downloaded from malicious.com"},
    {"techniqueID": "T1071.001", "score": 100, "comment": "HTTP C2 beaconing"},
    {"techniqueID": "T1547.001", "score": 80, "comment": "Run key persistence (inferred)"}
  ],
  "gradient": {"colors": ["#ff6666","#ffcc66","#ffff66","#66ff66"], "minValue": 0, "maxValue": 100}
}
```

---

## 18.6 Detection Coverage & Gap Analysis

### Coverage Mapping
| Tactic | Techniques | Covered (EDR/SIEM/NDR) | Gaps |
|--------|------------|------------------------|------|
| **Initial Access** | 9 | Phishing (EDR/Email), Valid Accts (Auth) | Supply Chain, Drive-by |
| **Execution** | 12 | PS/CMD (EDR/4104), Scheduled Task (4698) | Native API, IPC |
| **Persistence** | 19 | Run Keys (Sysmon), Tasks (4698), Services (7045) | WMI, COM, Bootkit |
| **Priv Esc** | 13 | Token Manip (EDR), UAC Bypass (EDR) | Kernel Exploit |
| **Defense Evasion** | 42 | Process Inj (EDR/Sysmon), Masquerade (Sysmon), Log Clear (1102) | Unhooking, Certs |
| **Cred Access** | 16 | LSASS (EDR/Sysmon), Kerberoast (4769), PtH (Auth) | DCSync, Keys |
| **Discovery** | 30 | System/Network/Account (EDR) | Cloud, Container |
| **Lateral** | 9 | SMB/RDP/WinRM (NDR/Auth) | DCOM, SSH Keys |
| **Collection** | 17 | Local/Shares/Email (EDR/NDR) | Cloud Repos |
| **C2** | 16 | HTTP/DNS (Proxy/NDR/EDR), Proxy | Domain Fronting |
| **Exfil** | 9 | Web/Cloud/C2 (Proxy/NDR/DLP) | Physical, Alt Proto |
| **Impact** | 13 | Ransomware (EDR), Wiper (EDR) | Firmware |

**L1 Task**: Know your org's coverage. Flag gaps in escalation.

---

## 18.7 Interview Questions for This Module

1. **What are the 14 Enterprise ATT&CK Tactics in order?**
   - Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact.

2. **Explain the difference between Tactic, Technique, Sub-technique, and Procedure.**
   - Tactic: Goal (Why). Technique: Method (How). Sub-technique: Granular variant (.001). Procedure: Specific implementation (Tool/Code).

3. **What are the top 5 techniques L1 analysts should know for Initial Access?**
   - T1566 (Phishing), T1190 (Exploit Public App), T1078 (Valid Accounts), T1133 (External Remote Services), T1189 (Drive-by).

4. **How do you map an alert to MITRE ATT&CK?**
   - Identify observed behaviors → Map each to Technique ID → Group by Tactic → Document evidence + confidence → Create Navigator layer.

5. **What is the difference between "Observed" and "Inferred" in ATT&CK mapping?**
   - Observed: Direct evidence (logs show PowerShell -enc). Inferred: Strong indicator but not directly logged (persistence likely but not seen).

6. **What is ATT&CK Navigator and how do you use it?**
   - Web tool to visualize coverage/mapping. Create layer → Select techniques → Color-code (Observed/Inferred/Possible) → Add metadata → Export JSON/SVG.

7. **Name 5 Defense Evasion techniques with high detection value.**
   - T1055 (Process Injection), T1036 (Masquerading), T1562.001 (Disable Security Tools), T1070.001 (Clear Logs), T1027 (Obfuscation/Packing).

8. **What is the Credential Access tactic and its crown jewel technique?**
   - Stealing credentials. Crown jewel: T1003.001 (LSASS Memory Dumping) — leads to lateral movement, privilege escalation.

9. **How does ATT&CK help with detection gap analysis?**
   - Map existing detections to Techniques → Identify uncovered Techniques per Tactic → Prioritize gap closure by risk/prevalence.

10. **What are the four ATT&CK Matrices and which is primary for L1?**
    - Enterprise (Windows, Linux, Cloud, SaaS, Network), Mobile (iOS/Android), ICS (OT), PRE (deprecated). **Enterprise** is primary for L1.

---

## 18.8 Study Checklist for Module 18

- [ ] Recite 14 Enterprise Tactics in order with IDs
- [ ] Explain Tactic vs Technique vs Sub-technique vs Procedure
- [ ] List top 5 techniques for each tactic (Initial Access through Impact)
- [ ] Map sample alert to MITRE (behaviors → techniques → tactics)
- [ ] Create ATT&CK Navigator layer (JSON export)
- [ ] Perform detection coverage gap analysis for your org
- [ ] Identify "Crown Jewel" techniques per tactic (LSASS, Process Injection, etc.)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 19 — Common Attacks*