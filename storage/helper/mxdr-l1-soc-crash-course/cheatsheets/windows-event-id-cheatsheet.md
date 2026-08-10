# Windows Event ID Cheat Sheet for SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## Authentication Events

| Event ID | Name | Description | Key Fields | SOC Relevance |
|----------|------|-------------|------------|---------------|
| **4624** | Logon Success | Successful logon | LogonType, User, SourceIP, Workstation, AuthPackage | Baseline, anomaly detection, lateral movement |
| **4625** | Logon Failure | Failed logon | SubStatus, User, SourceIP, LogonType | Brute force, password spray, credential stuffing |
| **4634** | Logoff | User logoff | LogonType, User | Session duration, session tracking |
| **4647** | User Logoff | User-initiated logoff | User | Clean session termination |
| **4672** | Special Privileges | Admin privileges assigned | User, Privileges (SeDebug, SeAssignPrimaryToken) | Privilege escalation, admin activity |
| **4768** | Kerberos TGT Request | AS-REQ (TGT request) | User, ServiceName, TicketOptions, TicketEncryptionType | Kerberos authentication, TGT anomalies |
| **4769** | Kerberos TGS Request | TGS-REQ (Service ticket) | User, ServiceName, TicketOptions, TicketEncryptionType | Kerberoasting (RC4), service enumeration |
| **4771** | Kerberos Pre-Auth Failed | Pre-authentication failed | User, FailureCode (0x18 = bad password) | Kerberos brute force, AS-REP roasting |
| **4776** | NTLM Auth Attempt | NTLM authentication (domain controller) | User, SourceIP, Status | NTLM usage, Pass-the-Hash detection |

---

## Process & Execution Events

| Event ID | Name | Description | Key Fields | SOC Relevance |
|----------|------|-------------|------------|---------------|
| **4688** | Process Creation | New process created | NewProcessName, CommandLine, CreatorProcessID, ParentProcessName, TokenElevationType, MandatoryLabel | **Critical** — process trees, command lines, LOLBins |
| **4689** | Process Termination | Process exited | ProcessName, ProcessID | Process lifecycle |
| **4698** | Scheduled Task Created | Task registered | TaskName, TaskContent (XML), User | Persistence, privilege escalation |
| **4699** | Scheduled Task Deleted | Task deleted | TaskName, User | Anti-forensics, cleanup |
| **4700** | Scheduled Task Enabled | Task enabled | TaskName, User | Persistence activation |
| **4701** | Scheduled Task Disabled | Task disabled | TaskName, User | Defense evasion |
| **4702** | Scheduled Task Updated | Task modified | TaskName, TaskContent, User | Persistence modification |

---

## Account Management

| Event ID | Name | Description | Key Fields | SOC Relevance |
|----------|------|-------------|------------|---------------|
| **4720** | User Account Created | New user | TargetUserName, SubjectUserName | Unauthorized account creation |
| **4722** | User Account Enabled | Account enabled | TargetUserName, SubjectUserName | Reactivation of disabled accounts |
| **4723** | Password Change Attempt | Password change | TargetUserName, SubjectUserName | Password reset abuse |
| **4724** | Password Reset | Password reset by admin | TargetUserName, SubjectUserName | Admin password reset (legit or compromise) |
| **4725** | User Account Disabled | Account disabled | TargetUserName, SubjectUserName | Legitimate offboarding or attack |
| **4726** | User Account Deleted | Account deleted | TargetUserName, SubjectUserName | Cover-up, anti-forensics |
| **4728** | Group Member Added | Added to security group | TargetUserName, GroupName, SubjectUserName | **Privilege escalation** (Domain Admins, etc.) |
| **4729** | Group Member Removed | Removed from group | TargetUserName, GroupName | Privilege reduction or cleanup |
| **4732** | Group Member Added (Local) | Added to local group | TargetUserName, GroupName | Local admin escalation |
| **4738** | User Account Changed | Account modified | TargetUserName, Changes | Account manipulation |
| **4740** | User Account Locked Out | Account lockout | TargetUserName, LockoutDuration | Brute force indicator |

---

## System & Service Events

| Event ID | Name | Description | Key Fields | SOC Relevance |
|----------|------|-------------|------------|---------------|
| **7045** | Service Installed | New service installed | ServiceName, ServiceFileName, ServiceType, StartType | **Persistence** (malicious services), living-off-the-land |
| **7036** | Service State Change | Service started/stopped | ServiceName, State | Service manipulation |
| **7040** | Service Config Changed | Service config modified | ServiceName, Changes | Service hijacking |
| **1074** | System Shutdown/Restart | Shutdown initiated | User, ReasonCode | Unexpected reboots, anti-forensics |
| **6005** | Event Log Service Started | Log service start | — | System boot |
| **6006** | Event Log Service Stopped | Log service stop | — | System shutdown or log tampering |
| **6008** | Unexpected Shutdown | Previous shutdown unexpected | — | Crash, power loss, forced reboot |
| **6009** | Windows Version | OS version at boot | Version, Build | Asset inventory |
| **6013** | System Uptime | Uptime at event log start | Uptime | System availability |

---

## Audit & Policy

| Event ID | Name | Description | Key Fields | SOC Relevance |
|----------|------|-------------|------------|---------------|
| **1102** | Audit Log Cleared | Security log cleared | SubjectUserName | **Anti-forensics**, evidence destruction |
| **4719** | Audit Policy Changed | System audit policy modified | Changes, SubjectUserName | Defense evasion, logging reduction |
| **4907** | Object Audit Settings Changed | SACL modified on object | ObjectName, SubjectUserName | Selective logging evasion |

---

## Logon Types (Critical for 4624/4625)

| Type | Name | Description | Typical Source |
|------|------|-------------|----------------|
| **2** | Interactive | Local keyboard/mouse | Physical access, console |
| **3** | Network | Network logon (SMB, RPC, WinRM, IIS) | File shares, remote admin, web apps |
| **4** | Batch | Scheduled task | Task Scheduler |
| **5** | Service | Service account | Windows services |
| **7** | Unlock | Workstation unlock | Screen unlock |
| **8** | NetworkCleartext | Network with cleartext creds | IIS basic auth, FTP |
| **9** | NewCredentials | RunAs /netonly | RunAs with different creds |
| **10** | RemoteInteractive | RDP / Terminal Services | **Remote Desktop** |
| **11** | CachedInteractive | Cached credentials | Offline logon (laptop) |

---

## SubStatus Codes (4625 Failure Reasons)

| Code | Meaning | Description |
|------|---------|-------------|
| **0xC000006A** | STATUS_WRONG_PASSWORD | Bad password (most common) |
| **0xC0000064** | STATUS_NO_SUCH_USER | User doesn't exist |
| **0xC000006D** | STATUS_LOGON_FAILURE | Generic failure (bad user OR password) |
| **0xC000006E** | STATUS_ACCOUNT_RESTRICTION | Logon restriction (time, workstation) |
| **0xC000006F** | STATUS_INVALID_LOGON_HOURS | Outside allowed hours |
| **0xC0000070** | STATUS_INVALID_WORKSTATION | Not allowed from this workstation |
| **0xC0000071** | STATUS_PASSWORD_EXPIRED | Password expired |
| **0xC0000072** | STATUS_ACCOUNT_DISABLED | Account disabled |
| **0xC000009A** | STATUS_INSUFFICIENT_RESOURCES | Server resources low |
| **0xC0000193** | STATUS_ACCOUNT_EXPIRED | Account expired |
| **0xC0000224** | STATUS_PASSWORD_MUST_CHANGE | Password change required |
| **0xC0000234** | STATUS_ACCOUNT_LOCKED_OUT | Account locked out |

---

## PowerShell Event IDs (Requires Logging Enabled)

| Event ID | Log Source | Description |
|----------|------------|-------------|
| **4103** | Microsoft-Windows-PowerShell/Operational | Module Logging (module loaded) |
| **4104** | Microsoft-Windows-PowerShell/Operational | **Script Block Logging** (full script content) |
| **4105** | Microsoft-Windows-PowerShell/Operational | Script Block Logging (start/stop) |
| **4106** | Microsoft-Windows-PowerShell/Operational | Script Block Logging (detailed) |
| **800** | Microsoft-Windows-PowerShell/Operational | Pipeline execution detail |
| **400** | Microsoft-Windows-PowerShell/Operational | Engine state (start/stop) |

---

## Sysmon Event IDs (If Deployed)

| Event ID | Name | Description | Key Fields |
|----------|------|-------------|------------|
| **1** | Process Create | Process creation (richer than 4688) | Image, CommandLine, ParentImage, ParentCommandLine, User, IntegrityLevel, Hashes (MD5, SHA256, IMPHASH) |
| **2** | File Creation Time | File creation time changed | TargetFilename, CreationUtcTime |
| **3** | Network Connection | TCP/UDP connection | Image, SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol |
| **4** | Sysmon Service State | Sysmon start/stop | State |
| **5** | Process Terminated | Process ended | Image, ProcessId |
| **6** | Driver Load | Kernel driver loaded | Image, Hashes |
| **7** | Image Load | DLL loaded | Image, Hashes |
| **8** | CreateRemoteThread | Thread created in another process | SourceImage, TargetImage, StartAddress |
| **9** | RawAccessRead | Raw disk read | Image, TargetDevice |
| **10** | ProcessAccess | Process opened (e.g., LSASS) | SourceImage, TargetImage, GrantedAccess |
| **11** | File Create | File created | TargetFilename, Image, CreationUtcTime |
| **12** | Registry Event (Create/Delete) | Registry key/value create/delete | TargetObject, Details |
| **13** | Registry Event (Value Set) | Registry value modified | TargetObject, Details |
| **14** | Registry Event (Key/Value Rename) | Registry renamed | TargetObject, NewName |
| **15** | File Create Stream Hash | File stream hash (ADS) | TargetFilename, Hashes |
| **16** | Sysmon Config Change | Config modified | — |
| **17** | Pipe Event | Named pipe created/connected | PipeName, Image |
| **18** | DNS Query | DNS resolution | QueryName, QueryType, QueryResults, Image |
| **19** | WMI Event | WMI filter/consumer binding | Filter, Consumer |
| **20** | WMI Activity | WMI event triggered | — |
| **21** | WMI Activity (Consumer) | WMI consumer action | — |
| **22** | DNS Query (v2) | Enhanced DNS logging | QueryName, QueryType, QueryResults, Image, User |
| **23** | File Delete | File deleted | TargetFilename, Image |
| **24** | Clipboard Change | Clipboard content changed | Image, DataType |
| **25** | Process Tampering | Process image tampering | Image, TargetImage |
| **26** | File Delete Detected | File delete detected via USN | TargetFilename |

---

## Quick Reference: Top 20 Must-Know Event IDs

| Priority | Event ID | Why Critical |
|----------|----------|--------------|
| **1** | 4624 | All successful logons |
| **2** | 4625 | All failed logons |
| **3** | 4688 | Process execution (command lines!) |
| **4** | 4672 | Privilege assignment |
| **5** | 4698 | Scheduled task persistence |
| **6** | 4720 | Account creation |
| **7** | 4728 | Group membership (privilege escalation) |
| **8** | 4768 | Kerberos TGT (AS-REQ) |
| **9** | 4769 | Kerberos TGS (TGS-REQ) |
| **10** | 4771 | Kerberos pre-auth failure |
| **11** | 4776 | NTLM authentication |
| **12** | 7045 | Service installation (persistence) |
| **13** | 1102 | Log clearing (anti-forensics) |
| **14** | 4104 | PowerShell script block logging |
| **15** | 4625 (SubStatus) | Failure reason codes |
| **16** | 4624 (LogonType) | Logon type classification |
| **17** | 5140 | Share access (lateral movement) |
| **18** | 4662 | Directory service access (DCSync) |
| **19** | 4703 | Token rights adjusted |
| **20** | 4964 | Special groups assigned to logon |

---

## KQL Quick Queries for Top Event IDs

```kql
// All authentication events (success + failure)
SecurityEvent
| where EventID in (4624, 4625)
| where TimeGenerated > ago(4h)

// Process creation with command lines
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(4h)
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName

// Scheduled task creation
SecurityEvent
| where EventID == 4698
| where TimeGenerated > ago(24h)

// Service installation
SecurityEvent
| where EventID == 7045
| where TimeGenerated > ago(24h)

// Log clearing
SecurityEvent
| where EventID == 1102
| where TimeGenerated > ago(24h)

// Kerberoasting (TGS requests for SPNs with RC4)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == 0x17  // RC4
| where ServiceName has "@"  // SPN format
| where TimeGenerated > ago(4h)
```

---

## SPL Quick Queries for Top Event IDs

```spl
# All auth events
index=winevents sourcetype=xmlwineventlog (EventCode=4624 OR EventCode=4625) earliest=-4h

# Process creation
index=winevents sourcetype=xmlwineventlog EventCode=4688 earliest=-4h
| table _time, Computer, Account, NewProcessName, CommandLine, ParentProcessName

# Scheduled tasks
index=winevents sourcetype=xmlwineventlog EventCode=4698 earliest=-24h

# Service installs
index=winevents sourcetype=xmlwineventlog EventCode=7045 earliest=-24h

# Log clearing
index=winevents sourcetype=xmlwineventlog EventCode=1102 earliest=-24h

# Kerberoasting
index=winevents sourcetype=xmlwineventlog EventCode=4769 TicketEncryptionType=0x17 earliest=-4h
| where like(ServiceName, "%@%")
```

---

## Print-Friendly One-Pager

```
WINDOWS EVENT ID QUICK REFERENCE (SOC L1)
=========================================

AUTHENTICATION:
4624  = Logon SUCCESS        (LogonType: 2=Interactive, 3=Network, 10=RDP)
4625  = Logon FAILURE        (SubStatus: 0xC000006A=BadPwd, 0xC0000064=NoUser)
4634  = Logoff
4672  = Special Privileges   (SeDebugPrivilege = LSASS dump risk)
4768  = Kerberos AS-REQ      (TGT request)
4769  = Kerberos TGS-REQ     (Service ticket - Kerberoasting if RC4 + SPN)
4771  = Kerberos Pre-Auth Fail
4776  = NTLM Auth (DC)

PROCESS/EXECUTION:
4688  = Process Create       (CommandLine! ParentProcess! Critical!)
4698  = Scheduled Task Created  (Persistence!)
4702  = Scheduled Task Updated
7045  = Service Installed    (Persistence!)

ACCOUNT MGMT:
4720  = User Created
4728  = Added to Group       (Domain Admins = ESCALATION)
4732  = Added to Local Group
4740  = Account Locked Out

SYSTEM:
1102  = Audit Log Cleared    (ANTI-FORENSICS!)
7045  = Service Install

POWERSHELL (Enable Logging!):
4104  = Script Block Logging (FULL script content)
4103  = Module Logging

SYSMON (If Available):
1   = Process Create (Hashes! Parent cmdline! Integrity!)
3   = Network Connection
10  = Process Access (LSASS = 0x1010 = OpenProcess)
11  = File Create
13  = Registry Value Set
22  = DNS Query

LOGON TYPES:
2=Interactive  3=Network  4=Batch  5=Service  7=Unlock  10=RDP  11=Cached

FAILURE CODES:
0xC000006A=WrongPwd  0xC0000064=NoUser  0xC0000072=Disabled
0xC0000071=ExpiredPwd  0xC0000224=MustChange  0xC0000234=LockedOut
```