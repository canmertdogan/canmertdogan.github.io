# Module 4: Windows Security & Event Logs

**Priority: P0 — Foundation for all Windows investigation. Memorize key Event IDs.**

---

## 4.1 Windows Architecture Basics (SOC Perspective)

| Component | SOC Relevance |
|-----------|---------------|
| **Kernel** | Rootkits, DKOM, driver loads (Sysmon EID 6) |
| **User Mode** | Process execution, DLL injection, API hooking |
| **Session Manager (smss.exe)** | First user-mode process, session creation |
| **Winlogon** | Interactive logon, SAS (Ctrl+Alt+Del), screen lock |
| **LSASS (lsass.exe)** | Authentication, token creation, credential storage — **TARGET #1** |
| **Services (services.exe)** | Service installation (EID 7045), persistence |
| **Task Scheduler (taskhostw.exe)** | Scheduled tasks (EID 4698), persistence |
| **WMI (wmiprvse.exe)** | WMI event consumers, lateral movement, persistence |
| **Registry** | Persistence (Run keys, services), configuration |
| **Token / Privileges** | EID 4672 (special logon), token manipulation |

---

## 4.2 Windows Event Log Structure

```
Event Log Channels (Event Viewer → Windows Logs):
├── System          # Kernel, drivers, services, boot
├── Security        # Auditing: logon, object access, policy change — **MOST IMPORTANT**
├── Application     # App crashes, errors, custom events
└── ForwardedEvents # Collected from other hosts

Applications and Services Logs:
├── Microsoft
│   ├── Windows
│   │   ├── PowerShell          # Operational (4103, 4104) — **CRITICAL**
│   │   ├── Sysmon              # Operational (1-23) — **CRITICAL**
│   │   ├── Windows Defender    # Operational
│   │   ├── AppLocker           # EXE and DLL, MSI and Script
│   │   └── TaskScheduler       # Operational
│   └── Office                  # Macro execution, protected view
└── Third-party (AV, EDR, VPN, etc.)
```

### Log Retention Reality
| Channel | Default Size | Typical Retention | SOC Need |
|---------|--------------|-------------------|----------|
| Security | 128-512 MB | Hours to days | **Forward to SIEM immediately** |
| System | 128 MB | Days | Forward |
| PowerShell | 150 MB | Days | Forward (enable Script Block Logging) |
| Sysmon | 256 MB | Days | Forward (configure retention) |

**Never rely on local Event Viewer for investigation. Query SIEM/XDR.**

---

## 4.3 Critical Security Event IDs — The "Must Know" List

### Authentication & Logon

| Event ID | Name | Logon Types | Why It Matters |
|----------|------|-------------|----------------|
| **4624** | Successful Logon | 2,3,4,5,7,8,9,10,11 | **Primary logon visibility**. Track who, where, how. |
| **4625** | Failed Logon | 2,3,4,5,7,8,9,10,11 | **Brute force, password spray, credential stuffing**. |
| **4634** | Logoff | — | Session end. Correlate with 4624 for session duration. |
| **4647** | User Initiated Logoff | — | Clean logoff vs crash. |
| **4672** | Special Logon (Privileged) | — | **Admin logon**. SeDebugPrivilege, SeTcbPrivilege, etc. |
| **4768** | Kerberos TGT Request (AS-REQ) | — | **Kerberos auth start**. User → KDC. |
| **4769** | Kerberos Service Ticket (TGS-REQ) | — | **Service access**. SPN, service account targeting. |
| **4771** | Kerberos Pre-Auth Failed | — | **AS-REP Roasting, password spray (Kerberos)**. |
| **4776** | NTLM Auth Attempt (Domain Controller) | — | **NTLM auth**. Source workstation, target user. |

### Process & Execution

| Event ID | Name | Why It Matters |
|----------|------|----------------|
| **4688** | Process Creation | **Process execution**. NewProcessName, CommandLine, ParentProcess, TokenElevation, SubjectUser. **Enable CommandLine logging!** |
| **4698** | Scheduled Task Created | **Persistence**. Task name, author, action, trigger. |
| **4699** | Scheduled Task Deleted | Covering tracks. |
| **4700** | Scheduled Task Enabled | Persistence activation. |
| **4701** | Scheduled Task Disabled | Cleanup or disable defense. |

### Account Management

| Event ID | Name | Why It Matters |
|----------|------|----------------|
| **4720** | User Account Created | **New account**. Who created, privileges. |
| **4722** | User Account Enabled | Disabled → Enabled (staging). |
| **4723** | Password Change Attempt | Self vs admin reset. |
| **4724** | Password Reset Attempt | Admin reset (potential compromise). |
| **4728** | User Added to Global Group | **Privilege escalation**. Domain Admins, Enterprise Admins. |
| **4732** | User Added to Domain Local Group | Local admin, RDP access, etc. |
| **4756** | User Added to Universal Group | Cross-domain privileges. |

### Policy & Audit

| Event ID | Name | Why It Matters |
|----------|------|----------------|
| **1102** | Audit Log Cleared | **Anti-forensics**. Who, when. |
| **4719** | Audit Policy Changed | Logging tampering. |
| **4902** | Per-User Audit Policy Changed | Targeted logging evasion. |

### Service & Driver

| Event ID | Name | Why It Matters |
|----------|------|----------------|
| **7045** | Service Installed | **Persistence**. Service name, path, account, type. |
| **7036** | Service State Change | Start/stop. Unusual services starting. |
| **7040** | Service Start Type Changed | Disabled → Auto (persistence). |

---

## 4.4 Deep Dive: Top 15 Event IDs for L1

### 4624 — Successful Logon (The King of Events)

**Key Fields**:
```
Subject:  Security ID, Account Name, Account Domain, Logon ID
Logon Type:  (see below)
New Logon:  Security ID, Account Name, Account Domain, Logon ID, Logon GUID
Process:    Process ID, Process Name
Network:    Workstation Name, Source Network Address, Source Port
Authentication:  Authentication Package (Kerberos, NTLM, Negotiate), 
               Key Length, Impersonation Level, Restricted Admin Mode
```

**Logon Types (Memorize These)**:
| Type | Name | Description | Suspicious If |
|------|------|-------------|---------------|
| **2** | Interactive | Local console (keyboard) | On server, at 3AM, from admin |
| **3** | Network | SMB, RPC, PSRemoting, WinRM | Service accounts, lateral movement |
| **4** | Batch | Scheduled task | Non-service account, unusual time |
| **5** | Service | Service startup | Non-service account, new service |
| **7** | Unlock | Workstation unlock | Rapid lock/unlock, remote unlock |
| **8** | NetworkCleartext | IIS basic auth, FTP | Credentials in cleartext |
| **9** | NewCredentials | RunAs /netonly | **Lateral movement**, credential theft |
| **10** | RemoteInteractive | **RDP** | External IP, impossible travel, admin |
| **11** | CachedInteractive | Offline logon | Laptop off-domain, cached creds |

**Failure Codes (4625 — SubStatus / Status)**:
| Code | Meaning | Attack Indicator |
|------|---------|------------------|
| 0xC000006A | Wrong password | Brute force, password spray |
| 0xC000006D | Bad username | User enumeration |
| 0xC000006F | Logon time restriction | Policy violation |
| 0xC0000070 | Workstation restriction | Unauthorized device |
| 0xC0000071 | Password expired | Old credentials |
| 0xC0000072 | Account disabled | Targeting disabled accounts |
| 0xC000015B | Smartcard required | MFA bypass attempt |
| 0xC000018C | Trusted domain failed | Cross-domain attack |
| 0xC000019B | Account locked | Brute force success → lockout |
| 0xC0000224 | Password must change | Forced reset |
| 0xC0000225 | Account disabled (UI) | Same as 0xC0000072 |
| 0xC0000234 | Account locked (UI) | Same as 0xC000019B |
| 0xC00002EE | Account not found | User enumeration |

### 4688 — Process Creation (The Queen of Events)

**Requires**: `Audit Process Creation` + `Include command line in process creation events` (GPO)

**Key Fields**:
```
New Process:      NewProcessName, NewProcessID
Parent Process:   ParentProcessName, ParentProcessID
Creator:          SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId
Command Line:     CommandLine (FULL command with args)
Token:            TokenElevationType (Default / Full / Limited), 
                  MandatoryLabel (Integrity Level: Low/Medium/High/System)
```

**Suspicious Patterns**:
| Pattern | Example | Why |
|---------|---------|-----|
| **Office → Script** | `WINWORD.EXE` → `POWERSHELL.EXE` / `CMD.EXE` / `WSCRIPT.EXE` | Phishing, macro |
| **Script → Script** | `POWERSHELL.EXE` → `POWERSHELL.EXE` (encoded) | Obfuscation, staging |
| **System → User** | `SERVICES.EXE` → `POWERSHELL.EXE` | Service exploit |
| **LOLBin execution** | `RUNDLL32.EXE` javascript:, `REGSVR32.EXE` /s /n /u /i:http... | Living-off-land |
| **High integrity from Medium** | `CMD.EXE` (Medium) → `POWERSHELL.EXE` (High) | UAC bypass |
| **Unsigned / Temp path** | `C:\Users\...\AppData\Local\Temp\abc.exe` | Malware drop |
| **No parent / PID 0** | ParentProcessID = 0 or 4 (System) | Direct kernel, injection |

### 4672 — Special Logon (Privileged Access)

**Triggered when**: Logon with elevated privileges (admin-equivalent)
**Key Privileges**: SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege

**SOC Value**: Every admin logon. Correlate with 4624 Logon Type 10 (RDP) + 4672 = **Admin RDP session**.

### 4698 — Scheduled Task Created

**Key Fields**: TaskName, TaskContent (XML), Author, UserId, Action (Command, Arguments), Trigger

**Suspicious**:
- Task runs as SYSTEM or high-privilege account
- Action: PowerShell, CMD, script from temp, download cradle
- Trigger: At logon, idle, daily at odd hours, on event (e.g., 4624)
- Author ≠ Task scheduler service (manual creation)

### 7045 — Service Installed

**Key Fields**: ServiceName, ServiceFileName (path), ServiceType, ServiceStartType, ServiceAccount

**Suspicious**:
- Path: `C:\Temp\`, `C:\Users\...\AppData\`, non-standard
- Account: LocalSystem (default), but new service running as user
- StartType: Auto (2) or Demand (3) — persistence
- Name: Random, mimics legitimate (e.g., "Windows Defender Update")

### 1102 — Audit Log Cleared

**Key Fields**: SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId

**Always investigate**: Who cleared, when, what happened before/after. **Anti-forensics indicator.**

### 4768 / 4769 — Kerberos TGT / Service Ticket

**4768 (AS-REQ)**: User requests TGT from KDC. Fields: TargetUserName, ServiceName (krbtgt), PreAuthType, ResultCode
**4769 (TGS-REQ)**: User presents TGT, requests service ticket. Fields: TargetUserName, ServiceName (SPN), TicketOptions, ResultCode

**SOC Value**: Kerberoasting (4769 with RC4), AS-REP Roasting (4768 no pre-auth), unusual SPN requests.

### 4771 — Kerberos Pre-Auth Failed

**Key Fields**: TargetUserName, ServiceName, FailureCode (0x18 = bad password)
**Attack**: Password spray (Kerberos), AS-REP roasting target enumeration.

### 4776 — NTLM Authentication (Domain Controller)

**Logged on DC only**. SourceWorkstation, TargetUserName, Status (0x0=success, 0xC000006A=bad pwd).
**Value**: NTLM usage tracking, Pass-the-Hash detection (no 4624 on target), source workstation spoofing.

---

## 4.5 Advanced Audit Policy Configuration (What to Enable)

```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy

Logon/Logoff:
  ✅ Audit Logon (Success, Failure)           → 4624, 4625, 4634, 4647
  ✅ Audit Logoff (Success)                   → 4634
  ✅ Audit Account Lockout (Failure)          → 4740
  ✅ Audit IPsec Main Mode (Failure)          → VPN issues
  ✅ Audit IPsec Quick Mode (Failure)         → VPN issues
  ✅ Audit Network Policy Server (Success/Fail) → RADIUS

Object Access:
  ✅ Audit File System (Success, Failure)     → 4663 (sensitive files)
  ✅ Audit Registry (Success, Failure)        → 4657 (persistence keys)
  ✅ Audit Kernel Object (Success)            → Handle manipulation
  ✅ Audit SAM (Success, Failure)             → Local account changes
  ✅ Audit Certification Services (Success/Fail) → PKI

Policy Change:
  ✅ Audit Audit Policy Change (Success)      → 4719
  ✅ Audit Authentication Policy Change (Success) → 4739
  ✅ Audit Authorization Policy Change (Success) → 4704
  ✅ Audit Filtering Platform Policy Change (Success) → Firewall
  ✅ Audit MPSSVC Rule-Level Policy Change (Success) → Windows Firewall
  ✅ Audit Other Policy Change Events (Success) → 4902 (per-user audit)

Privilege Use:
  ✅ Audit Sensitive Privilege Use (Success)  → 4672, 4673, 4674
  ❌ Audit Non-Sensitive Privilege Use        → Too noisy

Detailed Tracking:
  ✅ Audit Process Creation (Success)         → 4688 **CRITICAL**
  ✅ Audit Process Termination (Success)      → 4689
  ✅ Audit DPAPI Activity (Success)           → 4692 (credential extraction)
  ✅ Audit PNP Activity (Success)             → Device install
  ❌ Audit RPC Events                         → Very noisy

Account Management:
  ✅ Audit User Account Management (Success)  → 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740
  ✅ Audit Computer Account Management (Success) → 4741-4743
  ✅ Audit Security Group Management (Success) → 4727-4735, 4754-4758
  ✅ Audit Application Group Management (Success)
  ✅ Audit Other Account Management Events (Success) → 4737, 4739

DS Access:
  ✅ Audit Directory Service Access (Success) → LDAP queries
  ✅ Audit Directory Service Changes (Success) → AD modifications
  ✅ Audit Directory Service Replication (Success)
  ❌ Audit Detailed Directory Service Replication → Noisy

Account Logon:
  ✅ Audit Kerberos Authentication Service (Success, Failure) → 4768, 4771
  ✅ Audit Kerberos Service Ticket Operations (Success, Failure) → 4769, 4770
  ✅ Audit Credential Validation (Success, Failure) → 4774, 4775, 4776
  ✅ Audit Other Account Logon Events (Success, Failure)
```

**Command to Apply (Admin PowerShell)**:
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

**Enable Command Line Logging**:
```
Computer Configuration → Administrative Templates → System → Audit Process Creation
→ Include command line in process creation events → Enabled
```

---

## 4.6 Event Log Query Patterns (KQL / Splunk / Elastic)

### Brute Force Detection
```kql
// 4625 failed logons → 4624 success within 10 min, same user, same source
SecurityEvent
| where EventID == 4625
| summarize FailCount=count(), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) 
  by TargetUserName, IpAddress, Computer
| where FailCount >= 10
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | project TimeGenerated, TargetUserName, IpAddress, Computer, LogonType
) on TargetUserName, IpAddress, Computer
| where TimeGenerated_right between (StartTime_left .. datetime_add('minute', 10, EndTime_left))
```

### Suspicious Process Tree
```kql
// Office apps spawning scripts
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe")
| where ParentProcessName has_any ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe")
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
```

### Admin Logon at Odd Hours
```kql
// 4624 + 4672 (special logon) outside business hours
SecurityEvent
| where EventID == 4624 and LogonType == 10  // RDP
| join kind=inner (
    SecurityEvent
    | where EventID == 4672
    | project TimeGenerated, Computer, SubjectUserName, SubjectLogonId
) on Computer, SubjectUserName, SubjectLogonId
| where TimeGenerated between (datetime(02:00:00) .. datetime(06:00:00))
```

### Scheduled Task Persistence
```kql
SecurityEvent
| where EventID == 4698
| parse TaskContent with * "<Command>" Command "</Command>" * "<Arguments>" Arguments "</Arguments>" *
| where Command has_any ("powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta", "http:", "https:")
| project TimeGenerated, Computer, TaskName, Author, Command, Arguments, TriggerType
```

---

## 4.7 Common Event ID Correlation Patterns

| Attack Stage | Primary Event IDs | Correlating Events |
|--------------|-------------------|-------------------|
| **Initial Access (Phishing)** | 4688 (Office→Script), 4104 (PS Script Block) | Email logs, Proxy/DNS |
| **Credential Theft** | 4672 (Special logon), 4624 (Type 9), 4776 (NTLM) | 4688 (LSASS access), 4663 (NTDS.dit) |
| **Lateral Movement** | 4624 (Type 3,10), 4688 (PsExec, WMI), 4698 (Remote task) | NDR (SMB, RPC), 4769 (Kerberos) |
| **Persistence** | 4698 (Task), 7045 (Service), 4657 (Run keys), 4698 (WMI) | 4688 (persistence execution) |
| **Privilege Escalation** | 4672 (new), 4688 (token manip), 4673 (priv use) | 4728/4732 (group add), 4719 (audit policy) |
| **Defense Evasion** | 1102 (log clear), 4719 (audit policy), 4688 (unhook) | 4663 (AV config), 4688 (EDR tamper) |
| **Exfiltration** | 4663 (file read), 5156 (network connect), Proxy logs | NDR (large transfer), Cloud logs |

---

## 4.8 Log Quality Issues & Workarounds

| Issue | Impact | Workaround |
|-------|--------|------------|
| **No command line in 4688** | Blind to args | Enable GPO; use Sysmon EID 1 (always has cmdline) |
| **Logon Type missing in 4624** | Can't distinguish RDP vs SMB | Check 4624 + 4672 combo; NDR for RDP |
| **Security log overwrites in hours** | Lost evidence | Forward to SIEM immediately; increase log size to 4GB |
| **No 4688 on some systems** | Blind to process | Deploy Sysmon; EDR kernel callbacks |
| **Service account noise** | Alert fatigue | Baseline service account behavior; suppress known-good |
| **Domain Controller log volume** | Performance, cost | Filter: only 4624/4625/4768/4769/4771/4776/4672/4688/4698/7045/1102 |

---

## 4.9 Interview Questions for This Module

1. **What are the 9 logon types in Event 4624 and which indicate RDP?**
   - Types 2,3,4,5,7,8,9,10,11. Type 10 = RDP (RemoteInteractive).

2. **Event 4625 shows Status 0xC000006A and SubStatus 0xC000006A. What does this mean?**
   - Wrong password (bad credentials). Brute force or password spray indicator.

3. **How do you distinguish a service account logon from a compromised admin logon using 4624?**
   - Logon Type: Service accounts = Type 5 (Service) or 4 (Batch). Admin interactive = Type 2, RDP = Type 10. Check 4672 (special logon) for admin.

4. **What does Event 4688 show and what GPO setting is required for command lines?**
   - Process creation with parent, command line, user, integrity level. GPO: "Include command line in process creation events" under Audit Process Creation.

5. **Event 4672 appears with 4624 Logon Type 10. What does this indicate?**
   - Privileged (admin-equivalent) RDP session. High value target.

6. **What Event ID indicates a scheduled task was created and what fields matter?**
   - 4698. TaskName, Author, Command, Arguments, Trigger, UserId.

7. **Event 1102 fires. What is your immediate action?**
   - Investigate immediately: Who (SubjectUserName), when, what happened before/after. Anti-forensics indicator.

8. **How do you detect Kerberoasting using Windows Event Logs?**
   - 4769 (TGS-REQ) with TicketEncryptionType=0x17 (RC4) targeting service accounts (SPNs). High volume from single user.

9. **What's the difference between Event 4768 and 4769?**
   - 4768 = AS-REQ (TGT request, user→KDC). 4769 = TGS-REQ (Service ticket request, user→KDC with TGT).

10. **Event 4776 on a Domain Controller shows Status 0x0. What does this mean?**
    - Successful NTLM authentication. SourceWorkstation field shows origin. Check for Pass-the-Hash (no corresponding 4624 on target).

---

## 4.10 Study Checklist for Module 4

- [ ] Recite 15 critical Event IDs and their purpose
- [ ] Memorize 9 Logon Types and 10 Failure Codes
- [ ] Explain 4624, 4625, 4688, 4672, 4698, 7045, 1102, 4768, 4769, 4771, 4776 in detail
- [ ] Write KQL/Splunk queries for: brute force, Office→script, admin RDP, scheduled task, Kerberoasting
- [ ] Configure Advanced Audit Policy from memory (key subcategories)
- [ ] Correlate event IDs to attack stages (Initial Access → Exfiltration)
- [ ] Identify log quality gaps and workarounds
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 5 — Sysmon Telemetry*