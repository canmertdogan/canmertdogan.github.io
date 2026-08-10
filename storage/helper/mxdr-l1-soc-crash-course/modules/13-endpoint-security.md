# Module 13: Endpoint Security

**Priority: P0 — Endpoint = where attacks execute. L1 lives in EDR console daily.**

---

## 13.1 Endpoint Protection Evolution

| Generation | Technology | Detection | Response |
|------------|------------|-----------|----------|
| **1st** | Antivirus (AV) | Signatures (MD5/SHA) | Quarantine file |
| **2nd** | EPP (Endpoint Protection Platform) | Signatures + Heuristics + Basic Behavioral | Quarantine, clean |
| **3rd** | NGAV (Next-Gen AV) | ML/Static AI + Behavioral | Quarantine, rollback |
| **4th** | **EDR (Endpoint Detection & Response)** | **Behavioral + ML + Threat Intel + Hunt** | **Isolate, kill, remediate, hunt** |
| **5th** | **XDR (Extended Detection & Response)** | **Cross-layer (Endpoint+Network+Cloud+Identity)** | **Unified response** |

### Key Distinction: EPP vs EDR
| Aspect | EPP (Prevention) | EDR (Detection/Response) |
|--------|------------------|--------------------------|
| **Goal** | Block known/unknown malware | Detect, investigate, respond |
| **Visibility** | File execution, registry | **Full process tree, memory, network, user** |
| **Data Retention** | Minutes/Hours | **Days/Weeks (queryable history)** |
| **Investigation** | None/Alert only | **Timeline, root cause, pivot** |
| **Response** | Automated block/quarantine | **Manual + Automated (SOAR)** |
| **Threat Hunting** | No | **Yes (query language, MITRE mapping)** |

**Reality**: Modern agents combine EPP + EDR (e.g., CrowdStrike, SentinelOne, Defender for Endpoint, Cortex XDR).

---

## 13.2 EDR Telemetry — What the Agent Sees

### Kernel-Level Collection (via Kernel Driver / Minifilter)
| Telemetry Type | Examples | Collection Method |
|----------------|----------|-------------------|
| **Process** | Create, Exit, OpenProcess, CreateRemoteThread | PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks |
| **File** | Create, Write, Delete, Rename, Read | Minifilter (IRP_MJ_CREATE, WRITE, SET_INFO) |
| **Registry** | Key/Value Create, Modify, Delete | CmRegisterCallback |
| **Network** | Connect, Accept, Send, Receive | WFP (Windows Filtering Platform) Callouts |
| **Image/DLL Load** | LoadImage, MapViewOfSection | PsSetLoadImageNotifyRoutine |
| **Thread** | CreateRemoteThread, QueueUserAPC | ObRegisterCallbacks (Thread) |
| **Memory** | VirtualAlloc, VirtualProtect, WriteProcessMemory | ETW (Event Tracing for Windows) + Kernel callbacks |
| **Token/Privilege** | AdjustTokenPrivileges, Impersonation | ObRegisterCallbacks (Token) |
| **Driver Load** | Load/Unload | PsSetLoadImageNotifyRoutine |
| **WMI** | Event Filter/Consumer Binding | ETW (Microsoft-Windows-WMI-Activity) |

### User-Mode Collection
| Source | Data |
|--------|------|
| **ETW Providers** | PowerShell (Script Block), .NET, WMI, DNS Client, WinINet, HTTP.sys |
| **AMSI** | Script content (PowerShell, VBScript, JS, .NET assemblies) |
| **Application Logs** | Custom app logs, browser history, email client |
| **Command Line** | Via Process Create (kernel) + ETW |

---

## 13.3 Detection Methodologies

### 1. Signature-Based (Static)
| Type | Description | Evasion |
|------|-------------|---------|
| **Hash** | MD5/SHA1/SHA256 of known malware | Polymorphism, packing |
| **YARA** | Pattern rules (strings, regex, structure) | Obfuscation, encryption |
| **IOC** | IP, Domain, Hash, Mutex, Registry | Fast rotation, living-off-land |

### 2. Heuristic/Static Analysis (Pre-Execution)
| Technique | What It Checks |
|-----------|----------------|
| **PE Header Analysis** | Imports, sections, entropy, timestamps, certificates |
| **String Extraction** | URLs, IPs, registry keys, mutexes, commands |
| **Import Table (IMPHASH)** | Library/function fingerprinting |
| **Control Flow Graph** | Structural similarity to malware families |
| **ML Static** | Features → Malicious/Benign probability |

### 3. Behavioral (Runtime) — **EDR Core**
| Behavior Category | Examples | MITRE |
|-------------------|----------|-------|
| **Process Injection** | CreateRemoteThread, QueueUserAPC, SetThreadContext, Process Hollowing, Process Doppelgänging, Herpaderping | T1055 |
| **Credential Access** | LSASS OpenProcess (VM_READ), Mimikatz,sekurlsa, comsvcs.dll, PSScriptPolicyTest | T1003 |
| **Persistence** | Run Keys, Services, Scheduled Tasks, WMI, Startup Folder, COM Hijack, DLL Search Order | T1547, T1543, T1053 |
| **Defense Evasion** | AMSI Bypass, ETW Tampering, Unhooking, Masquerading, Timestomping, Clearing Logs | T1562, T1036, T1070 |
| **Discovery** | Net view, whoami, systeminfo, AD query, Process enumeration, Network share enumeration | T1082, T1083, T1018 |
| **Lateral Movement** | PsExec, WMI, SMB Admin$, RDP, WinRM, Pass-the-Hash, Pass-the-Ticket | T1021 |
| **Collection** | Clipboard, Screen capture, File staging, Archive creation, Email collection | T1056, T1119, T1560 |
| **Command & Control** | Beaconing, DNS/HTTP/HTTPS C2, Domain fronting, Non-standard ports, Protocol tunneling | T1071 |
| **Exfiltration** | Large uploads, Cloud storage, Encrypted channels, Scheduled transfers | T1041, T1567 |
| **Impact** | Ransomware (mass encrypt), Wiper, Data destruction, Service stop, Defacement | T1486, T1485 |

### 4. Machine Learning / AI
| Approach | Training Data | Output |
|----------|---------------|--------|
| **Supervised** | Labeled malicious/benign samples | Probability score |
| **Unsupervised/Anomaly** | Baseline normal behavior | Outlier score |
| **Deep Learning** | Raw bytes, sequences, graphs | Family classification, detection |
| **Graph/Relational** | Process tree, network, file relations | Attack chain detection |

---

## 13.4 EDR Response Capabilities

| Action | Description | Use Case |
|--------|-------------|----------|
| **Network Isolation** | Block all except management (EDR cloud) | Contain compromised host |
| **Process Kill** | Terminate PID, optionally delete binary | Stop active malware/C2 |
| **File Quarantine** | Move to encrypted vault, replace with placeholder | Preserve evidence, prevent execution |
| **Registry Rollback** | Revert malicious changes (Run keys, services) | Remove persistence |
| **Memory Dump** | Capture process/system memory (LSASS, malware) | Forensic analysis |
| **Script Execution** | Run PowerShell/Bash for remediation | Automated cleanup |
| **Host Reboot** | Force restart (sometimes needed for driver unload) | Kernel-level malware |
| **User Logoff** | Force logoff, invalidate tokens | Compromised session |
| **Block Hash/IP/Domain** | Add to blocklist (local or global) | Prevent re-infection |

---

## 13.5 EDR Architecture — What L1 Sees in Console

### Typical EDR Console Views
| View | Purpose |
|------|---------|
| **Alert Queue** | Triage: Severity, Status, Host, User, MITRE, Timestamp |
| **Host Timeline** | Process tree, file/reg/net events, MITRE tags, 24h/7d/30d |
| **Process Details** | Full tree, command lines, hashes, network conns, DLLs, MITRE |
| **Network Connections** | All outbound/inbound, resolved IPs, process context, JA3 |
| **File Analysis** | Hash reputation, sandbox verdict, prevalence, PE info |
| **User Activity** | Logons, file access, admin actions, risk score |
| **Threat Hunting** | Query language (KQL, XQL, proprietary), MITRE heatmap |
| **Vulnerability** | Missing patches, CVE mapping, exploitability |
| **Compliance** | Policy adherence, encryption, firewall status |

### Key Investigation Pivots
```
Alert → Host Timeline → Process Tree → Command Line → Network Conns → File Hash → Threat Intel
                ↓
           Parent Process → Grandparent → ... → Root Cause
                ↓
           Child Processes → Spawned → ... → Impact Scope
                ↓
           Network → Destination IP/Domain → Threat Intel → C2 Infrastructure
                ↓
           Files → Created/Modified → Hash → Sandbox → Family
                ↓
           User → Logons → Groups → Privilege → Lateral Risk
```

---

## 13.6 Common EDR Alert Types — Triage Guide

| Alert Category | Typical Trigger | L1 Triage Steps |
|----------------|-----------------|-----------------|
| **Suspicious Process Tree** | Office → Script, LOLBin, Service → Shell | Check parent, cmdline, network, files, user |
| **Credential Theft** | LSASS access, Mimikatz, sekurlsa, comsvcs.dll | Source process, user, network, timeline |
| **Persistence** | Run key, Service, Task, WMI, Startup | Persistence type, creator, payload, survival |
| **C2/Beaconing** | Regular intervals, known C2 IP, JA3 match | Interval, destination, process, payload |
| **Lateral Movement** | SMB/Admin$, RDP, WinRM, Pass-the-Hash | Source/dest, auth type, account, scope |
| **Ransomware** | Mass file encrypt, ransom note, entropy spike | Process, extensions, ransom note, scope |
| **Exploit** | CVE exploit, buffer overflow, RCE | Vuln CVE, process, payload, patch status |
| **Living-off-Land** | Certutil, Regsvr32, Rundll32, Mshta, InstallUtil | Binary, args, network, parent |
| **AMSI/ETW Bypass** | AmsiScanBuffer patch, ETW provider disable | Process, technique, follow-up actions |
| **Data Staging** | Large archive creation, file copy to temp | Files, destination, process, user |

---

## 13.7 EDR Evasion — What Attackers Do (So You Detect It)

| Technique | Mechanism | Detection |
|-----------|-----------|-----------|
| **Unhook/Inline Hook Removal** | Restore original syscall/API bytes | Kernel callback detects modification |
| **Direct Syscalls** | Bypass user-mode hooks (ntdll) | Syscall monitoring (ETW, kernel) |
| **Heaven's Gate** | 32-bit → 64-bit transition (WoW64) | Cross-architecture calls |
| **Process Hollowing** | Create suspended → Replace memory → Resume | Memory writes to remote process, section mapping |
| **Process Doppelgänging** | TxF transaction → Replace → Commit | Transactional NTFS abuse |
| **Process Herpaderping** | Write → Map → Create → Modify → Execute | File create + image load mismatch |
| **Reflective DLL Injection** | Manual LoadLibrary in memory | Memory allocation + RWX, no disk DLL |
| **Module Stomping** | Overwrite legitimate module in memory | Image load + memory permission changes |
| **AMSI Bypass** | Patch AmsiScanBuffer / AmsiInitFailed | AMSI event logs, memory scan |
| **ETW Tampering** | Disable ETW providers (Threat-Intelligence, etc.) | ETW provider state changes |
| **Living-off-Land (LOLBins)** | Signed Microsoft binaries for malicious use | Process tree + args + network context |
| **Bring Your Own Vulnerable Driver (BYOVD)** | Load signed vulnerable driver → Kernel exploit | Driver load (unexpected), kernel callbacks |

---

## 13.8 Major EDR Vendors — Capability Comparison

| Vendor | Agent | Query Language | Key Strength |
|--------|-------|----------------|--------------|
| **CrowdStrike Falcon** | Lightweight (sensor) | FQL (Falcon Query Language) | Cloud-native, threat intel, managed hunting |
| **SentinelOne Singularity** | Behavioral AI (Static/Dynamic) | PowerQuery (SQL-like) | Autonomous response, storyline, rollback |
| **Microsoft Defender for Endpoint** | Built-in (Win10/11/Server) | KQL (Advanced Hunting) | Windows integration, Entra ID, cost |
| **Palo Alto Cortex XDR** | Cortex XDR Agent | XQL (SQL-like) | Network+Endpoint+Cloud, analytics |
| **Elastic Defend** | Elastic Agent | KQL/ES|QL | Open, flexible, SIEM integration |
| **Trend Micro Vision One** | Apex One + Sensors | Custom | XDR suite, email/network/endpoint |
| **Cybereason** | Behavioral (Malop) | Custom | Attack storyline (Malop), Russian APT focus |

**L1 Reality**: You'll use whatever your org has. Learn the **concepts** (process tree, timeline, pivots), not just one UI.

---

## 13.9 EDR Health & Hygiene — What L1 Monitors

| Metric | Healthy | Action if Unhealthy |
|--------|---------|---------------------|
| **Sensor Online %** | > 99% | Investigate offline hosts (reboot, reinstall, network) |
| **Sensor Version** | Latest - 1 | Push updates, check deployment rings |
| **Policy Applied** | 100% matched | Drift detection, re-apply |
| **Event Throughput** | Normal baseline | Check for storm (log4j, ransomware) or drop |
| **Cloud Connectivity** | Connected | Network/firewall/proxy check |
| **License Usage** | < 85% | Procure more, reclaim stale |
| **False Positive Rate** | < 5% (tunable) | Tune rules, create suppressions |
| **Mean Time to Detect (MTTD)** | < 15 min (P1) | Process improvement |
| **Mean Time to Respond (MTTR)** | < 1 hr (P1) | Automation, playbooks |

---

## 13.10 Interview Questions for This Module

1. **What is the difference between EPP and EDR?**
   - EPP: Prevention-focused, signature/heuristic, block/quarantine. EDR: Detection/response-focused, behavioral, full visibility, investigation, hunt, manual+auto response.

2. **What telemetry does an EDR agent collect at kernel level?**
   - Process create/exit, OpenProcess, CreateRemoteThread, File create/write/delete, Registry key/value changes, Network connect/send, Image/DLL load, Thread creation, Memory allocation/protect, Driver load, Token manipulation.

3. **Name 5 behavioral detection categories with MITRE techniques.**
   - Process Injection (T1055), Credential Access (T1003), Persistence (T1547/T1053), Defense Evasion (T1562), Discovery (T1082), Lateral Movement (T1021), C2 (T1071), Exfiltration (T1041), Impact (T1486).

4. **What response actions can EDR take?**
   - Network isolate, process kill, file quarantine, registry rollback, memory dump, script execution, host reboot, user logoff, block hash/IP/domain.

5. **How do you investigate an EDR alert for "Suspicious Process Tree"?**
   - Check parent process, command line, network connections, file modifications, child processes, user context, threat intel on hashes/IPs, MITRE tags.

6. **What is "Living-off-the-Land" and how does EDR detect it?**
   - Using signed system binaries (LOLBins) for malicious purposes. Detection: Process tree context, command line args, network connections, behavioral anomalies (not just binary reputation).

7. **What is Process Hollowing and how does EDR detect it?**
   - Create suspended process → Replace memory with malicious code → Resume. Detected by: Memory writes to remote process, section mapping, image load mismatch, RWX memory.

8. **What is AMSI and how do attackers bypass it?**
   - Antimalware Scan Interface scans script content in memory. Bypass: Patch AmsiScanBuffer in memory, set AmsiInitFailed via reflection. Detected via AMSI event logs, memory scans.

9. **What metrics should L1 monitor for EDR health?**
   - Sensor online %, version compliance, policy applied, event throughput, cloud connectivity, license usage, FP rate, MTTD, MTTR.

10. **How does EDR differ from traditional AV in data retention?**
    - AV: Minutes/hours (alert only). EDR: Days/weeks of queryable history (process tree, timeline, network, files, registry).

---

## 13.11 Study Checklist for Module 13

- [ ] Explain EPP vs EDR vs NGAV vs XDR evolution
- [ ] List 10+ kernel telemetry sources
- [ ] Describe 4 detection methodologies (Signature, Heuristic, Behavioral, ML)
- [ ] Map 9 behavioral categories to MITRE techniques
- [ ] List 9 EDR response actions
- [ ] Walk through EDR console investigation pivots
- [ ] Triage 5 common alert types (Process Tree, Cred Theft, Persistence, C2, Lateral)
- [ ] Explain 10 EDR evasion techniques and detection
- [ ] Compare 7 major EDR vendors
- [ ] List 9 EDR health metrics
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 14 — Malware Fundamentals*