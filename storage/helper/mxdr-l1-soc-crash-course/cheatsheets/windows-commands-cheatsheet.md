# Windows Commands Cheat Sheet for SOC Analysts

**Priority: P1 — The commands you type every shift when investigating a Windows endpoint: processes, network, persistence, and logons.**

---

## Process Enumeration

### tasklist (cmd) vs Get-Process (PowerShell)

```cmd
tasklist                         :: All processes
tasklist /fi "imagename eq powershell.exe"   :: Filter by image name
tasklist /svc                    :: Show services each process hosts (svchost)
tasklist /v                      :: Verbose (session, memory, CPU time)
```

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Process powershell | Select-Object Id, Path, StartTime
```

### Find a specific process and its command line

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.Name -match "powershell|cmd|wscript|cscript" }
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine
```

**What to spot**: a process named `powershell.exe` sitting in an unusual path, a **legitimate-name imposter** (e.g. `svchost.exe` in `C:\Users\...\AppData\Local\Temp`), and command lines that don't match the process's apparent identity. Sysmon EID 1's `OriginalFileName` field catches renames like this. Check the parent PID — a process spawned by `WINWORD.EXE` or `OUTLOOK.EXE` is a phishing red flag.

---

## Command-Line Inspection

### Legacy WMIC

```cmd
wmic process get processid,parentprocessid,name,commandline
wmic process where "name='powershell.exe'" get commandline
```

### Modern PowerShell equivalent

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine
```

**What to look for** in command lines:

| Indicator | Example | Meaning |
|-----------|---------|---------|
| **Base64 encode** | `powershell -enc JABjAGwAaQBlAG4AdAA...` | Obfuscated command (decodes to UTF-16LE) |
| **Download cradle** | `IEX (New-Object Net.WebClient).DownloadString('http://...')` | Remote code fetch + execute |
| **In-memory loading** | `[Convert]::FromBase64String(...)`, `[Assembly]::Load()` | Fileless execution |
| **Hidden window** | `-windowstyle hidden`, `-w hidden` | Stealth |
| **Legitimate name, weird path** | `C:\Windows\Temp\svchost.exe` | Masquerading / imposter |

Decode an `-enc` payload:

```powershell
$e = "JABjAGwAaQBlAG4AdAA..."
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e))
```

Remember: Event 4104 (Script Block Logging) shows the **deobfuscated** script — the parser resolves concatenation, `$var` substitution, and encoding before it logs. Always check it.

---

## Network Connections

### netstat (cmd) — always run as admin for `-b`

```cmd
netstat -ano                :: All connections + owning PID
netstat -anob               :: + executable name (admin only)
netstat -ano | findstr ":445"       :: Filter by port
netstat -ano | findstr "LISTENING"  :: Listening only
```

### Get-NetTCPConnection (PowerShell) — the modern way

```powershell
Get-NetTCPConnection | Where-Object State -eq "Established"
Get-NetTCPConnection -LocalPort 5985          :: Who is on WinRM?
Get-NetTCPConnection | Where-Object RemotePort -eq 443 |
  ForEach-Object { Get-Process -Id $_.OwningProcess | Select-Object Id, ProcessName, Path }
```

**Map PID to process** (works for netstat output too):

```powershell
Get-Process -Id 1234 | Select-Object Id, ProcessName, Path
```

| Legacy (cmd) | Modern (PowerShell) | Purpose |
|--------------|---------------------|---------|
| `netstat -ano` | `Get-NetTCPConnection` | All connections + PID |
| `netstat -anob` | `Get-NetTCPConnection` + `Get-Process` | Map PID to process |
| `findstr ":80"` | `Where-Object { $_.LocalPort -eq 80 }` | Filter by port |

**What to spot**: **LISTENING** ports you don't recognize, **established outbound** connections to external IPs from non-browser processes (`powershell.exe`, `rundll32.exe`, `svchost.exe`), and beaconing cadence (same destination, regular intervals). Cross-check Sysmon EID 3 which gives you the process, IP, port, and protocol in one event.

---

## Services & Scheduled Tasks (Persistence)

### Services

```cmd
sc query                       :: All services, status
sc qc <service-name>           :: Query config (binary path = what it runs)
sc queryex <service-name>      :: Running + PID
```

```powershell
Get-Service | Where-Object Status -eq "Running"
Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName, StartName
```

**What to spot**: a **new service** (Event **7045**), a `PathName` pointing to `C:\Temp\` or `AppData`, a service running as a normal user account, or a name that mimics Windows ("Windows Defender Update"). `sc qc` shows the exact `BINARY_PATH_NAME` the service will execute.

### Scheduled tasks

```cmd
schtasks /query /fo LIST /v     :: All tasks, verbose
schtasks /query /tn "TaskName" /fo LIST /v
```

```powershell
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
Get-ScheduledTask -TaskName "*update*" |
  ForEach-Object { $_.Actions | Select-Object Execute, Arguments }
```

**What to spot**: task action is `powershell`, `cmd`, or a script from temp; task runs as SYSTEM or a privileged account; author isn't the Task Scheduler service; trigger fires at logon, on idle, or on event (e.g., 4624). Creation is logged as Event **4698**.

---

## Startup & Persistence Locations

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s
```

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

**Key persistence registry locations to check** (Sysmon EID 12/13/14 monitor these):

| Registry Key | Technique |
|--------------|-----------|
| `HKLM\...\CurrentVersion\Run` / `RunOnce` | Logon persistence |
| `HKCU\...\CurrentVersion\Run` / `RunOnce` | Current-user logon persistence |
| `HKLM\...\Windows NT\CurrentVersion\Winlogon\Userinit` | Winlogon chain |
| `HKLM\...\Winlogon\Shell` | Shell replacement |
| `HKLM\SYSTEM\CurrentControlSet\Services\*` | Service persistence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | Policy-based |

**WMI subscriptions** (fileless persistence — Sysmon EID 19/20/21):

```powershell
Get-CimInstance -Namespace root\Subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\Subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root\Subscription -ClassName __FilterToConsumerBinding
```

A filter bound to a consumer running `powershell -enc ...` is **High** suspicion — permanent WMI persistence.

---

## Users & Logon

```cmd
whoami /all                     :: Current user + groups + privileges
net user <user>                 :: Local user details (active, password age)
net user <user> /domain         :: Domain user (DC context)
net localgroup administrators   :: Who is a local admin?
qwinsta                         :: Active RDP sessions
```

```powershell
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon
Get-LocalGroupMember -Group "Administrators"
Get-CimInstance Win32_UserAccount | Where-Object LocalAccount -eq $true
Get-LocalGroupMember -Group "Remote Desktop Users"
```

**What to spot**: a **new local account** (Event **4720**) or one you never created, an unexpected member of the **Administrators** or **Remote Desktop Users** group (Events **4732**/**4728**), admin RDP sessions at 3 AM, and accounts with a very recent `PasswordLastSet`.

### Logon events (4624 / 4625)

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } -MaxEvents 50 |
  ForEach-Object { $_.Properties[8].Value; $_.Properties[11].Value }
```

| Logon Type | Name | Suspicious if |
|-----------|------|---------------|
| **2** | Interactive | On a server, off-hours |
| **3** | Network | Service account hitting many hosts |
| **9** | NewCredentials | RunAs /netonly — lateral movement |
| **10** | RemoteInteractive | RDP from external/unexpected IP |
| **11** | CachedInteractive | Laptop using cached creds |

A 4624 Type 10 (RDP) paired with **4672** (Special Logon) = **privileged remote admin session**. A **1102** (audit log cleared) is anti-forensics — escalate.

---

## Patches & Installed Software

```cmd
wmic qfe list brief             :: Installed hotfixes / patches
wmic product get name,version   :: Installed software (slow!)
```

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Select-Object DisplayName, DisplayVersion, InstallDate
```

**Why it matters**: an unpatched host (missing KB for a disclosed exploit) raises severity, and `Uninstall` keys reveal what tools are present (e.g., **AnyDesk**, **nmap**, **mimikatz**-adjacent tooling) without relying on the slow `wmic product`.

---

## File & Forensic Queries

```cmd
dir /a /o-d C:\Users\Public       :: Include hidden files, newest first
dir /s /a C:\Windows\Temp         :: Recursive, include hidden
```

```powershell
Get-ChildItem C:\Windows\Temp -Force -Recurse |
  Sort-Object LastWriteTime -Descending | Select-Object -First 25
Get-ChildItem C:\Users\*\AppData\Local\Temp -Force -Recurse |
  Sort-Object LastWriteTime -Descending | Select-Object -First 25
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup -Force
```

**Recent file hunt** — files written around the alert time:

```powershell
Get-ChildItem C:\Users\*\AppData\Local\Temp -Force -Recurse |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) } |
  Select-Object FullName, Length, LastWriteTime
```

**Hash a suspicious file** for VT/threat-intel lookup:

```powershell
Get-FileHash C:\Users\Public\malware.exe -Algorithm SHA256
```

**What to spot**: executables or scripts in temp/staging dirs (`Temp`, `ProgramData`, `Public`), `.dll`/`.ps1` files written right before the alert, and timestamps that don't match the file's stated creation date.

### Alternate Data Streams (ADS)

```cmd
dir /r                          :: Show NTFS streams in the current dir
```

```powershell
Get-Item C:\path\to\file -Stream *
Get-ChildItem -Recurse -Force | ForEach-Object { Get-Item $_.FullName -Stream * } |
  Where-Object { $_.Stream -ne ':$DATA' }
```

Hiding payloads in ADS is a classic evasion technique — anything with a stream other than `:$DATA` is suspicious (Sysmon EID 15 covers stream creation).

---

## Event Log Queries with Get-WinEvent

The local answer to "query the SIEM" when you must check a host directly:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1) }
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=1102 }          # Log cleared
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 }
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 }
```

**Process execution with command lines** (Sysmon EID 1, always has cmdline):

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } -MaxEvents 100 |
  Where-Object { $_.Message -match "powershell|cmd.exe|rundll32" } |
  Select-Object TimeCreated, Message
```

**Query a remote host** (needs WinRM permissions):

```powershell
Invoke-Command -ComputerName SERVER01 -ScriptBlock {
  Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } -MaxEvents 10
}
```

**Command-line wevtutil** (legacy, for scripting):

```cmd
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /f:text /c:50
wevtutil qe Microsoft-Windows-Sysmon/Operational "/q:*[System[(EventID=3)]]" /f:text /c:20
```

---

## Memorize These One-Liners (PowerShell)

```powershell
# Top CPU processes (possible cryptominer / beacon)
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Everything a given user has running
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "jdoe|suspicious" } |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine

# Listening ports mapped to processes
Get-NetTCPConnection -State Listen | ForEach-Object {
  Get-Process -Id $_.OwningProcess } | Select-Object Id, ProcessName, Path

# Failed logons in the last 24h (brute force?)
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1) } |
  Group-Object { $_.Properties[13].Value } | Sort-Object Count -Descending

# Recent PowerShell script blocks (encoded / IEX hunting)
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } |
  Where-Object { $_.Message -match "DownloadString|FromBase64String|IEX|Invoke-Expression" }

# New services (installed since boot)
Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045 }

# Hash + upload path for a dropped file
Get-FileHash $env:TEMP\payload.exe -Algorithm SHA256

# Autoruns-style quick check (Run keys + startup folders)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
```

---

## Summary — L1 Must Know

- [ ] `tasklist /fi "imagename eq ..."` and `Get-CimInstance Win32_Process` for process + command-line enumeration
- [ ] Spot imposter processes: legitimate names in `Temp`/`AppData`, command line mismatching the binary
- [ ] Decode base64 `-enc` payloads and recognize `IEX`, `DownloadString`, `FromBase64String` indicators
- [ ] `netstat -ano`/`-anob` and `Get-NetTCPConnection` + `Get-Process -Id` to map ports to processes
- [ ] `sc qc`, `schtasks /query /fo LIST /v`, `Get-ScheduledTask` for service/task persistence
- [ ] Check Run/RunOnce keys, Startup folders, and WMI event subscriptions for persistence
- [ ] `whoami /all`, `net localgroup administrators`, `Get-LocalUser`, `Get-LocalGroupMember` for account review
- [ ] 4624/4625 logon types (2/3/9/10) and correlate 4672 (special logon) and 1102 (log cleared)
- [ ] `wmic qfe`/`Get-HotFix` for patch status when triaging severity
- [ ] `dir /a /o-d`, `Get-ChildItem -Force -Recurse` on temp dirs, and `Get-FileHash -Algorithm SHA256`
- [ ] Hunt ADS with `dir /r` / `Get-Item -Stream *` (anything beyond `:$DATA`)
- [ ] Query Security, PowerShell (4104), and Sysmon logs with `Get-WinEvent` filter hashtables
