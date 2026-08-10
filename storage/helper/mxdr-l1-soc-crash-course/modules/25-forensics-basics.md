# Module 25: Forensics Basics for L1 SOC Analysts

**Priority: P1 — Important for first months on the job**

> **Scope Note**: This module covers ONLY what an L1 analyst needs to know to preserve evidence, understand forensic artifacts, and support the IR/forensics team. It is NOT a digital forensics certification course.

---

## 25.1 Why Forensics Basics Matter for L1

### L1 Forensics Role: Preserve → Document → Handoff
```
L1 DISCOVERS INCIDENT
        │
        ▼
┌───────────────────────┐
│  PRESERVE EVIDENCE    │  ◀── Critical: Don't destroy what forensics needs
│  (Before Containment) │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  DOCUMENT EVERYTHING  │  ◀── Timeline, actions, artifacts, queries
│  (Chain of Custody)   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  HANDOFF TO IR/FORENSICS │  ◀── Complete package for deep analysis
└───────────────────────┘
```

### What L1 Does NOT Do
- ❌ Memory analysis (Volatility, Rekall)
- ❌ Disk imaging (FTK Imager, dd, ewf)
- ❌ Malware reverse engineering (IDA, Ghidra)
- ❌ Timeline reconstruction from raw artifacts (plaso, mactime)
- ❌ Expert testimony / legal evidence handling

### What L1 DOES Do
- ✅ Identify what artifacts exist and where
- ✅ Preserve volatile data before containment
- ✅ Collect logs, screenshots, query exports
- ✅ Document chain of custody for what they touch
- ✅ Explain artifacts to IR team: "Here's the Prefetch showing execution"
- ✅ Understand forensic reports from IR team

---

## 25.2 Chain of Custody Basics

### Core Principle
> **Evidence must be traceable from collection to court.** Every person who handles it must be documented.

### L1 Chain of Custody Log Entry
```
Evidence Item: EDR Timeline Export - WKS-0452
Collected By: J. Doe (Analyst ID: SOC-045)
Date/Time: 2024-01-15 10:25:12 UTC
Collection Method: CrowdStrike Falcon Console → Host Timeline → Export CSV
Hash (SHA256): a1b2c3d4e5f6... (calculated at collection)
Storage Location: SOC Evidence Share /INC-2024-001234/EDR_Timeline_WKS-0452.csv
Access Log: 
  2024-01-15 10:25 - J. Doe (collection)
  2024-01-15 14:30 - L2 Smith (review)
  2024-01-16 09:00 - Forensics Lead (ingestion)
```

### Minimum Documentation for Every Artifact
| Field | Example |
|-------|---------|
| **What** | "PowerShell command line from EDR process event" |
| **Where** | "CrowdStrike Falcon, Host WKS-0452, Event ID 12345" |
| **When Collected** | "2024-01-15 10:25:12 UTC" |
| **Who Collected** | "Analyst J. Doe (SOC-045)" |
| **How Collected** | "EDR Console → Process Timeline → Copy Command Line" |
| **Hash** | "SHA256: a1b2c3... (of exported file)" |
| **Storage** | "SOC Evidence Share /INC-2024-001234/" |

---

## 25.3 Evidence Preservation: Before Containment

### Volatile Data (Lost on Reboot/Isolation) — Capture FIRST
| Priority | Artifact | How to Capture (L1) |
|----------|----------|---------------------|
| **1** | Running processes + command lines | EDR timeline export, `ps`/`tasklist` screenshot |
| **2** | Network connections | EDR network view, `netstat -ano` / `ss -tunap` screenshot |
| **3** | Open files / deleted files still open | EDR file events, `lsof` / Process Hacker screenshot |
| **4** | Loaded modules / DLLs | EDR image load events, `listdlls` / Process Hacker |
| **5** | Memory (if capability exists) | **Call IR/Forensics** — L1 typically cannot dump memory |
| **6** | Clipboard contents | Rarely accessible remotely — note if observed |

### Non-Volatile Data (Persists) — Capture Before Wipe/Rebuild
| Artifact | Source | L1 Collection Method |
|----------|--------|---------------------|
| Windows Event Logs | SIEM / Forwarder | SIEM query export (TimeGenerated, EventID, all fields) |
| Sysmon Logs | SIEM / Forwarder | SIEM query export |
| EDR Telemetry | EDR Console | Full timeline export (CSV/JSON) |
| Firewall/Proxy Logs | SIEM | SIEM query export |
| DNS Logs | SIEM / DNS Server | SIEM query export |
| Email Headers | Email Security / User | Forward as .eml / save from portal |
| File System (MFT, $LogFile) | Disk Image | **Forensics Team Only** — L1 requests image |
| Registry Hives | Disk Image / Live | **Forensics Team** — L1 notes keys of interest |
| Memory Dump | RAM | **Forensics Team** — L1 requests |

---

## 25.4 Windows Forensic Artifacts — What L1 Must Recognize

### 1. Prefetch (`C:\Windows\Prefetch\*.pf`)
| What It Is | What L1 Needs to Know |
|------------|----------------------|
| Windows creates `.pf` when executable runs | **Proves execution** — even if file deleted |
| Contains: executable name, run count, last run times (up to 8), files referenced | **Run count + timestamps** = frequency & recency |
| Naming: `EXECUTABLE-NAME-HASH.pf` | Hash = path hash, not file hash |
| **L1 Action**: Request IR to parse; note executable names in ticket |

### 2. Amcache (`C:\Windows\AppCompat\Programs\Amcache.hve`)
| What It Is | What L1 Needs to Know |
|------------|----------------------|
| Registry hive tracking program execution | **Persistent record** — survives reboot, user deletion |
| Contains: file path, SHA1 hash, publisher, first/last run, file size | **SHA1 hash** = pivot to VT/sandbox |
| **L1 Action**: Note suspicious entries (temp paths, unsigned, odd names) |

### 3. Shimcache (AppCompatCache) — Registry
| What It Is | What L1 Needs to Know |
|------------|----------------------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Tracks **executed programs** (even from network shares) |
| Contains: path, file size, last modified time, execution flag | **Execution flag** = actually ran (not just present) |
| **L1 Action**: IR parses; L1 notes suspicious paths in ticket |

### 4. UserAssist — Registry
| What Is | What L1 Needs to Know |
|---------|----------------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | **GUI program execution** via Explorer (not CLI) |
| ROT13 encoded names, run count, last execution time | **Proves user interaction** — not just background process |
| **L1 Action**: IR parses; L1 correlates with user activity timeline |

### 5. Recent Files / Jump Lists
| What Is | What L1 Needs to Know |
|---------|----------------------|
| `%AppData%\Microsoft\Windows\Recent\` (LNK files) | Files **opened by user** via Explorer/Office |
| `%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\` (Jump Lists) | **DestList** = files accessed via app (Word, Excel, etc.) |
| **L1 Action**: Note accessed files (e.g., malicious doc, ransom note) |

### 6. LNK Files (Shortcuts)
| What Is | What L1 Needs to Know |
|---------|----------------------|
| `.lnk` files in Recent, Desktop, Start Menu | Contain: **target path, MAC times, volume serial, MAC address** |
| Created when user opens file/folder | **Proves access** — even to network shares |
| **L1 Action**: Request IR parse; note target paths in ticket |

### 7. Windows Event Logs (Revisited for Forensics)
| Log | Forensic Value |
|-----|----------------|
| **Security** (4624, 4625, 4688, 4698, 4702, 4703) | Auth, process creation, scheduled tasks |
| **System** (7045, 7036, 1074, 6005/6006/6008/6009/6013) | Service install, shutdown/reboot, crash |
| **PowerShell Operational** (4103, 4104) | Script block logging, module loading |
| **Microsoft-Windows-TerminalServices-LocalSessionManager** | RDP connect/disconnect |
| **Microsoft-Windows-Sysmon/Operational** | Process create, network, file, registry, DNS, etc. |

### 8. SRUM (System Resource Usage Monitor)
| What Is | What L1 Needs to Know |
|---------|----------------------|
| `%SystemRoot%\System32\sru\SRUDB.dat` | **Per-app network usage** (bytes sent/received) per hour |
| Tracks: App name, user, network bytes, CPU time | **Data exfil evidence** — which app sent how much |
| **L1 Action**: IR parses with `srum-dump`; L1 notes suspicious apps |

### 9. BAM/DAM (Background Activity Moderator / Desktop Activity Moderator)
| What Is | What L1 Needs to Know |
|---------|----------------------|
| Registry: `HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` | **Modern app execution** (UWP, packaged apps) |
| Contains: executable path, last background/foreground time | **Proves execution** of Store apps, modern malware |
| **L1 Action**: IR parses; L1 notes in timeline |

---

## 25.5 Linux Forensic Artifacts — What L1 Must Recognize

| Artifact | Location | Forensic Value |
|----------|----------|----------------|
| **Authentication Logs** | `/var/log/auth.log` or `/var/log/secure` | SSH logins, sudo, failed attempts |
| **System Logs** | `/var/log/syslog` or `/var/log/messages` | Service starts, cron, kernel events |
| **Auditd Logs** | `/var/log/audit/audit.log` | Syscall-level: execve, open, connect, setuid |
| **Bash History** | `~/.bash_history` | User commands (if not cleared) |
| **Cron Jobs** | `/etc/crontab`, `/var/spool/cron/`, `/etc/cron.*/` | Persistence |
| **Systemd Services** | `/etc/systemd/system/`, `/lib/systemd/system/` | Persistence, malicious services |
| **SSH Keys** | `~/.ssh/authorized_keys`, `/root/.ssh/` | Lateral movement, persistence |
| **Tmp Files** | `/tmp`, `/var/tmp`, `/dev/shm` | Malware staging, scripts |
| **Package Manager Logs** | `/var/log/dpkg.log`, `/var/log/yum.log` | Software installation |
| **Journalctl** | Binary logs (`journalctl -u service`) | Service-specific, structured |

---

## 25.6 Browser Artifacts (When User Compromise Suspected)

| Browser | Key Artifacts | Location (Windows) |
|---------|--------------|-------------------|
| **Chrome/Edge** | History, Downloads, Cookies, Login Data, Cache | `%LocalAppData%\Google\Chrome\User Data\Default\`<br>`%LocalAppData%\Microsoft\Edge\User Data\Default\` |
| **Firefox** | Places.sqlite (history/bookmarks), Downloads, Cookies | `%AppData%\Mozilla\Firefox\Profiles\xxxx.default\` |

### What L1 Can Extract (If Accessible)
- **Download history**: Malicious file source
- **URL history**: Phishing sites, C2 panels, credential harvesters
- **Cookies**: Session tokens (if stolen)
- **Autofill/Login Data**: Saved credentials (encrypted but extractable)

> **L1 Note**: Browser forensics requires specialized tools (DB Browser for SQLite, BrowserHistoryView). L1 documents locations; IR extracts.

---

## 25.7 Email Forensics Basics

### Header Analysis (L1 Must Know)
```
Key Headers to Extract:
─────────────────────
Return-Path: <attacker@evil.com>       → Actual sender (SMTP MAIL FROM)
Received: from mail.evil.com (192.0.2.1) → Hop-by-hop path (read BOTTOM to TOP)
Received-SPF: fail                      → SPF check result
DKIM-Signature: v=1; d=evil.com         → DomainKeys Identified Mail
DMARC: fail                             → Domain-based Message Authentication
Message-ID: <unique@evil.com>           → Unique identifier
X-Originating-IP: [192.0.2.1]           → Client IP (if added by provider)
```

### L1 Email Investigation Checklist
```
[ ] Save original email as .eml (preserves headers)
[ ] Extract all headers (not just displayed)
[ ] Check SPF/DKIM/DMARC results
[ ] Analyze Received chain (find true origin)
[ ] Extract URLs → reputation check
[ ] Extract attachments → hash → sandbox/VT
[ ] Check sender domain: WHOIS, age, reputation
[ ] Check Reply-To vs From mismatch
[ ] Search SIEM for other recipients
[ ] Search Proxy/DNS for URL clicks
```

---

## 25.8 File & Disk Forensics Concepts (Awareness Level)

### NTFS Artifacts L1 Should Know Exist
| Artifact | What It Tracks | Tool to Parse |
|----------|---------------|---------------|
| **MFT ($MFT)** | Every file: name, timestamps (MAC), size, attributes, resident data | `MFTECmd`, `AnalyzeMFT`, `autopsy` |
| **$LogFile** | Transaction log for NTFS metadata changes | `LogFileParser` |
| **$UsnJrnl** | Change journal: file create/delete/rename/modify | `UsnParser`, `MFTECmd` |
| **$I30 (Index)** | Directory listings (including deleted) | `MFTECmd` |
| **$Bitmap** | Cluster allocation map | Recovery tools |

### Timestamp Forensics (MAC Times)
| Time | Meaning | Reliability |
|------|---------|-------------|
| **M**odified | File content changed | High (but can be timestomped) |
| **A**ccessed | File read/opened | Low (disabled by default on Win8+) |
| **C**reated | File created on volume | Medium (can change on copy) |
| **E**ntry Modified (MFT) | MFT record changed | High (harder to forge) |

> **Timestomping**: Attackers modify timestamps. L1 should note: "Timestamps may be manipulated; verify with $LogFile/$UsnJrnl (IR task)."

### Alternate Data Streams (ADS)
- `file.txt:malicious.exe` — Hidden data attached to file
- Used for: Hiding malware, evading AV
- Detection: `dir /r` (Windows), `ls -la` (Linux xattr), EDR file events
- **L1 Action**: Note if EDR alerts on ADS; request IR deep dive

---

## 25.9 Memory Forensics Concepts (Awareness Only)

### What Memory Contains (Why Forensics Wants It)
| Artifact | Why It Matters |
|----------|---------------|
| **Running processes** | Hidden/unlinked processes, process hollowing |
| **Command lines** | Full commands (may differ from disk) |
| **Network connections** | Active C2, listening ports |
| **Loaded DLLs/modules** | Injected code, reflective loading |
| **Registry keys** | Decrypted in memory |
| **Encryption keys** | Ransomware keys, VeraCrypt/BitLocker keys |
| **Malware config** | C2 IPs, campaign IDs, mutexes |
| **Clipboard** | Stolen credentials, crypto addresses |

### L1 Role with Memory
- **Cannot acquire** (needs admin + tools: WinPMEM, dumpit, lime)
- **Can request** IR/Forensics to acquire
- **Can identify need**: "Process X injected into Y — memory needed to see shellcode"
- **Can analyze basics** if provided Volatility output (process list, netscan, cmdline)

---

## 25.10 Evidence Packaging for Handoff

### L1 Evidence Package Structure
```
/INC-2024-001234/
├── 00_README.md                    # Case summary, analyst, timeline
├── 01_ALERTS/
│   ├── original_alert.json         # Raw alert from SIEM/EDR
│   └── alert_screenshot.png
├── 02_HOST_INVESTIGATION/
│   ├── host_WKS-0452_timeline.csv  # EDR full timeline export
│   ├── process_tree.png            # EDR process tree screenshot
│   ├── network_connections.png     # EDR network view screenshot
│   └── detection_details.png       # EDR detection details
├── 03_QUERY_EXPORTS/
│   ├── auth_events_j_smith.csv     # SIEM query: 4624/4625 for user
│   ├── process_events_WKS-0452.csv # SIEM query: 4688 for host
│   └── network_ioc_search.csv      # SIEM query: evil.com/1.2.3.4
├── 04_THREAT_INTEL/
│   ├── vt_hash_a1b2c3.json         # VirusTotal result
│   ├── abuseipdb_1.2.3.4.json      # AbuseIPDB result
│   └── urlscan_evil.com.json       # URLScan result
├── 05_IOCS/
│   └── iocs.yaml                   # Structured IOCs for blocking
├── 06_ANALYSIS/
│   ├── investigation_notes.md      # 20-question answers, hypothesis
│   ├── mitre_mapping.xlsx          # Technique mapping
│   └── timeline.xlsx               # Event timeline
└── 07_CONTAINMENT/
    ├── containment_actions.log     # What, when, who approved
    └── evidence_preserved.log      # What captured before containment
```

### IOC Export Format (YAML Example)
```yaml
incident: INC-2024-001234
analyst: J. Doe
date: 2024-01-15
iocs:
  - type: ipv4
    value: 192.0.2.100
    confidence: high
    source: "EDR network event + AbuseIPDB 85%"
    tags: ["C2", "Cobalt Strike"]
    first_seen: "2024-01-15T10:23:45Z"
  - type: domain
    value: evil.com
    confidence: high
    source: "VT 12/90 malicious, URLScan"
    tags: ["C2", "Phishing"]
  - type: file_hash
    value: "sha256:a1b2c3d4e5f6..."
    confidence: high
    source: "EDR process event + VT malicious"
    tags: ["Ransomware", "LockBit"]
    filename: "payload.exe"
```

---

## 25.11 Common L1 Forensics Mistakes

| Mistake | Consequence | Correct Approach |
|---------|-------------|------------------|
| Isolating host before capturing process list | Lost volatile evidence | Capture EDR timeline → THEN isolate |
| Rebooting compromised host | Memory, encrypted files, keys lost | NEVER reboot; isolate network only |
| Running AV scan on compromised host | Destroys timestamps, artifacts | Hands off — forensics first |
| Deleting/moving suspicious files | Spoliation, chain of custody broken | Preserve in place; document location |
| Not hashing exported evidence | Cannot prove integrity later | SHA256 every export at collection time |
| Screenshots without timestamps | Timeline ambiguity | Include clock in screenshot or timestamp in filename |
| Sharing evidence via email/Slack | Chain of custody broken, data leak | Use approved evidence share with access logging |
| Not documenting "negative" findings | Incomplete picture for IR | "No lateral movement found in last 7 days" is valuable |

---

## 25.12 Tools L1 Should Know Exist (Not Necessarily Use)

| Category | Tools | L1 Knowledge Level |
|----------|-------|-------------------|
| **Disk Imaging** | FTK Imager, Guymager, dd/ewfacquire, Arsenal Image Mounter | Know they exist; know write-blocker required |
| **Memory Acquisition** | WinPMEM, DumpIt, LiME, AVML | Know IR acquires; know volatile data lost on reboot |
| **Log Parsing** | EVTXECmd, EvtxAnalyzer, Chainsaw, Hayabusa | Use SIEM instead; know for offline analysis |
| **Artifact Parsing** | MFTECmd, AmcacheParser, AppCompatCacheParser, PECmd, RECmd, JumpListParser, LECmd | Know what each parses; request IR to run |
| **Timeline** | Plaso (log2timeline), Timesketch | Know IR builds super-timeline |
| **Memory Analysis** | Volatility 3, Rekall | Know IR uses; can read basic output (pslist, netscan) |
| **Malware Analysis** | CAPE, Cuckoo, Joe Sandbox, Any.Run, Hybrid Analysis | Submit hashes; read reports |
| **Forensic Suites** | Autopsy, FTK, EnCase, X-Ways | Know IR uses; L1 doesn't |

---

## 25.13 Summary: What L1 Must Know

- [ ] Chain of custody: what, where, when, who, how, hash, storage
- [ ] Evidence preservation ORDER: volatile first (processes, network), then non-volatile
- [ ] NEVER reboot or run AV on compromised host before forensics
- [ ] Key Windows artifacts: Prefetch, Amcache, Shimcache, UserAssist, LNK, Jump Lists, SRUM, BAM, Event Logs, MFT/$LogFile/$UsnJrnl
- [ ] Key Linux artifacts: auth.log, audit.log, bash_history, cron, systemd, SSH keys, /tmp
- [ ] Browser/Email artifacts exist; know what they contain; save .eml
- [ ] Timestamp forensics: MAC times, timestomping risk, MFT entry modified time
- [ ] Alternate Data Streams (ADS) for hiding data
- [ ] Memory forensics value; L1 requests acquisition, doesn't perform
- [ ] Evidence package structure for IR handoff
- [ ] IOC export in structured format (YAML/JSON/STIX)
- [ ] Common mistakes: rebooting, scanning, deleting, not hashing, breaking chain of custody