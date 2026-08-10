# Module 19: Common Attacks — Detection & Triage

**Priority: P0 — L1 sees these daily. Recognize patterns, map to MITRE, triage fast.**

---

## 19.1 Attack Categories & Detection Matrix

| Category | Key Attacks | Primary Data Sources | MITRE Tactics |
|----------|-------------|---------------------|---------------|
| **Identity** | Brute Force, Password Spray, Credential Stuffing, MFA Bypass | Auth logs (4624/4625/4776), VPN, MFA, Azure AD | Initial Access, Credential Access |
| **Endpoint** | Malware, Ransomware, Process Injection, LOLBins, Living-off-Land | EDR, Sysmon, 4688, 4104, AMSI | Execution, Defense Evasion, Persistence |
| **Network** | C2, Lateral Movement, Scanning, Exfil, Tunneling | NDR, Zeek, Firewall, Proxy, NetFlow, DNS | C2, Lateral, Exfil, Discovery |
| **Web** | SQLi, XSS, SSRF, LFI/RFI, RCE, Web Shell | WAF, App logs, Proxy, EDR (web server) | Initial Access, Execution, Collection |
| **Email** | Phishing, BEC, Malware Delivery, Consent Phishing | Email Gateway, User Reports, Sandbox | Initial Access |
| **Identity/AD** | Kerberoasting, AS-REP Roasting, PtH, PtT, Golden/Silver Ticket, Delegation | 4768/4769/4771/4776, BloodHound, EDR | Credential Access, Privilege Escalation, Lateral |
| **Cloud** | Suspicious Login, Impossible Travel, Privilege Escalation, Data Access | Azure AD/Entra ID, AWS CloudTrail, GCP Audit Logs | Initial Access, Persistence, Collection |

---

## 19.2 Identity Attacks — Detection Patterns

### 1. Brute Force (Single Account, Many Passwords)
```kql
// 4625 (Failed) → 4624 (Success) same account, same source, short time
SecurityEvent
| where EventID in (4625, 4624)
| where TargetUserName == "target_user"
| summarize 
    FailCount=countif(EventID==4625),
    SuccessCount=countif(EventID==4624),
    FirstFail=minif(TimeGenerated, EventID==4625),
    LastFail=maxif(TimeGenerated, EventID==4625),
    FirstSuccess=minif(TimeGenerated, EventID==4624)
  by TargetUserName, IpAddress, Computer
| where FailCount >= 10 and SuccessCount > 0
| where FirstSuccess between (FirstFail .. datetime_add('minute', 30, LastFail))
```

### 2. Password Spray (Many Accounts, One Password)
```kql
// Many accounts, few failures each, same source, short time
SecurityEvent
| where EventID == 4625
| where Status == 0xC000006A  // Bad password
| summarize 
    TargetAccounts=dcount(TargetUserName),
    TotalFailures=count(),
    TimeSpan=max(TimeGenerated) - min(TimeGenerated)
  by IpAddress, Computer, bin(TimeGenerated, 30m)
| where TargetAccounts > 10 and TotalFailures < TargetAccounts * 3
| where TimeSpan < 30m
```

### 3. Credential Stuffing (Known Breached Creds)
```kql
// High volume, many IPs (botnet), known breach lists
SecurityEvent
| where EventID == 4625
| where Status == 0xC000006A
| join kind=leftouter (
    ThreatIntel
    | where IndicatorType == "Credential"
    | project Username=IndicatorValue
) on $left.TargetUserName == $right.Username
| where isnotempty(Username)  // Known breached credential
| summarize Count=count(), UniqueIPs=dcount(IpAddress) by TargetUserName, bin(TimeGenerated, 1h)
| where Count > 5
```

### 4. MFA Bypass / Fatigue
```kql
// Multiple MFA prompts → Accept
AzureADSignInLogs
| where AuthenticationRequirement == "MFA"
| where AuthenticationDetails has "MFA denied" or AuthenticationDetails has "MFA approved"
| summarize 
    DenyCount=countif(AuthenticationDetails has "MFA denied"),
    ApproveCount=countif(AuthenticationDetails has "MFA approved"),
    Devices=dcount(DeviceDetail)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where DenyCount > 3 and ApproveCount > 0
| where Devices > 1
```

---

## 19.3 Endpoint Attacks — Detection Patterns

### 1. Process Injection (T1055)
```kql
// Sysmon EID 8 (CreateRemoteThread) + EID 10 (ProcessAccess VM_READ/WRITE)
Sysmon
| where EventID in (8, 10)
| where TargetImage == "C:\\Windows\\System32\\lsass.exe"  // Credential theft
| or (EventID == 8 and SourceImage != TargetImage and TargetImage in ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\explorer.exe"))
| project TimeGenerated, Computer, SourceImage, TargetImage, SourceProcessId, TargetProcessId, GrantedAccess
```

### 2. LOLBin Execution
```kql
// Suspicious parent-child + network
Sysmon
| where EventID == 1
| where Image has_any ("certutil.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "installutil.exe", "msbuild.exe", "cscript.exe", "wscript.exe")
| where ParentImage !in ("cmd.exe", "powershell.exe", "explorer.exe")  // Unusual parent
| join kind=inner (
    Sysmon
    | where EventID == 3
    | project ProcessGuid, DestinationIp, DestinationPort
) on ProcessGuid
```

### 3. Ransomware Behavior
```kql
// Mass file modification + entropy + ransom notes
FileEvents
| where Action in ("Modified", "Created", "Renamed")
| where Extension in (".lockbit", ".contii", ".blackcat", ".ransom") or Entropy > 7.5
| summarize 
    Count=count(), 
    Extensions=make_set(Extension), 
    RansomNotes=countif(FileName has "README" or FileName has "HOW_TO" or FileName has "DECRYPT")
  by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where Count > 100 or RansomNotes > 0
```

### 4. Persistence (Run Keys, Services, Tasks)
```kql
// Sysmon EID 12/13 (Registry) + EID 4 (Service) + 4698 (Task)
Sysmon
| where EventID in (12, 13)
| where TargetObject has_any ("\\Run\\", "\\RunOnce\\", "\\Winlogon\\", "\\Services\\", "\\WMI\\")
| where Image != "C:\\Windows\\System32\\services.exe"  // Not legitimate service install
| project TimeGenerated, Computer, Image, TargetObject, Details, User
```

---

## 19.4 Network Attacks — Detection Patterns

### 1. C2 Beaconing
```kql
// Regular interval, small packets, long duration
// See Module 15 for detailed query
```

### 2. Lateral Movement (SMB, RDP, WinRM)
```kql
// Internal → Internal on admin ports
FirewallLogs
| where SourceIp in (internal_ranges) and DestinationIp in (internal_ranges)
| where DestinationPort in (445, 3389, 5985, 5986, 135, 139)
| where Action == "Allow"
| summarize Count=count(), Ports=make_set(DestinationPort) by SourceIp, DestinationIp, bin(TimeGenerated, 1h)
| where Count > 10
```

### 3. Internal Scanning
```kql
// One source → many destinations, same port
FirewallLogs
| where SourceIp in (internal_ranges) and DestinationIp in (internal_ranges)
| where DestinationPort in (445, 3389, 1433, 3306, 5432, 22, 23)
| summarize TargetCount=dcount(DestinationIp) by SourceIp, DestinationPort, bin(TimeGenerated, 5m)
| where TargetCount > 20
```

### 4. DNS Tunneling
```kql
// High entropy subdomains, TXT/NULL, high volume
DnsEvents
| extend Subdomain = split(QueryName, ".")[0]
| extend Entropy = calculate_shannon_entropy(Subdomain)
| where Entropy > 3.5 and strlen(Subdomain) > 30
| where QueryType in ("TXT", "NULL", "CNAME") or ResponseCode == "NXDOMAIN"
| summarize Count=count(), AvgEntropy=avg(Entropy) by SrcIp, bin(TimeGenerated, 1h)
| where Count > 500
```

---

## 19.5 Web Attacks — Detection Patterns

### 1. SQL Injection
```kql
// WAF / Proxy logs
WebLogs
| where cs_uri_query has_any ("'", "\"", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "OR 1=1", "'--", "';--")
| or cs_uri_query matches regex @"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E)"
| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
| where Count > 5
```

### 2. XSS (Cross-Site Scripting)
```kql
WebLogs
| where cs_uri_query has_any ("<script>", "javascript:", "onerror=", "onload=", "alert(", "document.cookie", "eval(")
| or cs_uri_query matches regex @"(%3Cscript%3E|javascript%3A|onerror%3D|onload%3D)"
| summarize Count=count() by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
```

### 3. SSRF (Server-Side Request Forgery)
```kql
// Outbound from web server to internal/metadata
WebLogs
| where cs_host in (web_server_ips)
| where cs_method in ("GET", "POST")
| where cs_uri_query has_any ("169.254.169.254", "127.0.0.1", "localhost", "metadata.google.internal", "metadata.azure.com")
| or cs_referer has_any ("169.254.169.254", "metadata.")
```

### 4. Web Shell
```kql
// POST to script with cmd/exec params
WebLogs
| where cs_method in ("POST", "PUT")
| where cs_uri_stem has_any (".php", ".jsp", ".asp", ".aspx", ".cfm", ".pl", ".py")
| where cs_uri_query has_any ("cmd=", "exec=", "shell=", "system=", "passthru=", "eval(", "assert(")
| summarize Count=count(), Commands=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
| where Count > 5
```

---

## 19.6 AD/Identity Attacks — Detection Patterns

### 1. Kerberoasting
```kql
// 4769 with RC4 targeting service accounts
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == 23  // RC4
| where TargetUserName has "@"  // SPN format
| summarize Count=count(), Services=make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where Count > 10
```

### 2. AS-REP Roasting
```kql
// 4768 no pre-auth + 4771 failures
SecurityEvent
| where EventID == 4768 and PreAuthType == 0
| join kind=inner (
    SecurityEvent
    | where EventID == 4771
    | project TargetUserName, TimeGenerated, FailureCode
) on TargetUserName
| where FailureCode == 0x18
```

### 3. Pass-the-Hash
```kql
// NTLM success without prior failure, unusual source
SecurityEvent
| where EventID == 4624 and LogonType == 3 and AuthenticationPackage == "NTLM"
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4625 and LogonType == 3
    | project TargetUserName, IpAddress, TimeGenerated
) on TargetUserName, IpAddress
```

### 4. Golden Ticket
```kql
// TGT with anomalous lifetime / PAC
SecurityEvent
| where EventID == 4768
| where TicketOptions has "renewable"
| // Look for: renew-till > 10 years, unusual groups in PAC
| // Better: EDR detection of forged tickets, krbtgt password age > 180 days
```

### 5. RBCD (Resource-Based Constrained Delegation)
```kql
// 5136: msDS-AllowedToActOnBehalfOfOtherIdentity modified
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "msDS-AllowedToActOnBehalfOfOtherIdentity"
| where OperationType == "Add" or OperationType == "Replace"
| project TimeGenerated, Computer, ObjectDN, AttributeValue, SubjectUserName
```

---

## 19.7 Cloud Attacks — Detection Patterns

### 1. Impossible Travel
```kql
AzureADSignInLogs
| where ResultType == 0  // Success
| order by UserPrincipalName, TimeGenerated asc
| extend PrevTime = prev(TimeGenerated), PrevGeo = prev(Location), PrevIP = prev(IpAddress)
| where isnotempty(PrevTime)
| extend TimeDiff = TimeGenerated - PrevTime
| extend Distance = geo_distance(PrevGeo, Location)  // Custom function
| extend Speed = Distance / TimeDiff  // km/h
| where Speed > 1000  // Impossible (plane ~900 km/h)
| project UserPrincipalName, TimeGenerated, PrevTime, Location, PrevGeo, IpAddress, PrevIP, Speed
```

### 2. Suspicious App Consent (Consent Phishing)
```kql
AzureADAuditLogs
| where OperationName == "Consent to application"
| where TargetResources has "Mail.Read" or TargetResources has "Files.ReadWrite.All" or TargetResources has "User.Read.All"
| where InitiatedBy.user.userPrincipalName in (high_value_users)
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources, Result, ResultReason
```

### 3. Privilege Escalation (Role Assignment)
```kql
AzureADAuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role")
| where TargetResources has "Global Administrator" or TargetResources has "Privileged Role Administrator" or TargetResources has "Security Administrator"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources, TargetResources.id, Result
```

---

## 19.8 Attack Chain Correlation — Putting It Together

### Example: Phishing → Ransomware
```
1. INITIAL ACCESS (TA0001)
   Alert: Phishing email delivered (Email Gateway)
   Evidence: Malicious .docm, user clicked, macro executed
   MITRE: T1566.001

2. EXECUTION (TA0002)
   Alert: Suspicious PowerShell (EDR)
   Evidence: WINWORD → POWERSHELL -enc → Download payload
   MITRE: T1059.001, T1105

3. PERSISTENCE (TA0003)
   Alert: Registry Run Key (Sysmon)
   Evidence: HKCU\Run\Update added with payload path
   MITRE: T1547.001

4. CREDENTIAL ACCESS (TA0006)
   Alert: LSASS Access (EDR)
   Evidence: Payload → rundll32 → LSASS OpenProcess VM_READ
   MITRE: T1003.001

5. LATERAL MOVEMENT (TA0008)
   Alert: SMB Admin$ Access (NDR)
   Evidence: Compromised host → File server via SMB admin$
   MITRE: T1021.002

6. IMPACT (TA0040)
   Alert: Mass File Encryption (EDR)
   Evidence: Payload encrypts files, drops ransom note
   MITRE: T1486

CORRELATION: Single Campaign (same payload hash, same C2, same user)
ESCALATION: P1 → IR Team engaged
```

---

## 19.9 Interview Questions for This Module

1. **How do you distinguish brute force from password spray in auth logs?**
   - Brute Force: One account, many passwords, same source. Password Spray: Many accounts, one/few passwords, same source.

2. **What EDR/Sysmon events detect process injection?**
   - Sysmon EID 8 (CreateRemoteThread), EID 10 (ProcessAccess with VM_READ/WRITE/ALL_ACCESS), EID 25 (Process Tampering). EDR: Memory API monitoring.

3. **How do you detect Kerberoasting?**
   - 4769 (TGS-REQ) with TicketEncryptionType=23 (RC4) targeting service accounts (SPNs). High volume from single user.

4. **What is RBCD and how do you detect it?**
   - Resource-Based Constrained Delegation. Detect via 5136: msDS-AllowedToActOnBehalfOfOtherIdentity modification (Add/Replace).

5. **How do you identify impossible travel in cloud logs?**
   - Successful sign-ins from geographically distant locations within impossible time window (speed > 1000 km/h).

6. **What web attack patterns do you look for in proxy/WAF logs?**
   - SQLi (UNION, SELECT, '), XSS (<script>, javascript:), SSRF (169.254.169.254, metadata), Web Shell (POST to .php/.asp with cmd=).

7. **How do you correlate a multi-stage attack chain?**
   - Same payload hash, same C2 infrastructure, same user/host, same timeframe, MITRE tactics in sequence (Initial Access → Execution → Persistence → Cred Access → Lateral → Impact).

8. **What are the key differences between Pass-the-Hash and Pass-the-Ticket?**
   - PtH: NTLM hash used for NTLM auth (SMB, WinRM). PtT: Kerberos ticket (TGT/ST) injected for Kerberos auth. PtH uses 4776/4624 Type 3; PtT uses 4624 Type 9.

9. **How do you detect DNS tunneling?**
   - High entropy subdomains, high query volume, TXT/NULL records, regular intervals, NXDOMAIN responses.

10. **What is a "Golden Ticket" and how do you detect it?**
    - Forged TGT using krbtgt hash. Detect: anomalous TGT lifetime/renewal, unusual PAC groups, krbtgt password age > 180 days, EDR forged ticket detection.

---

## 19.10 Study Checklist for Module 19

- [ ] Write KQL for: Brute Force, Password Spray, Credential Stuffing, MFA Bypass
- [ ] Write KQL for: Process Injection, LOLBin, Ransomware, Persistence
- [ ] Write KQL for: C2 Beaconing, Lateral Movement, Internal Scanning, DNS Tunneling
- [ ] Write KQL for: SQLi, XSS, SSRF, Web Shell
- [ ] Write KQL for: Kerberoasting, AS-REP Roasting, PtH, Golden Ticket, RBCD
- [ ] Write KQL for: Impossible Travel, Consent Phishing, Cloud Priv Esc
- [ ] Map example attack chain (Phishing → Ransomware) to MITRE with evidence
- [ ] Explain correlation methodology (hash, C2, user, host, timeframe, MITRE sequence)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 20 — Web Security*