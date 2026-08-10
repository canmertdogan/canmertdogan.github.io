# IOC / IOA / TTP Cheat Sheet for SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## Definitions — Know the Difference

| Term | Full Name | What It Is | Example | Question It Answers |
|------|-----------|------------|---------|---------------------|
| **IOC** | Indicator of Compromise | **Static artifact** — forensic evidence left behind | IP, hash, domain, URL, email, registry key, mutex | "What did we see?" (Past tense) |
| **IOA** | Indicator of Attack | **Behavioral pattern** — sequence of actions showing intent | Process tree, command sequence, network pattern | "What are they doing?" (Present tense) |
| **TTP** | Tactics, Techniques, Procedures | **Adversary methodology** — how they operate | Phishing → PowerShell → Persistence → LSASS dump → SMB lateral | "How do they operate?" (General) |

---

## IOC Types & Formats

### 1. Network Indicators
| Type | Format | Example | Context |
|------|--------|---------|---------|
| **IPv4** | `x.x.x.x` | `192.0.2.100` | C2, scanner, exfil destination |
| **IPv6** | `xxxx:xxxx:...` | `2001:db8::1` | Modern infrastructure |
| **CIDR** | `x.x.x.x/n` | `192.0.2.0/24` | Hosting provider range, Tor exit nodes |
| **Domain** | `example.com` | `evil.com` | C2, phishing, malware distribution |
| **Subdomain** | `sub.example.com` | `cdn.evil.com` | Specific campaign infrastructure |
| **URL** | `http(s)://...` | `http://evil.com/payload.exe` | Phishing link, malware download |
| **URI Path** | `/path/to/resource` | `/api/v1/beacon` | C2 endpoint pattern |
| **Email** | `user@domain.com` | `attacker@phishersite.xyz` | Sender, Reply-To, phishing campaigns |
| **ASN** | `ASxxxx` | `AS12345` | Hosting provider, bulletproof hoster |
| **JA3/JA3S** | `md5` | `a0e9f5d64349fb13191bc781f81f42e1` | TLS client/server fingerprint |

### 2. Host Indicators
| Type | Format | Example | Context |
|------|--------|---------|---------|
| **File Hash (MD5)** | 32 hex | `d41d8cd98f00b204e9800998ecf8427e` | Legacy, fast lookup |
| **File Hash (SHA1)** | 40 hex | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | Legacy, Git |
| **File Hash (SHA256)** | 64 hex | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | **Standard** — use this |
| **File Hash (SHA512)** | 128 hex | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` | High security |
| **IMPHASH** | 32 hex | `f34d5f2d4b7e8a9c1d2e3f4a5b6c7d8e` | PE import table — malware family |
| **SSDEEP** | `size:hash:hash` | `1536:AbC:DeF` | Fuzzy hash — similar files |
| **TLSH** | `T1...` | `T1A2B3C4D5E6F7...` | Trend Micro local sensitivity hash |
| **Mutex** | `Global\Name` | `Global\EmotetMutex` | Malware synchronization object |
| **Registry Key** | `HKLM\Path` | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | Persistence |
| **Service Name** | `ServiceName` | `WindowsDefenderUpdate` | Malicious service |
| **Scheduled Task** | `TaskName` | `Microsoft\Windows\Update\Updater` | Persistence |
| **Pipe Name** | `\\.\pipe\Name` | `\\.\pipe\CobaltStrike_1234` | C2 communication |
| **WMI Namespace/Class** | `root\cimv2:Class` | `root\subscription:__EventFilter` | WMI persistence |

---

## IOC Confidence Levels

| Level | Definition | Action |
|-------|------------|--------|
| **High** | Verified malicious by multiple sources; seen in active incidents | **Auto-block** (pre-approved playbook) |
| **Medium** | Suspicious; single source or low-reputation; context-dependent | **Analyst review** required before block |
| **Low** | Weak signal; unknown; potential FP | **Monitor** / enrich / do not block |
| **Benign** | Confirmed legitimate | **Allowlist** / suppress |

### Confidence Factors
| Factor | Increases Confidence | Decreases Confidence |
|--------|---------------------|---------------------|
| **Source** | Multiple TI feeds, internal incident, vendor advisory | Single unverified feed, blog post |
| **Context** | Seen in your environment, matches campaign | No context, generic list |
| **Age** | Recent (hours/days), active campaign | Old (months/years), sinkholed |
| **Behavior** | Active C2, malware execution, exfil | Passive, parked domain |
| **Prevalence** | Targeted (low prevalence) | Widespread (CDN, shared hosting) |

---

## IOA Patterns — Behavioral Detection

### Common IOA Patterns (Map to Detection Rules)
| IOA Name | Behavioral Pattern | MITRE Techniques | Detection Logic |
|----------|-------------------|------------------|-----------------|
| **Macro Malware Chain** | WINWORD/EXCEL → PowerShell/cmd → Network/Download | T1566.001, T1059.001, T1105 | Parent=Office, Child=Scripting |
| **PowerShell Download Cradle** | `IEX (New-Object Net.WebClient).DownloadString(...)` | T1059.001, T1105, T1027.010 | Encoded PS + WebClient/Invoke-WebRequest |
| **LOLBin Execution** | Signed binary (rundll32, certutil, regsvr32) from user-writable path | T1218.* | Signed binary + suspicious path/args |
| **Process Injection** | Process A → OpenProcess/WriteProcessMemory → Process B | T1055 | Sysmon EventID 8/10, cross-process |
| **Kerberoasting** | Single user → Many TGS requests (4769) for SPNs with RC4 | T1558.003 | Volume + RC4 + SPN pattern |
| **Pass-the-Hash** | NTLM logon (Type 3) from host where user has no interactive session | T1550.002 | 4624 Type 3 NTLM from unexpected host |
| **C2 Beaconing** | Regular interval, same destination, low volume, long duration | T1071.001 | Periodicity + same size + JA3 |
| **DNS Tunneling** | High-volume TXT/CNAME/MX to single domain, high-entropy subdomains | T1071.004 | Query type + volume + entropy |
| **Lateral Movement (SMB)** | Admin share (C$/ADMIN$) access from non-admin host | T1021.002 | EventID 5140 + source ≠ admin workstation |
| **Credential Dumping** | LSASS access (OpenProcess 0x1010) by non-legitimate process | T1003.001 | Sysmon EventID 10, GrantedAccess=0x1010 |
| **Persistence (Run Key)** | Registry write to Run/RunOnce by non-installer process | T1547.001 | Sysmon EventID 13, HKCU/HKLM Run |
| **Ransomware Encryption** | Mass file modification (rename/encrypt) + ransom note + VSS delete | T1486, T1490 | High file modify rate + .locked + vssadmin |
| **Data Staging** | Large file aggregation in temp/user profile before exfil | T1560.001 | Large archive creation in AppData/Temp |
| **Exfiltration** | Large outbound to unusual destination, compression, non-browser UA | T1041/T1048 | Volume + destination + process + UA |

---

## TTP Attribution — Common Threat Groups (L1 Awareness)

| Group | Origin | Known For | Key TTPs |
|-------|--------|-----------|----------|
| **APT28 (Fancy Bear)** | Russia (GRU) | Credential phishing, zero-days | T1566.002, T1190, T1059.001, T1003.001 |
| **APT29 (Cozy Bear)** | Russia (SVR) | Supply chain, cloud | T1195, T1078.004, T1530, T1578 |
| **APT41 (Wicked Panda)** | China | Ransomware + espionage, gaming | T1486, T1190, T1505.003, T1059.001 |
| **Lazarus Group** | North Korea | Crypto theft, destructive | T1485, T1486, T1566.001, T1105 |
| **FIN7 (Carbanak)** | Russia (Crime) | Financial, POS, phishing | T1566.001, T1059.001, T1005, T1041 |
| **FIN6** | Russia (Crime) | Retail, e-commerce | T1190, T1059.001, T1003.001, T1041 |
| ** Conti/TrickBot** | Russia (Crime) | Ransomware, banking | T1566.001, T1486, T1003.001, T1021.002 |
| **LockBit** | Russia (Crime/RaaS) | Ransomware, fast encryption | T1486, T1490, T1021.002, T1566.001 |
| **BlackCat/ALPHV** | Russia (Crime/RaaS) | Rust ransomware, extortion | T1486, T1485, T1021.002, T1567 |
| **Cl0p** | Russia (Crime) | Zero-day exploitation (MoveIT, GoAnywhere) | T1190, T1486, T1567, T1041 |

> **L1 Note**: Don't attribute. Use threat intel feeds that provide attribution. Report: "IOCs match FIN7 campaign per Vendor Advisory."

---

## IOC Lifecycle & Management

```
CREATION → VALIDATION → DEPLOYMENT → DETECTION → ENRICHMENT → RETIREMENT
```

| Phase | L1 Actions |
|-------|------------|
| **Creation** | Extract IOCs from investigation (hashes, IPs, domains, URLs) |
| **Validation** | Check against TI feeds, internal allowlists, prevalence |
| **Deployment** | Submit to SOAR/EDR/Firewall/Proxy blocklists via playbook |
| **Detection** | Alert fires → you triage → confirm TP/FP |
| **Enrichment** | Add context: campaign, actor, malware family, confidence |
| **Retirement** | Expire old IOCs (Tor exits change, domains sinkholed, IPs recycled) |

---

## IOC Sharing Formats

| Format | Use Case | Structure |
|--------|----------|-----------|
| **STIX 2.1** | Industry standard, TIPs, threat sharing | JSON-LD, objects (indicator, malware, attack-pattern) |
| **TAXII 2.1** | Transport protocol for STIX | HTTPS API, collections, polling |
| **OpenIOC** | Legacy, Mandiant | XML, indicator composition |
| **MISP** | Threat intel platform | JSON, events, attributes, tags, galaxies |
| **CSV/TSV** | Simple bulk import | `type,value,confidence,source,tlp,tags` |
| **JSON Lines** | Streaming, SIEM ingestion | One JSON object per line |

### Minimal IOC Export (CSV)
```csv
type,value,confidence,source,first_seen,last_seen,tlp,tags,description
ipv4,192.0.2.100,high,VT+AbuseIPDB,2024-01-15T10:23:00Z,2024-01-15T14:00:00Z,amber,C2:CobaltStrike,C2 server for Campaign X
domain,evil.com,high,VT+URLScan,2024-01-15T10:23:00Z,2024-01-15T14:00:00Z,amber,Phishing:C2,Phishing/C2 domain
sha256,a1b2c3d4e5f6...,high,EDR+VT,2024-01-15T10:23:00Z,2024-01-15T14:00:00Z,red,Malware:CobaltStrike,Cobalt Strike beacon
url,http://evil.com/payload.ps1,high,Decoded PS,2024-01-15T10:23:00Z,2024-01-15T14:00:00Z,amber,Payload:Download,Download cradle URL
```

---

## TLP (Traffic Light Protocol) — Sharing Restrictions

| Level | Color | Sharing Scope | Example |
|-------|-------|---------------|---------|
| **TLP:RED** | 🔴 | **Named individuals only** — not for org-wide | Active incident, sensitive source |
| **TLP:AMBER** | 🟠 | **Organization only** — need-to-know | Internal threat intel, specific campaign |
| **TLP:AMBER+STRICT** | 🟠+ | **Org only, not clients/partners** | Sensitive internal |
| **TLP:GREEN** | 🟢 | **Community** — peers, partners, ISACs | General threat trends, sanitized IOCs |
| **TLP:CLEAR** | ⚪ | **Public** — anyone | Published reports, blocklists |

**L1 Rule**: Default to TLP:AMBER for internal IOCs. Never share TLP:RED/AMBER externally.

---

## IOC Triage Checklist (Per IOC)

```
[ ] Type identified (IP, domain, hash, URL, email)
[ ] Format validated (valid IP, valid hash length, FQDN)
[ ] Confidence assessed (High/Medium/Low)
[ ] Source documented (VT, AbuseIPDB, internal, vendor advisory)
[ ] TLP assigned (RED/AMBER/GREEN/CLEAR)
[ ] Tags added (C2, Phishing, Malware:CobaltStrike, Ransomware:LockBit)
[ ] Context: first_seen, last_seen, campaign, actor (if known)
[ ] Allowlist checked (internal IPs, corporate domains, known good hashes)
[ ] Prevalence checked (VT detection ratio, passive DNS, WHOIS age)
[ ] Deployment: submitted to blocklists via playbook (if High confidence)
[ ] Documentation: added to ticket, IOC table, shared with team
```

---

## Common IOC Pitfalls (L1 Mistakes)

| Pitfall | Consequence | Fix |
|---------|-------------|-----|
| Blocking shared hosting IP (Cloudflare, AWS) | Legitimate traffic blocked | Check ASN, use domain-based blocking |
| Blocking sinkholed domain | No value, noise | Check if sinkholed (passive DNS, passive SSL) |
| Using MD5 only | Collisions, weak | Always use SHA256 |
| Not expiring IOCs | Stale blocks, FP | TTL: 30-90 days for IPs, 90-180 for domains |
| Sharing TLP:AMBER externally | Trust violation, legal risk | Verify TLP before sharing |
| No context in blocklist | Can't investigate later | Always include: source, date, confidence, ticket |
| Single-source IOC | High FP risk | Require 2+ sources or internal validation |

---

## ONE-PAGE PRINT VERSION

```
IOC / IOA / TTP — SOC L1 QUICK REFERENCE
=========================================

DEFINITIONS:
IOC = "What did we see?"     Static: IP, hash, domain, URL, email
IOA = "What are they doing?" Behavioral: process chain, beaconing, lateral
TTP = "How do they operate?" Methodology: ATT&CK tactics + techniques

IOC TYPES (Priority):
1. SHA256 hash          (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
2. IPv4 / CIDR          (192.0.2.100 / 192.0.2.0/24)
3. Domain / Subdomain   (evil.com / cdn.evil.com)
4. URL                  (http://evil.com/payload.exe)
5. Email                (attacker@phishersite.xyz)
6. JA3/JA3S             (a0e9f5d64349fb13191bc781f81f42e1)
7. Mutex / Registry / Pipe / WMI

CONFIDENCE:
High  = Multi-source + active + context → AUTO-BLOCK
Medium = Single source / needs review → ANALYST REVIEW
Low   = Weak / unknown → MONITOR
Benign = Confirmed good → ALLOWLIST

IOA PATTERNS (Detection Rules):
Macro Chain          : Office → PS/cmd → Network
PS Download Cradle   : IEX + WebClient/iwr + encoded
LOLBin               : Signed binary (rundll32/certutil) from AppData/Temp
Process Injection    : Cross-process OpenProcess/WriteMem
Kerberoasting        : Many 4769 RC4 for SPNs from single user
Pass-the-Hash        : NTLM Type 3 from unexpected host
C2 Beaconing         : Regular interval + same size + JA3 + duration
DNS Tunneling        : High TXT/CNAME volume + entropy subdomains
Lateral (SMB)        : C$/ADMIN$ from non-admin host
LSASS Dump           : Sysmon 10, GrantedAccess=0x1010
Persistence (Run)    : HKCU/HKLM Run key write by non-installer
Ransomware           : Mass encrypt + VSS delete + ransom note
Data Staging         : Large archive in AppData/Temp
Exfil                : Large outbound + non-browser UA + unusual dest

TTP (Top Groups — Awareness Only):
APT28/29 (Russia)  |  APT41 (China)  |  Lazarus (NK)
FIN7/FIN6 (Crime)  |  Conti/TrickBot |  LockBit/BlackCat
Cl0p (Zero-day)

IOC LIFECYCLE:
Extract → Validate → Deploy → Detect → Enrich → Retire

TLP (Sharing):
RED    = Named individuals only
AMBER  = Org only (need-to-know)
GREEN  = Community/peers
CLEAR  = Public

EXPORT FORMAT (Minimal CSV):
type,value,confidence,source,first_seen,last_seen,tlp,tags,description
ipv4,192.0.2.100,high,VT+AbuseIPDB,2024-01-15,2024-01-15,amber,C2:CobaltStrike,C2 server
sha256,a1b2c3...,high,EDR+VT,2024-01-15,2024-01-15,red,Malware:CobaltStrike,Beacon

PITFALLS:
❌ Block Cloudflare/AWS IPs          ✅ Block domain instead
❌ Use MD5 only                      ✅ Always SHA256
❌ Never expire IOCs                 ✅ TTL: 30-90d IP, 90-180d domain
❌ Share AMBER externally            ✅ Verify TLP first
❌ No context in blocklist           ✅ Source, date, confidence, ticket
```