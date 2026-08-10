# Module 10: DNS Security

**Priority: P1 — Critical for C2 detection, phishing, data exfil. L1 investigates DNS daily.**

---

## 10.1 DNS Fundamentals

### What is DNS?
**Domain Name System** — Hierarchical, distributed database mapping human-readable names to IP addresses (and more). The "phone book" of the internet.

### DNS Hierarchy
```
. (Root) → 13 Root Server Clusters (a.root-servers.net → m.root-servers.net)
    │
    ├── .com (TLD) → Verisign
    ├── .org (TLD) → PIR
    ├── .net (TLD) → Verisign
    ├── .edu (TLD) → Educause
    ├── .gov (TLD) → DOT
    ├── .io, .co, .xyz, .top, .tk, .ml, .ga, .cf (ccTLD/gTLD) → Various
    │
    └── example.com (Second-Level Domain) → Organization
            │
            ├── www.example.com (A/AAAA)
            ├── mail.example.com (MX)
            ├── vpn.example.com (A)
            ├── _kerberos._tcp.example.com (SRV)
            └── sub.domain.example.com (delegation)
```

### DNS Message Format
```
┌─────────────────────────────────────────────────────────────┐
│ Header (12 bytes)                                           │
├─────────────────────────────────────────────────────────────┤
│ Question Section (1+ entries)                               │
├─────────────────────────────────────────────────────────────┤
│ Answer Section (0+ RRs)                                     │
├─────────────────────────────────────────────────────────────┤
│ Authority Section (0+ RRs)                                  │
├─────────────────────────────────────────────────────────────┤
│ Additional Section (0+ RRs)                                 │
└─────────────────────────────────────────────────────────────┘
```

**Header Fields**:
| Field | Size | Description |
|-------|------|-------------|
| **Transaction ID** | 16 bits | Matches request/response (spoofing protection) |
| **Flags** | 16 bits | QR, Opcode, AA, TC, RD, RA, Z, RCODE |
| **Questions** | 16 bits | Number of questions |
| **Answer RRs** | 16 bits | Number of answer records |
| **Authority RRs** | 16 bits | Number of authority records |
| **Additional RRs** | 16 bits | Number of additional records |

**Flags Detail**:
```
QR (1)  | Opcode (4) | AA | TC | RD | RA | Z (3) | RCODE (4)
 0=Query  0=Standard  1=Auth  1=Trunc  1=Recurse  1=RecurseAvail  Reserved  0=NoError
 1=Resp   1=Inverse   Ans   ated  Desired   Available             3=NameError (NXDOMAIN)
                                             2=ServFail
                                             5=Refused
```

---

## 10.2 Critical DNS Record Types

| Type | Value | Purpose | SOC Relevance |
|------|-------|---------|---------------|
| **A** | 1 | IPv4 address | Standard resolution |
| **AAAA** | 28 | IPv6 address | IPv6 tracking |
| **CNAME** | 5 | Canonical name (alias) | **CDN, tracking, subdomain takeover** |
| **MX** | 15 | Mail exchange | **Email routing, phishing infrastructure** |
| **TXT** | 16 | Text data | **SPF, DKIM, DMARC, verification, C2** |
| **NS** | 2 | Name server | **Delegation, hijacking** |
| **PTR** | 12 | Reverse lookup (IP→Name) | **Recon, logging** |
| **SOA** | 6 | Start of Authority | Zone metadata, version |
| **SRV** | 33 | Service location | **Kerberos, LDAP, SIP, service discovery** |
| **CAA** | 257 | Certification Authority Auth | **Cert issuance control** |
| **DNAME** | 39 | Delegation name | Subtree alias (rare) |
| **DS** | 43 | Delegation Signer | **DNSSEC** |
| **DNSKEY** | 48 | DNS Key | **DNSSEC** |
| **RRSIG** | 46 | RRset Signature | **DNSSEC** |

---

## 10.3 DNS Resolution Process

### Recursive Resolution (Client → Recursive Resolver)
```
Client                                    Recursive Resolver
   │                                          │
   ├─ Query: www.example.com A ──────────────►│
   │                                          │
   │                                          ├─ Check cache
   │                                          ├─ If miss: Query Root (.)
   │                                          │   │
   │                                          │   ├─ Root Referral: .com NS + Glue
   │                                          │   │
   │                                          │   ├─ Query .com TLD
   │                                          │   │   │
   │                                          │   │   ├─ TLD Referral: example.com NS
   │                                          │   │   │
   │                                          │   │   ├─ Query example.com Auth NS
   │                                          │   │   │   │
   │                                          │   │   │   ├─ Answer: www.example.com A 93.184.216.34
   │                                          │   │   │   │
   │                                          │   │   │◄──┤
   │                                          │   │◄─────┤
   │                                          │◄────────┤
   │◄─ Response: 93.184.216.34 ───────────────┤
   │                                          │
```

### Iterative Resolution (Resolver → Authoritative)
- Resolver does the work, queries each level
- Authoritative servers only answer for their zone

### Caching & TTL
| Record | Typical TTL | SOC Note |
|--------|-------------|----------|
| A/AAAA | 300-3600s (5min-1hr) | Low TTL = fast flux, agile infrastructure |
| CNAME | 3600-86400s | Chain length matters |
| MX | 3600-86400s | |
| NS | 86400s+ (1 day+) | |
| TXT | 3600s | SPF/DKIM/DMARC |
| **Negative (NXDOMAIN)** | SOA MINIMUM (often 3600s) | NXDOMAIN caching |

**TTL = Time To Live**. Attackers use **low TTL (30-60s)** for fast flux / rapid IP rotation.

---

## 10.4 DNS Security Threats

### 1. DNS Tunneling (Data Exfil / C2)
**Mechanism**: Encode data in subdomains (queries) or TXT/NULL records (responses).
```
Exfil:  <base64(data)>.attacker.com     → Query
C2:     attacker.com TXT <base64(cmd)>  → Response
```
**Indicators**:
- High query volume from single host
- Long subdomains (>50 chars), high entropy
- Unusual record types (TXT, NULL, CNAME for data)
- Regular intervals (beaconing)
- NXDOMAIN responses (data in query only)

### 2. Domain Generation Algorithms (DGA)
**Mechanism**: Malware generates pseudorandom domains daily → C2 registers one → Malware resolves until hit.
**Indicators**:
- High NXDOMAIN rate
- Algorithmic domain patterns (entropy, length, consonant/vowel ratio)
- Many domains, few resolutions
- Newly registered domains (NRD)
- Same seed → predictable (sinkholing possible)

**Common DGA Families**: Necurs, Conficker, Gameover Zeus, Matsnu, Pushdo, Ramnit.

### 3. Fast Flux
**Mechanism**: Single domain → Many IPs (round-robin, low TTL) → Hide C2 behind compromised hosts.
**Types**:
- **Single Flux**: Domain ↔ Multiple IPs (A records)
- **Double Flux**: Domain ↔ Multiple IPs + NS records also flux
**Indicators**:
- Very low TTL (< 300s, often 30-60s)
- Many A records for single domain
- IPs geographically dispersed, unrelated ASNs
- High churn (IPs change frequently)

### 4. DNS Hijacking / Cache Poisoning
**Mechanism**: Corrupt resolver cache → Redirect traffic to attacker.
**Vectors**:
- **Kaminsky Attack**: Race condition, predict TXID + port
- **Rogue DHCP/WPAD**: Push malicious DNS (Option 6, 252)
- **Compromised Resolver**: ISP/Enterprise DNS hacked
- **Registrar/Registry Compromise**: Change NS records
**Indicators**:
- Unexpected IPs for known domains
- Certificate mismatches (TLS)
- User reports of phishing/redirection

### 5. Subdomain Takeover
**Mechanism**: CNAME points to external service (GitHub Pages, AWS S3, Azure, Heroku) → Service deleted → Attacker claims name → Serves content on victim's subdomain.
**Detection**:
- CNAME to known providers (github.io, s3.amazonaws.com, azurewebsites.net, herokudns.com)
- HTTP 404 / "No such app" / "Repository not found"
- Monitor external CNAME targets

### 6. DNS Reconnaissance
| Technique | Purpose |
|-----------|---------|
| **Zone Transfer (AXFR/IXFR)** | Enumerate all records (misconfigured NS) |
| **Reverse Lookup (PTR)** | Map IP ranges |
| **Certificate Transparency (CT) Logs** | Find subdomains via certs |
| **DNS Bruteforce / Dictionary** | Find hidden subdomains |
| **Passive DNS** | Historical resolution data |
| **SPF/DMARC/TXT Enumeration** | Discover mail infrastructure |

---

## 10.5 DNS Security Controls

| Control | Description | Deployment |
|---------|-------------|------------|
| **DNSSEC** | Cryptographic signing of zones (RRSIG, DNSKEY, DS, NSEC/NSEC3) | Authoritative + Validating Resolver |
| **DNS over TLS (DoT)** | DNS over TCP 853 (TLS) | Recursive Resolver |
| **DNS over HTTPS (DoH)** | DNS over HTTPS 443 | Browser/OS/Resolver |
| **DNSCrypt** | Encrypted DNS (proprietary) | Client → Resolver |
| **Response Rate Limiting (RRL)** | Limit authoritative responses to same client | Authoritative Server |
| **0x20 Bit Randomization** | Randomize case in query for entropy | Recursive Resolver |
| **Source Port Randomization** | Randomize UDP source port | Recursive Resolver |
| **RPZ (Response Policy Zones)** | Block/redirect malicious domains at resolver | Recursive Resolver |
| **Sinkholing** | Redirect malicious domains to controlled server | Resolver / Network |

---

## 10.6 DNS Investigation Workflow for L1

### Alert: "Suspicious DNS Activity - Potential Tunneling"
```
1. IDENTIFY SOURCE
   - Host: WORKSTN-047 (Marketing)
   - User: j.smith@company.com
   - Time: 2024-01-15 03:12:47 UTC
   - Resolver: Corporate DNS (10.10.10.53)

2. QUERY DNS LOGS (Zeek dns.log / Infoblox / Cisco Umbrella / Microsoft DNS)
   - Filter: src_ip=10.10.20.47, time window T-1h to T+1h
   
3. ANALYZE PATTERNS
   - Query count: 2,847 queries in 1 hour (baseline: ~200/hr)
   - Unique domains: 1,203
   - Record types: 95% TXT, 5% A
   - Subdomain length: avg 62 chars, max 187
   - Entropy: avg 4.2 (high)
   - Response codes: 89% NXDOMAIN, 11% NOERROR
   - Intervals: Regular ~5 seconds (beaconing)

4. EXAMPLE QUERIES
   - a1b2c3d4e5f6g7h8i9j0.attacker-c2.com TXT
   - k9l8m7n6o5p4q3r2s1t0.attacker-c2.com TXT
   - (decoded TXT: "cmd: whoami; sleep 5")

5. THREAT INTEL
   - Domain: attacker-c2.com
   - Registered: 2024-01-10 (5 days ago)
   - Registrar: Namecheap
   - NS: ns1.bulletproof-hosting.net
   - VT: 12/92 (C2, tunneling)
   - Passive DNS: Seen with Cobalt Strike, PoshC2

6. CORRELATE
   - Same host: Sysmon EID 22 shows PowerShell making DNS queries
   - Process: powershell.exe (PID 5102)
   - Network: No HTTP/HTTPS to domain (DNS-only C2)
   - User: j.smith clicked phishing link at 03:10 (email logs)

7. CLASSIFY
   - TRUE POSITIVE: DNS Tunneling C2 (PoshC2)
   - MITRE: T1071.004 (DNS), T1059.001 (PowerShell)
   - ESCALATE P2

8. CONTAINMENT
   - Block domain at DNS resolver (RPZ)
   - Block domain at firewall/proxy
   - Isolate host (EDR)
   - Reset user password (credential theft likely)
```

---

## 10.7 DNS Log Sources for SOC

| Source | Pros | Cons |
|--------|------|------|
| **Zeek (Bro) dns.log** | Full protocol parsing, all record types, timestamps | Requires sensor deployment |
| **Infoblox / BlueCat / Microsoft DNS Debug Logs** | Authoritative + Recursive, native | Verbose, performance impact |
| **Cisco Umbrella / OpenDNS** | Cloud-delivered, threat intel integrated | Cloud only, cost |
| **Firewall/Proxy DNS Logs** | Correlated with network flow | May miss internal-only |
| **Sysmon EID 22** | Process context (which exe made query) | Endpoint only |
| **Passive DNS (Farsight, CIRCL, VirusTotal)** | Historical, global view | Not real-time, subscription |

---

## 10.8 DNS Query Patterns — Detection Queries

### High Entropy / Long Subdomains (DGA/Tunneling)
```kql
DnsEvents
| extend Subdomain = split(QueryName, ".")[0]
| extend Entropy = calculate_shannon_entropy(Subdomain)
| extend Length = strlen(Subdomain)
| where Entropy > 3.5 and Length > 30
| summarize Count=count(), AvgEntropy=avg(Entropy), MaxLen=max(Length), Domains=make_set(QueryName) 
  by SrcIp, User, bin(TimeGenerated, 1h)
| where Count > 50
```

### Fast Flux Detection
```kql
DnsEvents
| where QueryType == "A" and ResponseCode == "NOERROR"
| summarize Ips=make_set(ResponseIp), TTLs=make_set(TTL), Count=count() 
  by QueryName, bin(TimeGenerated, 1h)
| where Count > 10 and array_length(TTLs) > 1 and min(TTLs) < 300
| extend UniqueASNs = ... (enrich IPs with ASN)
```

### DNS Tunneling (TXT/NULL, High Volume, NXDOMAIN)
```kql
DnsEvents
| where QueryType in ("TXT", "NULL", "CNAME") or ResponseCode == "NXDOMAIN"
| summarize QueryCount=count(), NxCount=countif(ResponseCode=="NXDOMAIN"), 
            UniqueDomains=dcount(QueryName), AvgSubLen=avg(strlen(split(QueryName, ".")[0]))
  by SrcIp, bin(TimeGenerated, 1h)
| where QueryCount > 500 and NxCount > QueryCount * 0.5
```

### Newly Registered Domains (NRD)
```kql
DnsEvents
| join kind=inner (
    ThreatIntel
    | where DomainAgeDays < 30
    | project Domain, Registrar, RegistrationDate
) on $left.QueryName == $right.Domain
| where QueryType in ("A", "AAAA", "CNAME")
```

---

## 10.9 Interview Questions for This Module

1. **Explain the DNS resolution process (recursive vs iterative).**
   - Client asks recursive resolver → Resolver queries root → TLD → Authoritative → Returns answer. Iterative = resolver does the work.

2. **What are the most common DNS record types and their purpose?**
   - A (IPv4), AAAA (IPv6), CNAME (alias), MX (mail), TXT (text/SPF/DKIM), NS (nameserver), PTR (reverse), SRV (service location), SOA (zone authority).

3. **What is DNS tunneling and how do you detect it?**
   - Encode data in DNS queries/responses (subdomains, TXT records). Detect: high volume, high entropy subdomains, unusual record types, regular intervals, NXDOMAIN heavy.

4. **What is a DGA (Domain Generation Algorithm) and indicators?**
   - Malware generates domains algorithmically. Indicators: high NXDOMAIN rate, algorithmic patterns (entropy, length), many domains few resolutions, newly registered.

5. **What is Fast Flux and how does it work?**
   - Single domain resolves to many IPs with low TTL (round-robin). Hides C2 behind compromised hosts. Single flux (A records) or double flux (NS also flux).

6. **What is subdomain takeover and how do you detect it?**
   - CNAME to external service (GitHub, AWS, Azure) → Service deleted → Attacker claims name. Detect: CNAME to known providers + HTTP 404/"No such app".

7. **What is DNSSEC and what records does it use?**
   - Cryptographic signing of zones. Records: DNSKEY (public key), RRSIG (signature), DS (delegation signer), NSEC/NSEC3 (authenticated denial).

8. **Difference between DoT (DNS over TLS) and DoH (DNS over HTTPS)?**
   - DoT: DNS over TCP 853 with TLS. DoH: DNS over HTTPS 443. DoH blends with web traffic, harder to block/inspect.

9. **What is RPZ (Response Policy Zone) and how is it used?**
   - Policy zones at recursive resolver to block/redirect malicious domains (sinkhole, NXDOMAIN, walled garden).

10. **How do you correlate DNS alerts with endpoint telemetry?**
    - Sysmon EID 22 (DNS Query) shows Process/Image/User making query. Match query name/timestamp to DNS logs. Identify malicious process (PowerShell, rundll32, custom).

---

## 10.10 Study Checklist for Module 10

- [ ] Draw DNS hierarchy and resolution flow
- [ ] List 12+ record types with purpose and SOC relevance
- [ ] Explain recursive vs iterative resolution
- [ ] Describe 6 DNS threats: Tunneling, DGA, Fast Flux, Hijacking, Subdomain Takeover, Recon
- [ ] List DNS security controls (DNSSEC, DoT, DoH, RPZ, Sinkholing)
- [ ] Perform DNS investigation workflow (source → logs → patterns → TI → correlate → classify)
- [ ] Write KQL for: High entropy, Fast Flux, Tunneling, NRD
- [ ] Compare DNS log sources (Zeek, Infoblox, Umbrella, Sysmon, Passive)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 11 — HTTP/HTTPS/TLS*