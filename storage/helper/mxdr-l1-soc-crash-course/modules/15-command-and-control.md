# Module 15: Command and Control (C2)

**Priority: P1 — C2 = attacker's lifeline. Detecting it = detecting the breach.**

---

## 15.1 What is C2?

**Command and Control (C2 / C&C)** — The communication channel between compromised host(s) and attacker's infrastructure. Used for:
- Sending commands / tasking
- Receiving results / exfiltrated data
- Updating malware / deploying modules
- Maintaining persistence / heartbeat

**Without C2, malware is just a stray binary. With C2, it's an active breach.**

---

## 15.2 C2 Communication Models

| Model | Description | Examples |
|-------|-------------|----------|
| **Centralized** | Single C2 server (or small cluster) | Traditional botnets, simple malware |
| **Tiered / Proxy** | Victims → Proxy/Redirector → Real C2 | APT, sophisticated actors |
| **P2P (Peer-to-Peer)** | No central server; nodes communicate | Gameover Zeus, ZeroAccess, Sality |
| **Domain Fronting** | Legit CDN domain (cloudfront.net) fronts malicious backend | Cobalt Strike, custom |
| **Fast Flux** | Rapidly changing IPs for single domain | Botnets, banking trojans |
| **Dead Drop Resolver** | C2 info posted to legit site (GitHub, Twitter, blockchain) | APT29, APT41, Lazarus |
| **Multi-Channel** | Simultaneous HTTP + DNS + TCP | Redundancy, evasion |

---

## 15.3 C2 Protocols & Channels

### 1. HTTP/HTTPS C2 (Most Common)
| Aspect | Details |
|--------|---------|
| **Protocol** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) |
| **Ports** | 80, 443, 8080, 8443, 8000, 8888, 9000+ |
| **Methods** | GET (beacon), POST (data exfil/task results) |
| **Encryption** | TLS (HTTPS) + Optional payload encryption (AES, RC4, XOR) |
| **Beaconing** | Regular GET/POST to `/checkin`, `/task`, `/beacon` |
| **Headers** | Custom: `X-Command`, `X-Session`, `Cookie` with session |
| **User-Agent** | Often spoofed (Chrome, Windows Update) or distinctive (python, Go) |

**Common Frameworks**: Cobalt Strike (HTTP/HTTPS), Sliver, Mythic, Covenant, Metasploit (HTTP), PosHC2, Empire.

### 2. DNS C2
| Aspect | Details |
|--------|---------|
| **Protocol** | DNS (UDP 53, TCP 53, DoH 443, DoT 853) |
| **Query Types** | A, AAAA, TXT, CNAME, MX, NULL, SRV |
| **Encoding** | Subdomain (exfil), TXT/NULL response (commands) |
| **Tunneling** | iodine, dnscat2, Cobalt Strike DNS, custom |
| **Advantages** | Rarely blocked, works in air-gapped (via recursive), hard to inspect |
| **Detection** | High entropy subdomains, high query volume, NXDOMAIN rate, TXT/NULL usage |

### 3. TCP/UDP Raw Socket C2
| Aspect | Details |
|--------|---------|
| **Protocol** | Custom binary protocol over TCP/UDP |
| **Ports** | High ports (>1024), non-standard (4444, 5555, 6666, 8080, 9999) |
| **Encryption** | Custom (AES, ChaCha20, XOR) or TLS (mbedTLS, OpenSSL) |
| **Frameworks** | Cobalt Strike (TCP), Sliver (TCP/mTLS), Covenant (TCP), Metasploit (Meterpreter TCP), custom |
| **Detection** | Non-HTTP on 443/80, JA3 anomalies, long-lived connections, regular heartbeats |

### 4. Legitimate Service Abuse (Living-off-the-Land C2)
| Service | Mechanism | Examples |
|---------|-----------|----------|
| **Cloud Storage** | Files in OneDrive, Google Drive, Dropbox, AWS S3 | Graph API, REST API, CLI tools |
| **Email** | IMAP/SMTP/OWA for commands/results | Outlook, Gmail, custom |
| **Messaging** | Telegram Bot API, Discord Webhooks, Slack, Matrix | Bots, webhooks |
| **Social Media** | Twitter, GitHub, Reddit, Pastebin | Posts, gists, repos |
| **Blockchain** | Smart contracts, transaction data | Ethereum, Bitcoin OP_RETURN |
| **IoT/OT Protocols** | MQTT, CoAP, Modbus | Industrial malware |

---

## 15.4 C2 Frameworks — Know the Big Ones

| Framework | Language | Channels | Notable Features |
|-----------|----------|----------|------------------|
| **Cobalt Strike** | C++ (Beacon) | HTTP, HTTPS, DNS, SMB (named pipes), TCP | **Industry standard for Red Team**, Malleable C2 profiles, Artifact Kit |
| **Sliver** | Go | HTTP, HTTPS, DNS, mTLS, WireGuard, SSH | Modern, cross-platform, mutual TLS, arm64 |
| **Metasploit / Meterpreter** | Ruby/C | HTTP, HTTPS, TCP, Named Pipes | Vast module library, session migration |
| **Covenant** | C#/.NET | HTTP, HTTPS, WebSocket | .NET native, dynamic compilation |
| **Empire / Starkiller** | PowerShell/Python | HTTP, HTTPS, DNS | PowerShell agents, GUI |
| **PoshC2** | Python/PowerShell | HTTP, HTTPS, DNS, SMB | UK NCSC, PowerShell-first |
| **Mythic** | Go/Python | Plugin-based (HTTP, DNS, WebSocket, etc.) | Modular, containerized |
| **Brute Ratel (BRC4)** | C++ | HTTP, HTTPS, DNS, TCP | Evasion-focused, custom crypto |
| **Havoc** | C++/Go | HTTP, HTTPS, DNS, TCP | Open-source, modern UI |

---

## 15.5 C2 Indicators — What L1 Detects

### Network Indicators
| Indicator | Detection Source |
|-----------|------------------|
| **Beaconing** | Regular interval (jitter), long duration, small packets | NetFlow, Zeek conn.log, EDR netconns, Proxy |
| **Known C2 IP/Domain** | Threat intel match | Firewall, Proxy, DNS, EDR, TI platform |
| **Suspicious Domain** | Newly registered, DGA-like, suspicious TLD, low reputation | DNS logs, Proxy, TI |
| **JA3/JA3S Anomaly** | Known malicious fingerprints (Cobalt Strike, Meterpreter, Sliver) | Zeek ssl.log, EDR TLS, Proxy |
| **Certificate Anomalies** | Self-signed, expired, mismatched CN/SAN, Let's Encrypt for C2 | Zeek ssl.log, Proxy, EDR |
| **Non-Standard Ports** | HTTPS on 8080, 8443, 9443; SSH on 443; Custom high ports | Firewall, NetFlow, Zeek |
| **Long-Lived Connections** | Hours/days (WebSocket, HTTP/2, custom TCP) | Zeek conn.log, EDR, NetFlow |
| **Data Exfil Patterns** | Large uploads, regular intervals, cloud storage APIs | Proxy, Firewall, DLP, NetFlow |

### Host Indicators (EDR/Sysmon)
| Indicator | Source |
|-----------|--------|
| **Suspicious Process Network** | PowerShell, Rundll32, Regsvr32, Mshta, Certutil, Wscript making outbound connections | Sysmon EID 3, EDR |
| **Injected Process Network** | Legitimate process (svchost, explorer, browser) making unusual connections | Sysmon EID 3 + EID 8/10, EDR |
| **Scheduled Task/Service Beacon** | Task/Service running periodically, making network calls | Sysmon EID 1/3/4/5, 4698 |
| **WMI Event Consumer Network** | WMI consumer executing network commands | Sysmon EID 19/20/21 |
| **Memory Injection + Network** | CreateRemoteThread + subsequent network from target | Sysmon EID 8 + EID 3 |

---

## 15.6 Beaconing Detection — Deep Dive

### Beacon Characteristics
```
BEACON = Periodic, Automated, Command-Response
         │
         ├── Interval: 30s - 24h (typical 60s, 5m, 1h)
         ├── Jitter: ±10-30% (to evade simple threshold)
         ├── Payload: Small (heartbeat) or Large (exfil/results)
         ├── Protocol: HTTP(S), DNS, TCP, Custom
         └── Persistence: Survives reboot (service, task, WMI, Run key)
```

### Detection Algorithms

#### 1. Regularity Scoring (Coefficient of Variation)
```python
# CV = Standard Deviation / Mean
# CV < 0.3 = Highly regular (beaconing)
# CV 0.3-0.5 = Moderate (jittered beacon)
# CV > 0.5 = Irregular (human)

intervals = [t2-t1, t3-t2, t4-t3, ...]
mean = statistics.mean(intervals)
stdev = statistics.stdev(intervals)
cv = stdev / mean
```

#### 2. Frequency Domain (FFT)
```python
# Convert timestamps to binary signal (1=connection, 0=no connection)
# FFT → Find dominant frequency
# Peak at 1/60Hz = 60-second beacon
```

#### 3. Machine Learning (Isolation Forest)
```python
features = [
    'mean_interval', 'std_interval', 'cv_interval',
    'mean_bytes_up', 'mean_bytes_down', 'byte_ratio',
    'dest_port_entropy', 'dest_ip_count', 'conn_duration',
    'hour_of_day_entropy', 'day_of_week_entropy'
]
# Train on normal → Flag outliers
```

### KQL Beaconing Query (Enhanced)
```kql
// Multi-protocol beaconing detection
let beacon_candidates = 
    union 
    (Sysmon | where EventID == 3 | project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Protocol, ProcessImage, Computer, User),
    (FirewallLogs | project TimeGenerated, SourceIp=SrcIp, DestinationIp=DstIp, DestinationPort=DstPort, Protocol=Protocol, ProcessImage="", Computer, User=""),
    (ProxyLogs | where cs_method in ("GET","POST") | project TimeGenerated, SourceIp=c_ip, DestinationIp=cs_host, DestinationPort=80, Protocol="HTTP", ProcessImage="", Computer, User=cs_username)
;
beacon_candidates
| where DestinationPort in (80, 443, 8080, 8443, 53) or Protocol in ("TCP", "UDP")
| summarize 
    Count=count(), 
    Intervals=make_list(TimeGenerated),
    BytesUp=make_list(OrigBytes),
    BytesDown=make_list(RespBytes),
    Destinations=make_set(strcat(DestinationIp, ":", DestinationPort)),
    Processes=make_set(ProcessImage),
    Users=make_set(User)
  by SourceIp, Computer, bin(TimeGenerated, 2h)
| where Count >= 6
| mv-expand Intervals
| order by SourceIp, Intervals asc
| extend PrevInterval = prev(Intervals)
| extend DeltaSeconds = datetime_diff('second', Intervals, PrevInterval)
| where isnotnull(DeltaSeconds)
| summarize 
    AvgDelta=avg(DeltaSeconds), 
    StdDelta=stdev(DeltaSeconds), 
    CV=stdev(DeltaSeconds)/avg(DeltaSeconds),
    MinDelta=min(DeltaSeconds), 
    MaxDelta=max(DeltaSeconds),
    Count=count(),
    TotalBytesUp=sum(BytesUp),
    TotalBytesDown=sum(BytesDown)
  by SourceIp, Computer, DestinationIp, DestinationPort
| where CV < 0.35 and AvgDelta between (30 .. 86400)  // 30s to 24h
| where Count >= 6
| extend BeaconScore = (1 - CV) * log10(Count) * (TotalBytesDown / (TotalBytesUp + 1))
| order by BeaconScore desc
```

---

## 15.7 C2 Infrastructure — Attacker OPSEC

### Redirectors / Proxies
```
Victim ──► Redirector (VPS, Cloud) ──► Real C2 (Team Server)
                │
                ├── Nginx/Apache/HAProxy/Caddy
                ├── TLS termination (valid cert)
                ├── Header manipulation (hide framework signatures)
                ├── IP allowlist (only victim IPs)
                └── Logging minimal
```

### Domain Fronting (Legacy but Conceptual)
```
Victim ──► CDN (cloudfront.net, azureedge.net) ──► Real C2
                │
                ├── Host Header: evil.c2.com
                ├── SNI: d123.cloudfront.net
                └── CDN routes to evil.c2.com origin
```
**Note**: Major CDNs (Cloudflare, AWS, Azure, Google) have largely mitigated this.

### Dead Drop Resolvers
```
Malware ──► Legit Site (GitHub, Twitter, Blockchain) ──► Reads C2 IP/Domain
                │
                ├── GitHub Gist/Repo: "config.txt" with encrypted C2 list
                ├── Twitter: Tweet with encoded C2 in bio/username
                ├── Blockchain: Transaction OP_RETURN with C2 data
                └── DNS TXT: Legit domain with C2 in TXT record
```

---

## 15.8 C2 Takedown & Disruption (SOC Role)

| Action | Description | L1 Involvement |
|--------|-------------|----------------|
| **Block IOC** | Firewall/Proxy/DNS block on IP, Domain, Hash | Execute immediately on TP |
| **Sinkhole** | Redirect malicious domain to controlled server | Coordinate with Net/IT, monitor connections |
| **Takedown Request** | Report to registrar, hosting, CERT | Provide evidence, TI team leads |
| **Credential Rotation** | Reset compromised creds, revoke tokens | L1 identifies scope, L2/IR executes |
| **Network Segmentation** | Isolate VLAN, enforce jump hosts | L1 identifies lateral paths, Net implements |
| **EDR Policy Update** | New hash, behavior, custom rule | L1 submits, Detection Eng implements |

---

## 15.9 Interview Questions for This Module

1. **What is C2 and why is it critical to detect?**
   - Command & Control = attacker's communication channel to compromised hosts. Without C2, malware is inert. Detecting C2 = detecting active breach.

2. **Name 5 C2 communication channels and their protocols.**
   - HTTP/HTTPS (80/443), DNS (53/DoH/DoT), Raw TCP/UDP (high ports), Cloud Storage APIs (443), Email/IMAP/SMTP (993/587/25), Messaging (Telegram/Discord/Slack).

3. **What is beaconing and how do you detect it statistically?**
   - Regular periodic communication. Detect via Coefficient of Variation (CV = StdDev/Mean < 0.3), FFT frequency analysis, or ML isolation forest on interval/byte features.

4. **What is Cobalt Strike and why is it significant?**
   - Commercial Red Team framework (Beacon payload). Widely used by APT/criminals. Malleable C2 profiles mimic legit traffic. Distinct JA3, default pipes, sleep/jitter patterns.

5. **How does DNS tunneling work for C2?**
   - Encode data in DNS subdomains (exfil) or TXT/NULL responses (commands). Uses legitimate DNS recursion. Hard to block (port 53 often open).

6. **What are "Living-off-the-Land" C2 channels?**
   - Abusing legitimate services: Cloud storage (OneDrive, GDrive), Email (OWA/IMAP), Messaging (Telegram/Discord), Social Media (GitHub/Twitter), Blockchain.

7. **What is a redirector in C2 infrastructure?**
   - Intermediate proxy (VPS/cloud) between victim and real C2. Hides team server, terminates TLS, filters IPs, manipulates headers.

8. **What JA3 fingerprints are associated with common C2 frameworks?**
   - Cobalt Strike: `ae4edc6faf64d08308082ad26be60767` (varies by profile), Meterpreter: `72a589da586844d7f0818ce684948eea`, Sliver: varies (Go TLS stack).

9. **How do you disrupt C2 once detected?**
   - Block IOCs (IP/domain/hash) at firewall/proxy/DNS, sinkhole domains, coordinate takedown, rotate credentials, segment network, update EDR rules.

10. **What host indicators suggest a process is beaconing?**
    - Suspicious process (PowerShell, LOLBin, injected svchost) making regular outbound connections, scheduled task/service with network activity, WMI consumer executing net commands.

---

## 15.10 Study Checklist for Module 15

- [ ] Define C2 and explain why it's the "lifeline" of a breach
- [ ] Compare 6 C2 communication models (Centralized, Tiered, P2P, Domain Fronting, Fast Flux, Dead Drop)
- [ ] Detail 4 protocol channels: HTTP/S, DNS, Raw TCP/UDP, Legit Service Abuse
- [ ] List 8 major C2 frameworks with languages and channels
- [ ] Identify 10+ network C2 indicators and 5+ host C2 indicators
- [ ] Explain beaconing characteristics (interval, jitter, payload, protocol, persistence)
- [ ] Implement 3 beaconing detection methods: CV, FFT, ML
- [ ] Write enhanced KQL for multi-protocol beaconing detection
- [ ] Describe C2 infrastructure OPSEC (redirectors, domain fronting, dead drops)
- [ ] List 6 C2 disruption actions with L1 role
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 16 — Phishing and Email Security*