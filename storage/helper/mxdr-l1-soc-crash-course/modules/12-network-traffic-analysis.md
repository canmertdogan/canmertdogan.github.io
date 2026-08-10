# Module 12: Network Traffic Analysis

**Priority: P1 — L1 must read PCAP, analyze flows, identify anomalies. Foundation for NDR/EDR correlation.**

---

## 12.1 Network Flow Analysis — The 5-Tuple

### Flow Definition (NetFlow/IPFIX/sFlow)
```
A "Flow" = Unidirectional sequence of packets sharing:
├── Source IP
├── Destination IP
├── Source Port
├── Destination Port
└── Protocol (TCP=6, UDP=17, ICMP=1, etc.)
```

### Bidirectional Flow (Session)
```
Two unidirectional flows (forward + reverse) = One session
Client (10.10.20.5:54321) ──► Server (192.168.1.10:443)  [Forward]
Server (192.168.1.10:443) ──► Client (10.10.20.5:54321)  [Reverse]
```

### Key Flow Metrics
| Metric | Description | Anomaly Indicator |
|--------|-------------|-------------------|
| **Duration** | First packet → Last packet | Very short (scan) or very long (C2, VPN) |
| **Packets (Total)** | Count in each direction | Asymmetric (data exfil, C2) |
| **Bytes (Total)** | Volume in each direction | Large outbound (exfil), large inbound (download) |
| **Packets/sec** | Rate | Constant low rate (beaconing), burst (exfil) |
| **Bytes/packet** | Average packet size | Small (C2, interactive), Large (file transfer) |
| **TCP Flags (OR'd)** | SYN, FIN, RST, PSH, ACK, URG | SYN only (scan), RST (blocked), FIN (clean close) |
| **First/Last Packet Time** | Absolute timestamps | Off-hours activity |

---

## 12.2 Beaconing Detection — C2 Heartbeat

### What is Beaconing?
Regular, periodic communication between compromised host and C2 server. "Heartbeat" to receive commands.

### Beaconing Characteristics
| Characteristic | Normal Traffic | Beaconing |
|----------------|----------------|-----------|
| **Interval** | Variable, bursty | **Constant (jitter ±10-20%)** |
| **Duration** | Session-based | **Long-running (hours/days)** |
| **Packet Size** | Variable | **Consistent (small, ~100-500 bytes)** |
| **Direction** | Request/Response | **Outbound-initiated, regular** |
| **Destination** | Many (CDN, APIs) | **Single/few IPs/domains** |
| **Protocol** | HTTPS, DNS, etc. | **Often HTTPS, DNS, custom TCP** |

### Detection Methods

#### 1. Statistical (Time Series)
```kql
// Regular interval detection
Flows
| where Protocol == "TCP" and DestinationPort in (80, 443, 8080, 8443)
| summarize Count=count(), 
            Intervals=make_list(TimeGenerated), 
            Destinations=make_set(DestinationIp),
            AvgBytes=avg(TotalBytes)
  by SourceIp, DestinationIp, DestinationPort, bin(TimeGenerated, 1h)
| where Count >= 12  // At least 12 connections/hour
| mv-expand Intervals
| order by SourceIp, Intervals asc
| extend PrevInterval = prev(Intervals)
| extend Delta = Intervals - PrevInterval
| summarize AvgDelta=avg(Delta), StdDev=stdev(Delta), MinDelta=min(Delta), MaxDelta=max(Delta) 
  by SourceIp, DestinationIp, DestinationPort
| where StdDev < AvgDelta * 0.2  // Low jitter (< 20%)
| where AvgDelta between (30s .. 3600s)  // Reasonable beacon interval
```

#### 2. Frequency Analysis (FFT/Periodogram)
- Convert connection timestamps to signal
- Find dominant frequencies
- Beaconing = sharp peak at beacon interval

#### 3. Machine Learning (Isolation Forest, LSTM)
- Train on normal flow patterns
- Flag outliers in: interval regularity, byte symmetry, destination persistence

### Jitter — The Evasion Technique
```
Perfect beacon:  Every 60.0s exactly  → EASY to detect
Jittered beacon: 60s ± 10% (54-66s)   → HARDER, but still periodic
Random beacon:   Exponential backoff  → HARDEST, mimics human
```

**Detection**: Look for *statistical regularity* even with jitter. Coefficient of Variation (StdDev/Mean) < 0.3 = suspicious.

---

## 12.3 Lateral Movement Detection

### Common Lateral Protocols (Internal → Internal)
| Protocol | Port | Tool/Technique | Flow Signature |
|----------|------|----------------|----------------|
| **SMB** | 445 | PsExec, WMI, Admin$, C$, IPC$ | Small commands, file ops, named pipes |
| **RDP** | 3389 | Remote Desktop, RDP hijack | Long duration, graphical (high bytes) |
| **WinRM** | 5985/5986 | PowerShell Remoting, Ansible | HTTP-like, short bursts |
| **SSH** | 22 | Linux lateral, tunneling | Encrypted, interactive or scripted |
| **RPC/DCOM** | 135 + dynamic | WMI, COM, SchTasks | Ephemeral high ports (>1024) |
| **LDAP** | 389/636 | AD enumeration, delegation | Query bursts |
| **Kerberos** | 88 | Pass-the-Ticket, delegation | TGT/TGS requests |
| **MSSQL** | 1433 | xp_cmdshell, linked servers | TDS protocol |
| **PostgreSQL** | 5432 | COPY TO PROGRAM | Query + exec |

### Detection Patterns
```kql
// SMB Admin$ access (PsExec/lateral)
Flows
| where DestinationPort == 445
| where TotalBytes < 10000  // Small command execution
| where SourceIp != DestinationIp
| join kind=inner (
    // Correlate with auth logs
    SecurityEvent
    | where EventID == 4624 and LogonType == 3
    | project TimeGenerated, SourceIp=IpAddress, TargetUserName
) on SourceIp, TimeGenerated

// RDP from unusual internal source
Flows
| where DestinationPort == 3389
| where SourceIp in (internal_subnet)
| where Duration > 300s  // Interactive session
| join kind=leftanti (
    // Known admin workstations
    AdminWorkstations
    | project SourceIp
) on SourceIp

// WinRM (PowerShell Remoting) lateral
Flows
| where DestinationPort in (5985, 5986)
| where SourceIp != DestinationIp
| where TotalPackets < 50  // Typical invoke-command burst
```

---

## 12.4 Data Exfiltration Detection

### Exfiltration Channels
| Channel | Protocol | Detection Focus |
|---------|----------|-----------------|
| **HTTPS** | 443 | Large uploads to rare domains, cloud storage |
| **DNS** | 53 | TXT/NULL records, high entropy subdomains |
| **HTTP** | 80 | POST to uncommon destinations |
| **FTP/SFTP** | 21/22 | Large transfers to external |
| **Cloud APIs** | 443 | AWS S3, Azure Blob, GCS, Dropbox, Google Drive |
| **Email** | 25/587/993 | Large attachments, auto-forward rules |
| **ICMP** | N/A | Covert channel (oversized packets) |
| **Custom TCP/UDP** | High ports | Non-standard, encrypted |

### Volume-Based Detection
```kql
// Unusual outbound volume
Flows
| where Direction == "Outbound"  // Internal → External
| where DestinationIp !in (approved_cdn, updates, cloud_providers)
| summarize TotalBytes=sum(TotalBytes), ConnectionCount=count(), 
            UniqueDests=dcount(DestinationIp), MaxSingleFlow=max(TotalBytes)
  by SourceIp, bin(TimeGenerated, 1h)
| where TotalBytes > 1073741824  // > 1 GB/hour
| or MaxSingleFlow > 104857600   // > 100 MB single flow

// Cloud storage exfil (known providers)
Flows
| where DestinationIp in (aws_s3_ips, azure_blob_ips, gcs_ips, dropbox_ips)
| where Direction == "Outbound"
| summarize TotalBytes=sum(TotalBytes) by SourceIp, DestinationIp, bin(TimeGenerated, 1h)
| where TotalBytes > 52428800  // > 50 MB to cloud storage
```

### Behavioral Detection
- **User baseline**: Normal daily upload volume per user/host
- **Peer baseline**: Compare to same department/role
- **Time baseline**: Off-hours vs business hours
- **Destination reputation**: Known exfil services, file sharing, paste sites

---

## 12.5 Scanning & Reconnaissance Detection

### Port Scan Types
| Scan Type | TCP Flags | Packets per Port | Detection |
|-----------|-----------|------------------|-----------|
| **SYN Scan** | SYN only | 1 | Many SYN, few SYN-ACK, many RST |
| **Connect Scan** | Full handshake | 3+ | Many SYN, SYN-ACK, ACK, FIN |
| **FIN/NULL/Xmas** | FIN / None / FIN+PSH+URG | 1 | RST response = closed |
| **UDP Scan** | UDP | 1 | ICMP Port Unreachable |
| **Idle/Zombie** | Spoofed | N/A | IP ID side channel |

### Detection Queries
```kql
// SYN Scan (Horizontal - one source, many dest ports)
Flows
| where Protocol == "TCP" and TCPFlags == "SYN"
| summarize ScannedPorts=dcount(DestinationPort), TargetCount=dcount(DestinationIp),
            SynCount=count(), SynAckCount=countif(TCPFlags has "SYN,ACK")
  by SourceIp, bin(TimeGenerated, 5m)
| where ScannedPorts > 20 or TargetCount > 50
| where SynCount > SynAckCount * 10  // Most SYN unanswered

// Host Sweep (Vertical - one source, many dest IPs, same port)
Flows
| where Protocol == "TCP" and TCPFlags == "SYN"
| summarize TargetIps=dcount(DestinationIp), PortList=make_set(DestinationPort)
  by SourceIp, bin(TimeGenerated, 5m)
| where TargetIps > 30 and array_length(PortList) <= 3

// UDP Scan
Flows
| where Protocol == "UDP"
| where ICMPType == 3 and ICMPCode == 3  // Port Unreachable
| summarize ScannedPorts=dcount(DestinationPort) by SourceIp, bin(TimeGenerated, 5m)
| where ScannedPorts > 50
```

---

## 12.6 PCAP Analysis — Wireshark/tcpdump Essentials

### tcpdump Filters (Memorize)
```bash
# Capture to file
tcpdump -i eth0 -w capture.pcap -s 0

# Read with filters
tcpdump -r capture.pcap "host 10.10.20.5"
tcpdump -r capture.pcap "net 192.168.1.0/24"
tcpdump -r capture.pcap "port 443"
tcpdump -r capture.pcap "tcp port 80 or tcp port 443"
tcpdump -r capture.pcap "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"
tcpdump -r capture.pcap "tcp[13] == 2"  # SYN only
tcpdump -r capture.pcap "tcp[13] == 18" # SYN-ACK
tcpdump -r capture.pcap "tcp[13] == 4"  # RST

# HTTP
tcpdump -r capture.pcap -A "tcp port 80 and (tcp[((tcp[12]>>2)*4)]=0x47455420 or tcp[((tcp[12]>>2)*4)]=0x504f5354)"

# DNS
tcpdump -r capture.pcap "udp port 53"

# Large packets
tcpdump -r capture.pcap "len > 1500"
```

### Wireshark Display Filters (Memorize)
```wireshark
# IP/Host
ip.addr == 10.10.20.5
ip.src == 10.10.20.5
ip.dst == 192.168.1.10

# Port/Protocol
tcp.port == 443
udp.port == 53
http
dns
tls
smb2
kerberos

# TCP Flags
tcp.flags.syn == 1
tcp.flags.reset == 1
tcp.flags.fin == 1
tcp.flags.syn == 1 and tcp.flags.ack == 0  # SYN only

# HTTP
http.request.method == "POST"
http.request.uri contains "cmd"
http.user_agent contains "python"
http.response.code == 401

# TLS
tls.handshake.type == 1  # ClientHello
tls.handshake.extensions_server_name contains "evil.com"
tls.ja3 == "ae4edc6faf64d08308082ad26be60767"

# DNS
dns.qry.name contains "tunnel"
dns.qry.type == 16  # TXT
dns.flags.rcode == 3  # NXDOMAIN

# Size/Anomalies
frame.len > 1500
tcp.len > 1460
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.out_of_order
```

### Wireshark Analysis Workflow
```
1. LOAD PCAP
2. STATISTICS → Conversations → Sort by Bytes (find top talkers)
3. STATISTICS → Endpoints → Identify internal/external
4. STATISTICS → Protocol Hierarchy → See protocol distribution
5. STATISTICS → Flow Graph → Visualize TCP sessions
6. APPLY FILTERS → Focus on suspicious:
   - External connections from internal
   - Long-duration flows
   - High-volume flows
   - Failed connections (RST, ICMP unreachable)
   - Non-standard ports
7. FOLLOW TCP STREAM → Reconstruct HTTP, SMTP, etc.
8. EXPORT OBJECTS → HTTP, SMB, DICOM, etc. (files, credentials)
9. EXPERT INFO → Errors, warnings, notes (retransmissions, malformed)
```

---

## 12.7 Zeek (Bro) — Structured Network Logs

### Key Log Files for SOC
| Log | Description | Key Fields |
|-----|-------------|------------|
| **conn.log** | **All connections** | uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, missed_bytes, history, orig_pkts, resp_pkts, tunnel_parents |
| **http.log** | HTTP requests/responses | uid, method, host, uri, referrer, user_agent, request_body_len, response_body_len, status_code, status_msg, mime_type, tags, username, password, proxied, orig_fuids, orig_mime_types, resp_fuids, resp_mime_types |
| **dns.log** | DNS queries/responses | uid, query, qclass, qtype, rcode, AA, TC, RD, RA, Z, answers, TTLs, rejected |
| **ssl.log** | TLS handshakes | uid, version, cipher, curve, server_name, resumed, established, cert_chain_fuids, client_cert_chain_fuids, subject, issuer, not_valid_before, not_valid_after, ja3, ja3s |
| **files.log** | Extracted files | fid, source, depth, analyzers, mime_type, filename, duration, local_orig, is_orig, seen_bytes, total_bytes, missing_bytes, overflow_bytes, timedout, parent_fuid, md5, sha1, sha256, extracted |
| **x509.log** | Certificate details | certificate.version, certificate.serial, certificate.subject, certificate.issuer, certificate.not_valid_before, certificate.not_valid_after, certificate.key_alg, certificate.sig_alg, certificate.key_type, certificate.key_length, certificate.exponent, certificate.curve, certificate.san, certificate.extensions |

### Zeek Query Examples
```zeek
# conn.log: Beaconing candidates
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes | 
awk '$6 > 100 && $7 < 1000 && $4 == "tcp"'

# http.log: Suspicious POST
cat http.log | zeek-cut uid id.orig_h method host uri status_code user_agent | 
awk '$3 == "POST" && $5 ~ /cmd|exec|shell/'

# ssl.log: Weak cipher / old TLS
cat ssl.log | zeek-cut uid id.orig_h id.resp_h version cipher server_name ja3 | 
awk '$4 ~ /TLSv1[01]/ || $5 ~ /RC4|DES|3DES|MD5|SHA1$/'

# dns.log: Tunneling
cat dns.log | zeek-cut uid id.orig_h query qtype rcode answers | 
awk '$4 == "TXT" || $5 == "NXDOMAIN"'
```

---

## 12.8 Threat Hunting with Network Data

### Hunt Hypotheses
| Hypothesis | Data Source | Query Pattern |
|------------|-------------|---------------|
| **C2 via HTTPS** | Proxy, Zeek ssl/conn | JA3 clustering, SNI anomalies, cert anomalies |
| **C2 via DNS** | DNS logs, Zeek dns | High entropy, NXDOMAIN rate, TXT volume |
| **Lateral Movement** | Firewall, Zeek conn (SMB/RDP/WinRM) | Internal→Internal, admin ports, off-hours |
| **Data Exfil** | Proxy, Firewall, NetFlow | Large outbound, cloud storage, rare domains |
| **Credential Theft** | Kerberos, NTLM, LDAP logs | AS-REQ/4768 anomalies, 4776 spikes, LDAP binds |
| **Malware Delivery** | Proxy, Email, Zeek http/files | Drive-by, malicious attachments, exploit kits |
| **Insider Threat** | DLP, Proxy, File logs | Large access, off-hours, personal cloud |

---

## 12.9 Interview Questions for This Module

1. **What is a network flow (5-tuple) and how does it differ from a session?**
   - Flow: Unidirectional 5-tuple (src/dst IP, src/dst port, protocol). Session: Bidirectional pair of flows.

2. **What are the key characteristics of C2 beaconing traffic?**
   - Regular intervals (low jitter), long duration, consistent small packet sizes, single/few destinations, outbound-initiated.

3. **How do you detect a SYN scan using flow data?**
   - Many SYN packets to many ports/hosts, few SYN-ACK responses, high SYN:SYN-ACK ratio.

4. **What lateral movement protocols should you monitor internally?**
   - SMB (445), RDP (3389), WinRM (5985/5986), SSH (22), RPC/DCOM (135+dynamic), LDAP (389/636), Kerberos (88), MSSQL (1433).

5. **What is JA3 and how is it used?**
   - TLS client fingerprint (MD5 of ClientHello parameters). Identifies tools/malware regardless of User-Agent spoofing.

6. **What Zeek log files are most valuable for SOC and why?**
   - conn.log (all connections), http.log (web), dns.log (DNS), ssl.log (TLS + JA3), files.log (extracted files), x509.log (certs).

7. **How do you detect data exfiltration to cloud storage via network logs?**
   - Large outbound transfers to known cloud provider IP ranges (AWS S3, Azure Blob, GCS), unusual for user/host baseline.

8. **What tcpdump filter captures only TCP SYN packets?**
   - `tcp[13] == 2` or `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0`

9. **What Wireshark display filter shows HTTP POST requests with "cmd" in URI?**
   - `http.request.method == "POST" and http.request.uri contains "cmd"`

10. **What is the difference between a horizontal and vertical port scan?**
    - Horizontal: One source scans many ports on one target. Vertical: One source scans one port across many targets.

---

## 12.10 Study Checklist for Module 12

- [ ] Define flow vs session, list 5-tuple components
- [ ] Describe beaconing characteristics and detection methods (statistical, FFT, ML)
- [ ] List lateral movement protocols with ports and flow signatures
- [ ] Write KQL for: Beaconing, SMB lateral, RDP lateral, Exfiltration, Port scans
- [ ] Memorize 15+ tcpdump filters and 15+ Wireshark display filters
- [ ] Explain Zeek log files (conn, http, dns, ssl, files, x509) and key fields
- [ ] Perform PCAP analysis workflow (Conversations → Endpoints → Protocol Hierarchy → Flow Graph → Filters → Follow Stream → Export Objects → Expert Info)
- [ ] Formulate 5 hunt hypotheses with data sources and query patterns
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 13 — Endpoint Security*