# Module 9: Networking for SOC

**Priority: P0 — Network visibility = detection coverage. L1 must read PCAP, flows, logs.**

---

## 9.1 OSI Model — SOC Perspective

| Layer | Name | PDU | SOC Relevance | Key Protocols |
|-------|------|-----|---------------|---------------|
| **7** | Application | Data | **App-layer visibility** (HTTP, DNS, SMTP, LDAP, Kerberos) | HTTP, DNS, SMTP, IMAP, LDAP, Kerberos, RDP, SSH |
| **6** | Presentation | Data | Encryption, encoding, compression | TLS/SSL, ASN.1, MIME |
| **5** | Session | Data | Session management, RPC | NetBIOS, RPC, PPTP |
| **4** | Transport | Segment | **Ports, connections, state** | TCP, UDP, SCTP |
| **3** | Network | Packet | **Routing, IP addressing, fragmentation** | IP, ICMP, IPsec, OSPF, BGP |
| **2** | Data Link | Frame | **MAC, VLAN, switching, ARP** | Ethernet, WiFi, ARP, VLAN, PPP |
| **1** | Physical | Bits | Hardware, cabling, signals | Copper, Fiber, Radio |

**L1 Focus**: Layers 3, 4, 7 (IP, TCP/UDP, Application). Layer 2 for local network forensics.

---

## 9.2 TCP/IP Suite — Core Protocols

### IP (Internet Protocol) — Layer 3
| Field | Size | SOC Relevance |
|-------|------|---------------|
| Version | 4 bits | IPv4 (4) vs IPv6 (6) |
| IHL | 4 bits | Header length (options?) |
| DSCP/ECN | 8 bits | QoS, congestion marking |
| Total Length | 16 bits | Packet size (MTU issues) |
| Identification | 16 bits | Fragmentation tracking |
| Flags/Fragment Offset | 16 bits | **Fragmentation attacks** |
| **TTL** | 8 bits | **Hop count, traceroute, OS fingerprint** |
| **Protocol** | 8 bits | **TCP=6, UDP=17, ICMP=1, IPsec=50/51** |
| Header Checksum | 16 bits | Integrity |
| **Source IP** | 32/128 bits | **Attribution, geo, reputation** |
| **Destination IP** | 32/128 bits | **Target, pivot detection** |
| Options | Variable | Rare, suspicious (source routing) |

### ICMP (Internet Control Message Protocol) — Layer 3.5
| Type | Code | Name | SOC Relevance |
|------|------|------|---------------|
| 0 | 0 | Echo Reply | Ping response |
| 3 | 0-15 | Destination Unreachable | **Firewall blocks, network mapping** |
| 3 | 3 | Port Unreachable | UDP scan response |
| 4 | 0 | Source Quench | Legacy congestion |
| 5 | 0-3 | Redirect | **MITM potential** |
| 8 | 0 | Echo Request | Ping, **traceroute, covert channel** |
| 11 | 0-1 | Time Exceeded | **Traceroute (TTL expired)** |
| 13/14 | 0 | Timestamp | Clock sync, reconnaissance |
| 30 | 0 | Traceroute (deprecated) | Alternative traceroute |

**Covert Channel**: ICMP tunneling (data in payload), oversized packets (>64 bytes).

### TCP (Transmission Control Protocol) — Layer 4
```
TCP Header (20 bytes minimum):
┌─────────────────────────────────────────────────────────────┐
│ Source Port (16)  │ Destination Port (16)                   │
├─────────────────────────────────────────────────────────────┤
│ Sequence Number (32)                                        │
├─────────────────────────────────────────────────────────────┤
│ Acknowledgment Number (32)                                  │
├──────────┬──────┬──────┬────────────────────────────────────┤
│ Data Off │ RSV  │ Flags │ Window Size (16)                  │
├──────────┼──────┼──────┼────────────────────────────────────┤
│ Checksum (16)   │ Urgent Pointer (16)                       │
├─────────────────────────────────────────────────────────────┤
│ Options (Variable: MSS, Window Scale, SACK, Timestamp)      │
└─────────────────────────────────────────────────────────────┘
```

**TCP Flags (Memorize)**:
| Flag | Bit | Hex | Meaning | SOC Relevance |
|------|-----|-----|---------|---------------|
| **SYN** | 1 | 0x02 | Synchronize (start) | **Port scan (SYN scan), connection attempts** |
| **SYN-ACK** | 1+4 | 0x12 | SYN + ACK | Server response, **open port** |
| **ACK** | 4 | 0x10 | Acknowledge | Data transfer, keep-alive |
| **FIN** | 0 | 0x01 | Finish (graceful close) | Normal termination |
| **RST** | 2 | 0x04 | Reset (abort) | **Port closed, firewall block, scanner** |
| **PSH** | 3 | 0x08 | Push (urgent data) | Application urgency |
| **URG** | 5 | 0x20 | Urgent pointer valid | Rare, potential exploit |

### Three-Way Handshake (Memorize)
```
Client                                    Server
   │                                          │
   ├─ SYN (seq=X) ───────────────────────────►│
   │                                          │
   │◄─ SYN-ACK (seq=Y, ack=X+1) ─────────────┤
   │                                          │
   ├─ ACK (seq=X+1, ack=Y+1) ────────────────►│
   │                                          │
   │         CONNECTION ESTABLISHED           │
   │                                          │
```

**Half-Open (SYN Flood)**: Client sends SYN, never completes ACK → Server resource exhaustion.

### TCP Connection Termination
```
Graceful (4-way):
Client                                    Server
   ├─ FIN ─────────────────────────────────►│
   │◄─ ACK ─────────────────────────────────┤
   │                                          │ (Server closes)
   │◄─ FIN ─────────────────────────────────┤
   ├─ ACK ─────────────────────────────────►│

Abrupt (RST):
   ├─ RST ─────────────────────────────────►│  (Immediate close)
```

### UDP (User Datagram Protocol) — Layer 4
| Field | Size | Notes |
|-------|------|-------|
| Source Port | 16 bits | |
| Destination Port | 16 bits | |
| Length | 16 bits | Header + Data |
| Checksum | 16 bits | Optional in IPv4 |

**SOC Relevance**: DNS (53), NTP (123), SNMP (161/162), Syslog (514), DHCP (67/68), **Amplification attacks** (NTP, DNS, Memcached), **CoAP/IoT**, **QUIC (HTTP/3)**.

---

## 9.3 Critical Ports — Memorize These

| Port | Protocol | Service | SOC Relevance |
|------|----------|---------|---------------|
| **20/21** | TCP | FTP (Data/Control) | Credential theft, anonymous access, data exfil |
| **22** | TCP | SSH | **Brute force, lateral (Linux), tunneling, proxy** |
| **23** | TCP | Telnet | **Cleartext creds, IoT, legacy** |
| **25** | TCP | SMTP | **Phishing relay, spam, enumeration (VRFY/EXPN)** |
| **53** | TCP/UDP | DNS | **C2, tunneling, exfil, reconnaissance** |
| **67/68** | UDP | DHCP | Rogue DHCP, MITM |
| **69** | UDP | TFTP | Firmware, config exfil, IoT |
| **80** | TCP | HTTP | **Web attacks, C2, phishing delivery** |
| **88** | TCP/UDP | Kerberos | **Authentication, Kerberoasting, delegation** |
| **110** | TCP | POP3 | Credential theft, cleartext |
| **123** | UDP | NTP | **Amplification, time sync (kerberos depends on it)** |
| **135** | TCP | RPC Endpoint Mapper | **Lateral movement, reconnaissance** |
| **137/138/139** | TCP/UDP | NetBIOS | Legacy, enumeration, poisoning |
| **143** | TCP | IMAP | Credential theft |
| **161/162** | UDP | SNMP | **Enumeration (public community), config theft** |
| **389** | TCP/UDP | LDAP | **AD enumeration, authentication, delegation** |
| **443** | TCP | HTTPS | **C2, exfil, phishing, web attacks (encrypted)** |
| **445** | TCP | SMB | **Lateral movement, PsExec, file share, ransomware** |
| **464** | TCP/UDP | Kerberos Password Change | Password reset attacks |
| **514** | UDP | Syslog | Log injection, exfil |
| **587** | TCP | SMTP Submission | Authenticated relay |
| **593** | TCP | HTTP RPC (Outlook Anywhere) | Legacy Exchange |
| **636** | TCP | LDAPS | Secure LDAP |
| **993** | TCP | IMAPS | Secure IMAP |
| **995** | TCP | POP3S | Secure POP3 |
| **1433** | TCP | MSSQL | **Data theft, xp_cmdshell, lateral** |
| **1434** | UDP | MSSQL Browser | Enumeration |
| **1723** | TCP | PPTP VPN | Legacy VPN |
| **3306** | TCP | MySQL | Data theft |
| **3389** | TCP | RDP | **Brute force, lateral, credential theft, BlueKeep** |
| **5060/5061** | UDP/TCP | SIP | VoIP enumeration |
| **5432** | TCP | PostgreSQL | Data theft |
| **5900** | TCP | VNC | Remote access, often no auth |
| **5985/5986** | TCP | WinRM (HTTP/HTTPS) | **Lateral (PowerShell Remoting)** |
| **8080/8443/8888** | TCP | HTTP Alt / Proxies | **C2, web shells, dev servers** |
| **9100** | TCP | JetDirect (Printers) | IoT, printer exploitation |
| **27017** | TCP | MongoDB | Data theft, ransomware |

---

## 9.4 IP Addressing & Routing — SOC Essentials

### IPv4 Address Classes (Legacy but still referenced)
| Class | Range | CIDR | Hosts | Use |
|-------|-------|------|-------|-----|
| A | 1.0.0.0 – 126.255.255.255 | /8 | 16.7M | Large orgs |
| B | 128.0.0.0 – 191.255.255.255 | /16 | 65K | Medium orgs |
| C | 192.0.0.0 – 223.255.255.255 | /24 | 254 | Small orgs |
| D | 224.0.0.0 – 239.255.255.255 | N/A | N/A | Multicast |
| E | 240.0.0.0 – 255.255.255.255 | N/A | N/A | Reserved |

### Private RFC 1918 Ranges (Internal Only)
| Range | CIDR | Hosts |
|-------|------|-------|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | 16.7M |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | 1M |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | 65K |

**Carrier-Grade NAT (CGNAT)**: 100.64.0.0/10 (ISP internal)

### Special Addresses
| Address | Purpose |
|---------|---------|
| 0.0.0.0 | Default route, "this network" |
| 127.0.0.0/8 | Loopback (127.0.0.1 = localhost) |
| 169.254.0.0/16 | Link-local (APIPA — DHCP fail) |
| 224.0.0.0/4 | Multicast (mDNS, routing protocols) |
| 255.255.255.255 | Limited broadcast |

### Subnetting (CIDR) — Quick Reference
| CIDR | Mask | Hosts | Use |
|------|------|-------|-----|
| /32 | 255.255.255.255 | 1 | Single host |
| /30 | 255.255.255.252 | 2 | Point-to-point |
| /29 | 255.255.255.248 | 6 | Small segment |
| /28 | 255.255.255.240 | 14 | DMZ, mgmt |
| /27 | 255.255.255.224 | 30 | VLAN |
| /26 | 255.255.255.192 | 62 | Department |
| /24 | 255.255.255.0 | 254 | Standard VLAN |
| /23 | 255.255.254.0 | 510 | Large VLAN |
| /22 | 255.255.252.0 | 1022 | Building |
| /16 | 255.255.0.0 | 65K | Campus |

### NAT (Network Address Translation)
| Type | Description | SOC Impact |
|------|-------------|------------|
| **Static NAT** | 1:1 mapping (Public ↔ Private) | Server exposure tracking |
| **Dynamic NAT** | Pool of public IPs | Session correlation harder |
| **PAT / NAPT** | Many:1 (Port Address Translation) | **Most common — source port = session ID** |
| **Double NAT** | NAT behind NAT (home + ISP) | Geo/IP reputation confusion |

**Firewall Logs**: Show **post-NAT** (public IP) or **pre-NAT** (private IP) depending on placement. Know your sensor location!

---

## 9.5 DHCP — Dynamic Host Configuration Protocol

### DORA Process
```
Client                                    Server
   │                                          │
   ├─ DISCOVER (broadcast) ──────────────────►│
   │                                          │
   │◄─ OFFER (unicast/broadcast) ────────────┤
   │   • Offered IP, Subnet, Gateway, DNS     │
   │   • Lease Time, Server ID, Options       │
   │                                          │
   ├─ REQUEST (broadcast) ───────────────────►│
   │   • Requested IP, Server ID              │
   │                                          │
   │◄─ ACK (unicast) ────────────────────────┤
   │   • Confirmed IP, Lease, Options         │
```

### DHCP Options (Security Relevant)
| Option | Name | Abuse |
|--------|------|-------|
| 1 | Subnet Mask | |
| 3 | Router (Gateway) | **Rogue gateway → MITM** |
| 6 | DNS Servers | **Rogue DNS → Phishing, C2 redirect** |
| 15 | Domain Name | |
| 42 | NTP Servers | Time sync attacks |
| 60 | Vendor Class ID | Device fingerprinting |
| 66/67 | TFTP Server / Bootfile | **PXE boot hijack** |
| 119 | Domain Search | Suffix search order |
| 252 | WPAD (Proxy Auto-Config) | **WPAD spoofing → MITM** |

### DHCP Attack Detection
- **Rogue DHCP**: Multiple OFFERs for same client, unauthorized server MAC
- **DHCP Starvation**: Exhaust pool (many DISCOVERs from different MACs)
- **Option 6/252 tampering**: Rogue DNS/WPAD in OFFER/ACK

---

## 9.6 VPN, Proxy, Firewall — Network Security Devices

### VPN (Virtual Private Network)
| Type | Protocol | Port | SOC Visibility |
|------|----------|------|----------------|
| **IPsec** | ESP (50), AH (51), IKE (500/4500) | Encrypted | **Limited** (metadata only) |
| **SSL/TLS VPN** | HTTPS (443) | 443 | App-layer visibility (if decrypt) |
| **WireGuard** | UDP (51820 default) | High perf | Modern, simple |
| **OpenVPN** | UDP/TCP (1194) | Configurable | TLS-based |

**VPN Logs**: User, source IP, assigned virtual IP, connect/disconnect time, bytes transferred, split-tunnel vs full-tunnel.

### Proxy (Forward Proxy)
| Mode | Description | Visibility |
|------|-------------|------------|
| **Explicit** | Client configured (PAC/WPAD) | Full HTTP/HTTPS (with decrypt) |
| **Transparent** | Intercepted (no client config) | Full (with decrypt) |
| **Reverse** | Protects servers (WAF) | Inbound visibility |

**Proxy Logs**: Timestamp, Client IP, User, Method, URL, Category, Response Code, Bytes, MIME Type, **User-Agent**, **Referer**, **X-Forwarded-For**, Action (Allow/Block/Scan).

### Firewall (Stateful Inspection)
| Feature | Description |
|---------|-------------|
| **State Table** | Tracks TCP state (SYN, ESTABLISHED, FIN), UDP pseudo-state |
| **Rules** | Source/Dest IP, Port, Protocol, App-ID, User-ID, Action |
| **Zones** | Trust, Untrust, DMZ, Management |
| **NAT** | Source/Dest NAT, PAT |
| **App-ID** | Layer 7 identification (SSL, SSH, Facebook, etc.) |
| **User-ID** | Maps IP → User (AD integration) |
| **Decryption** | SSL Forward Proxy (outbound), SSL Inbound Inspection |

**Firewall Logs**: Timestamp, Rule Name, Source IP/Port/Zone/User, Dest IP/Port/Zone, Protocol, App, Action, Bytes, Packets, **Session ID**, Threat ID (if IPS/AV hit).

### IDS/IPS (Intrusion Detection/Prevention)
| Mode | Placement | Action |
|------|-----------|--------|
| **IDS** | SPAN/TAP (passive) | Alert only |
| **IPS** | Inline (active) | Block/Drop/Reset |

**Signatures**: Snort/Suricata rules, Emerging Threats, Vendor proprietary.
**Anomaly**: Baseline deviation (beaconing, volume, new protocols).

---

## 9.7 NDR (Network Detection and Response)

### Data Sources
| Source | Collection | Visibility |
|--------|------------|------------|
| **SPAN/Mirror Port** | Switch port mirroring | East-West, North-South |
| **Network TAP** | Hardware tap (passive) | Full line rate, no drop |
| **Cloud/VPC Flow Logs** | AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs | Cloud east-west |
| **Zeek (Bro)** | Software sensor | **Protocol parsing, files, certs, scripts** |
| **Suricata** | IDS/IPS engine | Rules + protocol parsing |

### Zeek (Bro) — Key Logs
| Log File | Content |
|----------|---------|
| `conn.log` | **All connections** (5-tuple, duration, bytes, state, service) |
| `http.log` | HTTP requests/responses (method, URI, headers, status, body hash) |
| `dns.log` | DNS queries/responses (query, answers, TTL, query type) |
| `ssl.log` | TLS handshakes (version, cipher, cert, JA3, SNI, validation) |
| `files.log` | Extracted files (hash, MIME, source) |
| `x509.log` | Certificate details |
| `ssh.log` | SSH sessions (version, auth, algorithms) |
| `rdp.log` | RDP connections |
| `smb_files.log` / `smb_mapping.log` | SMB file access, share mapping |
| `kerberos.log` | Kerberos traffic |
| `weird.log` | Protocol anomalies |

---

## 9.8 Network Flow Data (NetFlow/IPFIX/sFlow)

### NetFlow v5/v9/IPFIX Fields
| Field | Description |
|-------|-------------|
| **Src IP, Dst IP** | Endpoints |
| **Src Port, Dst Port** | Services |
| **Protocol** | TCP=6, UDP=17, ICMP=1 |
| **Packets, Bytes** | Volume |
| **Start Time, End Time** | Duration |
| **TCP Flags (OR'd)** | SYN, FIN, RST, PSH, ACK, URG |
| **ToS/DSCP** | QoS marking |
| **Input/Output Interface** | Direction |
| **AS Numbers** | Source/Dest Autonomous System |
| **Next Hop** | Routing |
| **VLAN IDs** | Segmentation |

### Flow Analysis for SOC
| Pattern | Detection |
|---------|-----------|
| **Beaconing** | Regular interval, small packets, long duration |
| **Port Scan** | One src → many dst ports (SYN only) |
| **Host Scan** | One src → many dst IPs (same port) |
| **Data Exfil** | Large outbound, unusual dest, off-hours |
| **Lateral Movement** | Internal → Internal (SMB, RDP, RPC, WinRM) |
| **C2** | Known bad IP, DGA domains, suspicious JA3 |
| **DDoS** | Volume spike, many sources → one dest |

---

## 9.9 Wireless (WiFi) — Brief SOC Notes

| Standard | Freq | Max Rate | Security |
|----------|------|----------|----------|
| 802.11n (WiFi 4) | 2.4/5 GHz | 600 Mbps | WPA2 |
| 802.11ac (WiFi 5) | 5 GHz | 6.9 Gbps | WPA2/WPA3 |
| 802.11ax (WiFi 6/6E) | 2.4/5/6 GHz | 9.6 Gbps | WPA3 |

**Attacks**: Evil Twin (rogue AP), KRACK (WPA2), PMKID (WPA3), Deauth, WPS PIN brute force.
**Detection**: WIPS (Wireless IPS), rogue AP detection, anomalous associations.

---

## 9.10 Interview Questions for This Module

1. **Explain the TCP three-way handshake and what each packet contains.**
   - SYN (seq=X) → SYN-ACK (seq=Y, ack=X+1) → ACK (seq=X+1, ack=Y+1). Establishes sequence numbers for reliable delivery.

2. **What is the difference between TCP and UDP? When would you see each?**
   - TCP: Connection-oriented, reliable, ordered, flow control (HTTP, SSH, SMB). UDP: Connectionless, no guarantee, low latency (DNS, NTP, DHCP, streaming).

3. **What do the TCP flags SYN, ACK, FIN, RST, PSH mean?**
   - SYN: Start connection. ACK: Acknowledge. FIN: Graceful close. RST: Abort connection. PSH: Push data to app immediately.

4. **What is NAT and how does it affect SOC visibility?**
   - Network Address Translation maps private IPs to public. PAT (NAPT) uses ports for many:1 mapping. Sensors see post-NAT or pre-NAT depending on placement — must know which!

5. **What are the RFC 1918 private IP ranges?**
   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Also CGNAT 100.64.0.0/10.

6. **What is the DHCP DORA process and which options are security-relevant?**
   - Discover, Offer, Request, ACK. Options: 3 (Gateway — MITM), 6 (DNS — hijack), 252 (WPAD — MITM), 66/67 (PXE boot).

7. **What is the difference between a forward proxy and a reverse proxy?**
   - Forward: Client → Internet (egress control, visibility). Reverse: Internet → Server (WAF, load balancing, inbound protection).

8. **What network data sources does NDR use and what does Zeek provide?**
   - SPAN/TAP, Cloud flow logs, Zeek, Suricata. Zeek: conn.log, http.log, dns.log, ssl.log, files.log, x509.log — protocol parsing + extracted artifacts.

9. **What NetFlow fields are most useful for detecting C2 beaconing?**
   - Src/Dst IP/Port, Protocol, Packets/Bytes, Start/End Time, TCP Flags, Duration. Beaconing = regular interval, small bytes, long duration, same dest.

10. **How does a TCP SYN scan work and what does the target respond with?**
    - Scanner sends SYN → Open port responds SYN-ACK → Scanner sends RST (never completes handshake). Closed port responds RST. Filtered = no response.

---

## 9.11 Study Checklist for Module 9

- [ ] Draw OSI/TCP/IP model with protocols at each layer
- [ ] Explain TCP 3-way handshake and 4-way termination
- [ ] Identify TCP flags and their hex values
- [ ] List top 30 ports with service and SOC relevance
- [ ] Explain IPv4 classes, RFC 1918, CIDR notation
- [ ] Describe NAT types and SOC impact
- [ ] Walk through DHCP DORA and identify risky options
- [ ] Compare VPN, Proxy, Firewall, IDS/IPS visibility
- [ ] List Zeek log files and their content
- [ ] Identify flow analysis patterns (beaconing, scan, exfil, lateral)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 10 — DNS Security*