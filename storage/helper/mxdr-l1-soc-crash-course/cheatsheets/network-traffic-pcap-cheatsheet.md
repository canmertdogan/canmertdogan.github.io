# Network Traffic & PCAP Analysis Cheat Sheet for SOC Analysts

**Priority: P1 — PCAP and flow data are ground truth for C2, exfiltration, and scans; L1 must be able to find the needle in the capture.**

---

## Core Concepts — Flows, Sessions, and TCP

### Flow vs Session
A **flow** is a unidirectional sequence of packets sharing the **5-tuple**: source IP, dest IP, source port, dest port, protocol (TCP=6, UDP=17, ICMP=1). A **session** is the bidirectional pair of flows (forward + reverse) between two endpoints. NetFlow/IPFIX record flows; Wireshark and Zeek `conn.log` group them into sessions.

### TCP Flags — Memorize
| Flag | Hex | Meaning | SOC Relevance |
|------|-----|---------|---------------|
| **SYN** | 0x02 | Start connection | Port scans (SYN only), connection attempts |
| **SYN-ACK** | 0x12 | Server response | Open port, handshake completion |
| **ACK** | 0x10 | Acknowledge | Data transfer, keep-alive |
| **FIN** | 0x01 | Graceful close | Normal termination |
| **RST** | 0x04 | Abort/reset | **Closed port, firewall block, scanner** |
| **PSH** | 0x08 | Push data | Application urgency |
| **URG** | 0x20 | Urgent pointer | Rare, potential exploit |

**Three-way handshake (memorize):** client SYN → server SYN-ACK → client ACK. A **half-open connection** (SYN sent, ACK never completes) is the signature of a SYN flood or SYN scan. **TCP flag byte filter:** `tcp[13] == 2` = SYN only, `tcp[13] == 18` = SYN-ACK, `tcp[13] == 4` = RST.

### Ports vs Services
A port is a number; the **service** is what runs on it — traffic can use any port for any service. **L1 reflex:** suspicious traffic on a well-known port does NOT mean the real service (e.g., HTTPS on 53, C2 on 443). Memorize the high-risk set: **22** SSH, **25** SMTP, **53** DNS (C2/tunnel/exfil), **80/443** HTTP/HTTPS (web attacks, C2), **88** Kerberos, **135** RPC, **445** SMB (lateral movement, ransomware), **1433** MSSQL, **3389** RDP (brute force, BlueKeep), **5985/5986** WinRM, **8080/8443** alt HTTP/proxies/C2.

---

## tcpdump Essentials

### Capture vs Read
- **Capture:** `tcpdump -i any -nn -s 0 -w capture.pcap` (snaplen 0 = full packets)
- **Live options:** `-i any` (all interfaces), `-n` (no DNS), `-nn` (no DNS + no port names), `-c N` (stop after N packets), `-A` (ASCII payload), `-X` (hex + ASCII payload)
- **Read:** `tcpdump -r capture.pcap` with any filter applied

### Filters — Memorize
| Goal | Filter |
|------|--------|
| Host | `host 10.10.20.5` |
| Subnet | `net 192.168.1.0/24` |
| Port | `port 443` / `tcp port 80 or tcp port 443` |
| Port range | `tcp portrange 8000-8100` |
| Direction | `src host 10.10.20.5 and dst port 53` |
| Protocol | `udp port 53`, `icmp`, `tcp` |
| SYN only | `tcp[13] == 2` |
| RST only | `tcp[13] == 4` |
| Large packets | `len > 1500` |

```bash
# Capture full packets to a file for forensics
sudo tcpdump -i any -nn -s 0 -w evidence.pcap

# Common L1 read commands
tcpdump -r evidence.pcap -nn 'host 10.10.20.5'          # All traffic to/from host
tcpdump -r evidence.pcap -nn 'port 53'                  # DNS only
tcpdump -r evidence.pcap -nn 'tcp[13] == 2'             # SYN-only (scanning)
tcpdump -r evidence.pcap -A 'port 80' | head -50        # ASCII payload (HTTP)
tcpdump -r evidence.pcap -X 'host 203.0.113.9'          # Hex+ASCII payload
tcpdump -r evidence.pcap -A | grep -i "password"        # Cleartext creds hunt
```

---

## Wireshark Essentials

### Display Filters — Memorize
| Goal | Filter |
|------|--------|
| Host anywhere | `ip.addr == 10.10.20.5` |
| Direction | `ip.src == 10.10.20.5` / `ip.dst == 203.0.113.9` |
| Port | `tcp.port == 443`, `udp.port == 53` |
| HTTP | `http.request.method == "POST"` |
| Suspicious URI | `http.request.uri contains "cmd"` |
| TLS | `tls.handshake.type == 1` (ClientHello) |
| SNI | `tls.handshake.extensions_server_name contains "evil"` |
| JA3 | `tls.ja3 == "ae4edc6faf64d08308082ad26be60767"` |
| DNS query | `dns.qry.name contains "tunnel"` |
| TXT records | `dns.qry.type == 16` |
| NXDOMAIN | `dns.flags.rcode == 3` |
| Retransmissions | `tcp.analysis.retransmission` |

### Analysis Workflow
```text
1. STATISTICS → Conversations → sort by Bytes (find top talkers)
2. STATISTICS → Endpoints → separate internal vs external IPs
3. STATISTICS → Protocol Hierarchy → protocol distribution (anomalous DNS? ICMP?)
4. STATISTICS → Flow Graph → visualize TCP session timing (beaconing)
5. Apply filters → focus on external connections, long durations, RST/errors
6. Right-click a conversation → FOLLOW TCP STREAM → reconstruct HTTP/SMTP/creds
7. File → Export Objects → HTTP, SMB, DICOM → hash and triage extracted files
8. Analyze → Expert Info → errors/warnings (retransmissions, malformed, blacklisted)
```

### tshark CLI Equivalents
```bash
tshark -r evidence.pcap -Y 'ip.addr == 10.10.20.5'         # Display-filter read
tshark -r evidence.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport | head
tshark -r evidence.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri | head
tshark -r evidence.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head
tshark -r evidence.pcap -Y 'tcp.flags.syn == 1 and tcp.flags.ack == 0' -c 50
```

---

## Zeek Essentials

Zeek turns raw traffic into structured logs. If your NDR ships Zeek logs, mine these instead of opening a pcap.

| Log | Content | Key L1 Fields |
|-----|---------|---------------|
| **conn.log** | All connections | id.orig_h, id.resp_h, id.resp_p, proto, duration, orig_bytes, resp_bytes, conn_state |
| **dns.log** | DNS queries/responses | query, qtype, rcode, answers, TTLs |
| **ssl.log** | TLS handshakes | server_name (SNI), version, cipher, ja3, issuer, subject |
| **http.log** | HTTP requests | method, host, uri, user_agent, status_code, response_body_len |
| **files.log** | Extracted files | mime_type, filename, sha256, extracted |
| **x509.log** | Certificates | subject, issuer, validity |
| **weird.log** | Protocol anomalies | protocol weirdness — read every line |

```bash
# Beaconing candidates: long-lived, small, outbound TCP
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes | \
awk '$4 == "tcp" && $5 > 100 && $7 < 1000'

# DNS tunneling: TXT queries or NXDOMAIN responses
cat dns.log | zeek-cut query qtype rcode | awk '$2 == "TXT" || $3 == "NXDOMAIN"'

# TLS: weak version or suspicious SNI
cat ssl.log | zeek-cut id.resp_h version server_name ja3 | awk '$2 ~ /TLSv1[01]/'
```

---

## DNS — The L1 Goldmine

DNS is **plaintext metadata** and every analyst's best friend: even if HTTP/HTTPS is encrypted, the resolver log shows what the host asked for.

### Tunneling Indicators
- **Long, high-entropy subdomains** (>50 chars, random base64/base32/hex labels like `a1b2c3d4e5f6...attacker-c2.com`)
- **TXT-heavy** query volume (95%+ of a host's queries are TXT/NULL)
- High query rate to a single domain from one host, often at **regular intervals**
- High **NXDOMAIN** rate (data encoded in the query, answer never exists)

### DGA Indicators
- High NXDOMAIN rate, algorithmic label patterns (length, entropy, consonant/vowel ratio)
- Many domains, few successful resolutions, **newly registered domains (NRD)**
- Same seed → predictable → sinkholing possible

### First-Seen & Anomaly Checks
- **First-seen domain** for the org, domain age < 30 days, unusual TLD
- Unusual record types in volume (TXT, NULL, SRV) for ordinary hosts
- Very low TTL (30-60s) + many A records for one domain = **fast flux**
- Known legitimate domains resolving to unexpected IPs = **DNS hijacking/poisoning** (validate against baseline, check certs)

---

## C2 & Beaconing Detection

**Beaconing** = regular, periodic communication between a compromised host and C2 to fetch commands. MITRE techniques: **T1071** (Application Layer Protocol), **T1573** (Encrypted Channel), **T1105** (Ingress Tool Transfer).

| Characteristic | Normal Traffic | Beaconing |
|----------------|----------------|-----------|
| **Interval** | Variable, bursty | **Constant (jitter +-10-20%)** |
| **Duration** | Session-based | **Long-running (hours/days)** |
| **Packet size** | Variable | **Consistent, small (100-500 bytes)** |
| **Destinations** | Many (CDN, APIs) | **Single/few IPs or domains** |
| **Protocol** | HTTPS, DNS, etc. | Often HTTPS, DNS, or custom TCP |

```bash
# Flow data (Zeek conn.log): same dest, regular intervals, low bytes
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p ts duration orig_bytes resp_bytes | \
awk '$5 > 300 && $6 < 1000 && $7 < 1000' | head -50

# PCAP: find beacon interval via timestamps of a host/port pair
tshark -r evidence.pcap -Y 'ip.addr == 10.10.20.5 && tcp.port == 443' \
  -T fields -e frame.time_relative -e tcp.stream | awk 'NR > 1 {print $1 - prev} {prev = $1}' | head -30
```

**Look for:** HTTP **POST with small request / large response** (task fetch), unusual ports carrying services (**445/53/443 misuse**), **User-Agent anomalies** (python-requests, curl, Go-http-client on Windows hosts), TLS to non-standard IPs, self-signed certs, **long-lived connections**, JA3 fingerprints matching known malware (Cobalt Strike, Meterpreter), and CoV (stddev/mean) of intervals < 0.3.

---

## Exfiltration Detection

| Channel | Detection Focus |
|---------|-----------------|
| **HTTPS (443)** | Large uploads to rare/personal cloud domains |
| **DNS (53)** | TXT/NULL records, base32/hex in labels |
| **HTTP (80)** | Large POST to uncommon destinations |
| **FTP/SFTP (21/22)** | Large transfers to unusual external host |
| **Email (25/587/993)** | Large attachments, auto-forward rules |
| **ICMP** | **Oversized echo payloads** (>64 bytes) — covert channel |
| **Custom TCP/UDP** | Non-standard high ports |

**Signals:** large **outbound** bytes at night/off-hours, data to personal cloud storage (Dropbox, Google Drive, raw paste sites), asymmetric flows (small requests, huge responses — or the reverse), SFTP/SCP to a host the user has never touched, DNS labels decoding to base32/hex.

```bash
# tshark: ICMP payload beyond normal 64 bytes (covert channel)
tshark -r evidence.pcap -Y 'icmp' -T fields -e ip.src -e ip.dst -e frame.len | awk '$3 > 84'

# Zeek: asymmetric outbound volume on port 443
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes | \
awk '$3 == 443 && $4 > 1000000'
```

---

## Reconnaissance & Scanning Detection

| Scan Type | Signature in PCAP/Flows |
|-----------|--------------------------|
| **SYN scan** | Many SYN, few SYN-ACK, many RST (half-open) |
| **Connect scan** | Full handshake per port (louder) |
| **FIN/NULL/Xmas** | Single packet, RST = closed port |
| **UDP scan** | ICMP type 3 code 3 (Port Unreachable) responses |

- **Horizontal scan:** one source, many dest **ports** on one target — `dcount(DestinationPort) > 20`
- **Vertical scan (host sweep):** one source, many dest **IPs** on one port — `dcount(DestinationIp) > 30` with few ports
- **Application-level scan:** HTTP probing — many 404s, `HEAD`/`OPTIONS` bursts, scanning User-Agents (nmap, sqlmap, Go-http-client)

```bash
# Top scanned hosts/ports in a pcap
tshark -r evidence.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -nr | head
```

---

## Correlating with Threat Intel & Evidence Collection

1. **Extract IOCs:** pull every external IP, SNI/domain, and JA3 from the capture — `tshark -r evidence.pcap -T fields -e ip.dst | sort -u` and `-e tls.handshake.extensions_server_name`.
2. **Pivot to intel:** check IPs/domains in VirusTotal, abuseipdb, threat intel feed, passive DNS. Note first-seen, reg date, ASN/geo (unrelated ASN = suspicious).
3. **Correlate:** match pcap timestamps to EDR (process making connections), proxy, and auth logs. Example: PowerShell making DNS queries at beacon time = Sysmon EID 22 correlation.
4. **Classify & evidence for the ticket:** record pcap hash (`sha256sum evidence.pcap`), key frame numbers, the filter that surfaced the IOC, the exact IP/domain/port/timestamps, and the MITRE technique (**T1071/T1573/T1105** for C2, **T1041/T1048** for exfil). Preserve the **original full-capture pcap** — never edit or truncate evidence.

```text
Ticket evidence block:
  File:         evidence.pcap (sha256: 3f9c...e2a1)
  Host:         WORKSTN-047 (10.10.20.47)
  IOC:          attacker-c2.com 203.0.113.9:443
  Frames:       1241-1293 (ClientHello), 1310-4402 (beacon stream)
  Interval:     60s constant, duration 4h02m
  Correlates:   Sysmon EID 22 -> powershell.exe PID 5102 at 03:10 UTC
  Verdict:      HIGH — C2 beaconing, escalate P2
```

---

## Quick Reference — Memorize These One-Liners

```bash
# Top talkers in a pcap
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr | head

# All DNS queries by frequency
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head

# External connections from an internal host
tshark -r capture.pcap -Y 'ip.src == 10.10.20.47 && ip.dst != 10.0.0.0/8' | head

# HTTPS sessions with SNI
tshark -r capture.pcap -Y tls.handshake.type == 1 -T fields -e ip.dst -e tls.handshake.extensions_server_name

# Retransmissions (network trouble or attacker chaos)
tshark -r capture.pcap -Y tcp.analysis.retransmission | wc -l

# Read a pcap's protocol mix
tshark -r capture.pcap -q -z io,phs
```

---

## Summary — L1 Must Know

- [ ] Define flow vs session and recite the 5-tuple (src/dst IP, src/dst port, protocol)
- [ ] Recite TCP flags (SYN/ACK/FIN/RST/PSH) and their hex values
- [ ] Capture a pcap: `tcpdump -i any -nn -s 0 -w file.pcap` and read it with `-r`
- [ ] Filter by host, net, port, and protocol; show payloads with `-A`/`-X`
- [ ] Use Wireshark display filters for IP, port, HTTP, TLS SNI, and DNS query names
- [ ] Follow the workflow: Conversations → Endpoints → Protocol Hierarchy → Follow Stream → Export Objects
- [ ] Spot DNS tunneling (long high-entropy labels, TXT-heavy, high NXDOMAIN) and DGA (random labels, NRD)
- [ ] Recognize beaconing (constant interval, small packets, single dest) and C2 over HTTP/HTTPS
- [ ] Flag exfiltration (large off-hours outbound, personal cloud, DNS/ICMP covert channels)
- [ ] Distinguish horizontal (many ports) vs vertical (many hosts) scans from SYN patterns
- [ ] Correlate pcap IOCs with threat intel and endpoint logs before escalating
- [ ] Collect evidence properly: preserve the original pcap, capture hash, frame numbers, and timestamps
