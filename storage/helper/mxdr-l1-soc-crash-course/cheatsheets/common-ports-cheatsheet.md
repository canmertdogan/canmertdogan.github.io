# Common Ports Cheat Sheet for SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## Well-Known Ports (0-1023) — Must Memorize

| Port | Protocol | Service | SOC Relevance |
|------|----------|---------|---------------|
| **20** | TCP | FTP Data | File transfer, data exfil |
| **21** | TCP | FTP Control | Authentication, brute force, anonymous access |
| **22** | TCP | SSH | **Critical** — remote admin, brute force, tunneling, lateral movement |
| **23** | TCP | Telnet | **Insecure** — cleartext creds, legacy systems, IoT |
| **25** | TCP | SMTP | Email delivery, open relay, spam, phishing |
| **53** | TCP/UDP | **DNS** | **Critical** — resolution, tunneling (TCP), DGA, exfil |
| **67/68** | UDP | DHCP | IP assignment, rogue DHCP, MITM |
| **69** | UDP | TFTP | Firmware/config transfer, IoT, no auth |
| **80** | TCP | HTTP | Web traffic, cleartext, proxy logs, web attacks |
| **88** | TCP/UDP | Kerberos | **Critical** — AD authentication, Kerberoasting, Golden Ticket |
| **110** | TCP | POP3 | Email retrieval, cleartext creds |
| **123** | UDP | NTP | Time sync, amplification attacks |
| **135** | TCP | RPC / EPMAP | **Critical** — DCOM, WMI, lateral movement, reconnaissance |
| **137/138/139** | TCP/UDP | NetBIOS | Legacy name resolution, enumeration, SMB over NetBIOS |
| **143** | TCP | IMAP | Email retrieval, cleartext creds |
| **161/162** | UDP | SNMP | Network monitoring, enumeration (public community string) |
| **389** | TCP/UDP | LDAP | **Critical** — AD queries, enumeration, anonymous binds |
| **443** | TCP | **HTTPS** | **Critical** — encrypted web, C2, exfil, proxy visibility |
| **445** | TCP | **SMB** | **Critical** — file shares, lateral movement, PsExec, EternalBlue |
| **464** | TCP/UDP | Kerberos Password Change | Password changes, kpasswd |
| **465** | TCP | SMTPS | SMTP over SSL (legacy) |
| **587** | TCP | SMTP Submission | Email submission (STARTTLS) |
| **636** | TCP | LDAPS | LDAP over SSL |
| **873** | TCP | rsync | File sync, backup, data exfil |
| **993** | TCP | IMAPS | IMAP over SSL |
| **995** | TCP | POP3S | POP3 over SSL |
| **1433** | TCP | MS SQL | Database, SQL injection, data theft |
| **1521** | TCP | Oracle DB | Database access |
| **1723** | TCP | PPTP VPN | Legacy VPN, weak encryption |
| **3306** | TCP | MySQL | Database, web app backend |
| **3389** | TCP | **RDP** | **Critical** — remote desktop, brute force, lateral, exposed |
| **5432** | TCP | PostgreSQL | Database |
| **5900** | TCP | VNC | Remote desktop, often unsecured |
| **5985/5986** | TCP | WinRM / PowerShell Remoting | **Critical** — lateral movement, admin, HTTP/HTTPS |
| **6379** | TCP | Redis | Cache/db, often unprotected, RCE |
| **8080/8443** | TCP | Alt HTTP/HTTPS | Proxy, web apps, management interfaces |
| **8888** | TCP | Alt HTTP | Development, management consoles |
| **9000-9090** | TCP | Various | Development, management, SonarQube, etc. |

---

## Registered Ports (1024-49151) — Common in SOC

| Port | Protocol | Service | SOC Relevance |
|------|----------|---------|---------------|
| **1080** | TCP | SOCKS Proxy | Tunneling, bypass, C2 |
| **1194** | UDP | OpenVPN | VPN traffic |
| **1434** | UDP | MS SQL Browser | SQL instance discovery |
| **1701** | UDP | L2TP | VPN |
| **1812/1813** | UDP | RADIUS | AAA, authentication |
| **2049** | TCP/UDP | NFS | File sharing, Linux/Unix |
| **2100** | TCP | FTP Data (alt) | |
| **2222** | TCP | SSH (alt) | Non-standard SSH |
| **2375/2376** | TCP | Docker API | **Critical** — container escape, unauthorized access |
| **27017** | TCP | MongoDB | Database, often exposed |
| **3128** | TCP | Squid Proxy | Corporate proxy |
| **3268/3269** | TCP | Global Catalog | AD GC (LDAP) |
| **3306** | TCP | MySQL | |
| **4444** | TCP | Metasploit Default | **Malware/C2 default** — suspicious if seen |
| **47808** | UDP | BACnet | Building automation (OT) |
| **5000** | TCP | Docker Registry / Flask | Dev tools |
| **5060/5061** | UDP/TCP | SIP | VoIP |
| **5601** | TCP | Kibana | Elasticsearch UI |
| **5672** | TCP | RabbitMQ | Message queue |
| **5901-5910** | TCP | VNC Displays | Multiple VNC sessions |
| **6379** | TCP | Redis | |
| **8000-8010** | TCP | Dev web servers | Python, Django, etc. |
| **8080** | TCP | HTTP Proxy / Alt Web | Very common for C2, web shells |
| **8081/8082** | TCP | Alt Web / Jenkins | CI/CD, management |
| **8443** | TCP | HTTPS Alt | Management consoles, APIs |
| **9000** | TCP | SonarQube / PHP-FPM | Code quality, PHP |
| **9090** | TCP | Cockpit / Prometheus | Linux admin, monitoring |
| **9200/9300** | TCP | Elasticsearch | Log storage, often unsecured |
| **9418** | TCP | Git | Git protocol |
| **10000** | TCP | Webmin | Linux web admin |
| **11211** | TCP | Memcached | Caching, amplification, data exposure |
| **15672** | TCP | RabbitMQ Management | Management UI |
| **27017/27018** | TCP | MongoDB | Database |
| **50000** | TCP | SAP / DB2 | Enterprise apps |

---

## Ephemeral / Dynamic Ports (49152-65535)

| Range | Use |
|-------|-----|
| **49152-65535** | Client-side ephemeral ports (outbound connections) |
| **49152-65535** | Server-side dynamic RPC ports (Windows) |

**SOC Note**: Outbound connections from your network will use these as source ports. Inbound to these = suspicious (servers shouldn't listen here typically).

---

## Port Categories by SOC Interest

### 🔴 CRITICAL — High Alert Value
| Port(s) | Why Critical |
|---------|--------------|
| **22, 3389, 5985/5986** | Remote access — brute force, lateral, exposed admin |
| **445, 135, 139, 5985/5986** | Windows lateral movement (SMB, RPC, WinRM) |
| **88, 389, 636, 3268/3269** | AD authentication — Kerberoasting, enumeration, DCSync |
| **53** | DNS — tunneling, DGA, C2, exfil |
| **443, 80, 8080, 8443** | Web — C2, exfil, web shells, proxy visibility |
| **1433, 3306, 5432, 27017** | Databases — data theft, SQLi, exposed DBs |

### 🟡 HIGH — Investigate Anomalies
| Port(s) | Why High |
|---------|----------|
| **21, 23, 110, 143** | Cleartext protocols — credential theft |
| **25, 587, 465** | Email — spam, phishing, open relay |
| **161/162** | SNMP — enumeration, config theft |
| **6379, 11211, 27017** | NoSQL/Redis — often unprotected, data exposure |
| **5900, 5901+** | VNC — remote access, often weak/no auth |
| **1080, 3128** | Proxies — tunneling, bypass |
| **2375/2376** | Docker API — container escape, RCE |

### 🟢 MEDIUM — Context Dependent
| Port(s) | Context |
|---------|---------|
| **67/68** | DHCP — rogue server, MITM |
| **69** | TFTP — firmware, config, IoT |
| **123** | NTP — amplification, time sync |
| **1194, 1701, 1723** | VPN — legitimate remote access |
| **5060/5061** | SIP — VoIP, toll fraud |
| **2049** | NFS — Linux file sharing |

---

## Common Malware / C2 Default Ports

| Port | Associated With |
|------|-----------------|
| **443** | Almost all modern C2 (HTTPS) — Cobalt Strike, Sliver, Empire, custom |
| **80** | HTTP C2 (less common now) |
| **8080, 8443, 8888** | HTTP/HTTPS alt — many C2 frameworks default here |
| **4444** | Metasploit default reverse shell |
| **4445** | Metasploit secondary |
| **5555** | Android ADB / some C2 |
| **6666, 6667, 6697** | IRC (legacy C2) |
| **1337** | "Leet" — custom tools, backdoors |
| **31337** | "Elite" — backdoors, rootkits |
| **1234, 12345, 54321** | Netcat, simple backdoors |
| **12345** | NetBus (legacy) |
| **27374** | SubSeven (legacy) |
| **31337** | Back Orifice (legacy) |

**Key Insight**: Modern C2 **almost always uses 443 (HTTPS)** or **80 (HTTP)** to blend in. Non-standard ports are noisy.

---

## Protocol vs Port Quick Reference

| Protocol | Standard Port | Common Alternatives | Encrypted? |
|----------|---------------|---------------------|------------|
| **SSH** | 22 | 2222, 2200, 2022 | ✅ Yes |
| **RDP** | 3389 | 3390, 13389 | ✅ Yes (with NLA) |
| **HTTPS** | 443 | 8443, 8080, 9443 | ✅ Yes |
| **HTTP** | 80 | 8080, 8888, 8000 | ❌ No |
| **SMB** | 445 | — | ⚠️ SMB 3.x supports encryption |
| **LDAP** | 389 | — | ❌ No (use 636/StartTLS) |
| **LDAPS** | 636 | 3269 (GC) | ✅ Yes |
| **Kerberos** | 88 | — | ✅ Yes (tickets) |
| **DNS** | 53 | — | ❌ No (DoH/DoT on 443/853) |
| **WinRM** | 5985 (HTTP), 5986 (HTTPS) | — | 5986 ✅ Yes |
| **RPC** | 135 + dynamic | — | ❌ No |
| **SQL Server** | 1433 | 14330, 2433 | ⚠️ Optional TLS |
| **MySQL** | 3306 | 33060 | ⚠️ Optional TLS |
| **PostgreSQL** | 5432 | — | ⚠️ Optional TLS |
| **MongoDB** | 27017 | 27018 | ⚠️ Optional TLS |
| **Redis** | 6379 | — | ❌ No (ACL in 6.0+) |
| **Docker API** | 2375 (HTTP), 2376 (HTTPS) | — | 2376 ✅ Yes |
| **VNC** | 5900+ | 5901-5910 | ⚠️ Optional TLS |

---

## Windows RPC Dynamic Port Range

```
Default: 49152-65535 (Vista/2008+)
Legacy:  1024-5000 (pre-Vista)

Check on host:
  netsh int ipv4 show dynamicport tcp
  netsh int ipv6 show dynamicport tcp
```

**SOC Relevance**: SMB/RPC lateral movement uses dynamic ports. Firewall must allow 445 + dynamic range for Windows admin.

---

## KQL/SPL Port Queries

```kql
// Suspicious external connections on critical ports
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemoteIPType == "Public"
| where RemotePort in (22, 23, 3389, 445, 135, 139, 5985, 5986, 1433, 3306, 5432, 6379, 27017)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName

// Non-standard ports from internal to external
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemoteIPType == "Public"
| where RemotePort !in (53, 80, 443, 123, 993, 995, 587, 465, 9418)
| where InitiatingProcessFileName !in ("chrome.exe", "firefox.exe", "msedge.exe", "teams.exe", "onedrive.exe")
| summarize count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where count > 10
```

```spl
# Suspicious external connections on critical ports
index=edr sourcetype=edr_network dest_ip_type=public dest_port IN (22,23,3389,445,135,139,5985,5986,1433,3306,5432,6379,27017)
| table _time, hostname, dest_ip, dest_port, process_name

# Non-standard ports (exclude browsers, known apps)
index=edr sourcetype=edr_network dest_ip_type=public
| where NOT dest_port IN (53,80,443,123,993,995,587,465,9418)
| where NOT process_name IN ("chrome.exe","firefox.exe","msedge.exe","teams.exe","onedrive.exe")
| stats count by hostname, process_name, dest_ip, dest_port
| where count > 10
```

---

## One-Page Print Version

```
COMMON PORTS — SOC QUICK REFERENCE
==================================

🔴 CRITICAL (Remote Access, Lateral, AD, DNS, Web, DB):
  22    SSH           3389  RDP
  5985/5986  WinRM    445   SMB
  135/139    RPC      88    Kerberos
  389/636    LDAP     53    DNS
  80/443     HTTP/S   8080/8443 Alt Web
  1433       MS SQL   3306  MySQL
  5432       Postgre  27017 MongoDB

🟡 HIGH (Cleartext, Email, Proxies, NoSQL, VNC, Docker):
  21/23    FTP/Telnet  25/587  SMTP
  110/143  POP3/IMAP   161/162 SNMP
  6379     Redis       11211   Memcached
  5900+    VNC         2375/2376 Docker API
  1080/3128 Proxy

🟢 MEDIUM (Context):
  67/68 DHCP  69 TFTP  123 NTP  1194/1723 VPN

🚨 MALWARE/C2 DEFAULTS:
  443   HTTPS C2 (most common!)
  80/8080/8443 HTTP/S Alt
  4444  Metasploit
  1337/31337 "Leet/Elite" backdoors
  1234/12345 Simple backdoors

EPHEMERAL PORTS: 49152-65535 (Client outbound, Windows RPC dynamic)

KEY INSIGHT: Modern C2 = 443 (HTTPS) to blend in. Non-standard = noisy.
```