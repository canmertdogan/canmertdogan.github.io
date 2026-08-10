# Module 26: Security Products — Telemetry & SOC Usage

**Priority: P1 — Important for first months on the job**

> **Focus**: What each product produces, how L1 uses it, and how they integrate in MXDR

---

## 26.1 Product Categories Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
                        SECURITY PRODUCT ECOSYSTEM
└─────────────────────────────────────────────────────────────────────────────┘

ENDPOINT LAYER                    NETWORK LAYER                     CLOUD LAYER
┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
│  AV / EPP       │              │  Firewall       │              │  CSPM           │
│  EDR            │              │  NDR            │              │  CWPP           │
│  XDR (Endpoint) │              │  IDS/IPS        │              │  CIEM           │
└────────┬────────┘              └────────┬────────┘              └────────┬────────┘
         │                                │                                │
         └────────────────────────────────┼────────────────────────────────┘
                                          ▼
                        ┌─────────────────────────────────┐
                        │      SIEM / XDR PLATFORM        │
                        │  (Correlation, Detection,       │
                        │   Enrichment, Case Mgmt)        │
                        └──────────────┬──────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
            ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
            │   SOAR        │  │  THREAT INTEL │  │  TICKETING    │
            │ (Automation)  │  │  PLATFORM     │  │  (Case Mgmt)  │
            └───────────────┘  └───────────────┘  └───────────────┘
```

---

## 26.2 Endpoint Products

### 1. Antivirus (AV) / EPP (Endpoint Protection Platform)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Signature-based malware prevention, basic behavioral blocking |
| **Telemetry Produced** | Detection events (signature match), file quarantine, scan results, definition updates |
| **Key Fields** | `threat_name`, `file_path`, `file_hash`, `action_taken` (clean/quarantine/delete/allow), `engine_version`, `signature_version` |
| **L1 Usage** | - Verify malware detection<br>- Check if quarantine succeeded<br>- Correlate with EDR for context<br>- False positive: submit for signature update |
| **Limitations** | No visibility into process tree, network, memory, behavior beyond signatures |
| **Common Vendors** | Windows Defender, McAfee, Symantec, Trend Micro, Sophos, Kaspersky |

### 2. EDR (Endpoint Detection and Response)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Continuous monitoring, behavioral detection, investigation, response |
| **Telemetry Produced** | Process create/terminate, DLL load, network connections, file create/modify/delete, registry changes, DNS queries, memory access, command lines, parent-child relationships, MITRE tags |
| **Key Fields** | `process_name`, `command_line`, `parent_process`, `user`, `timestamp`, `sha256`, `mitre_technique`, `severity`, `detection_type` (behavioral/ML/signature) |
| **L1 Usage** | - **Primary investigation tool**<br>- Process tree analysis<br>- Command line inspection<br>- Network connection review<br>- File/hash reputation<br>- Host isolation, file blocking, process kill<br>- Timeline reconstruction |
| **Key Capability** | **Process Tree** — Visual parent→child with full context |
| **Common Vendors** | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Cortex XDR, Elastic Defend, Carbon Black, Cybereason |

### 3. XDR (Extended Detection and Response) — Endpoint Component
| Aspect | Details |
|--------|---------|
| **Difference from EDR** | Native integration with network, cloud, identity, email telemetry; cross-layer correlation |
| **Telemetry** | EDR telemetry + normalized network/cloud/identity events in same platform |
| **L1 Usage** | - Single console for endpoint + network + cloud alerts<br>- Cross-layer pivot: "Show me all activity for this user across endpoint, email, cloud"<br>- Unified investigation timeline |
| **Common Vendors** | Palo Alto Cortex XDR, Microsoft Defender XDR, Trend Vision One, Singularity XDR, Stellar Cyber |

---

## 26.3 Network Products

### 4. Firewall (Next-Gen / NGFW)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Network traffic control, application identification, IPS, URL filtering, SSL inspection |
| **Telemetry Produced** | Traffic logs (allow/deny), threat prevention (IPS/AV), URL filtering, application control, SSL/TLS inspection, user-ID mapping |
| **Key Fields** | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `action` (allow/deny/drop/reset), `app_id`, `url_category`, `threat_id`, `bytes`, `packets`, `session_duration`, `user` (if User-ID enabled) |
| **L1 Usage** | - Block malicious IPs/domains (containment)<br>- Verify blockade effectiveness<br>- Identify C2 traffic patterns<br>- Data exfiltration: large outbound transfers<br>- Lateral movement: SMB/RDP between segments<br>- SSL inspection: visibility into encrypted traffic |
| **Common Vendors** | Palo Alto, Fortinet, Check Point, Cisco, Juniper, Sophos |

### 5. NDR (Network Detection and Response)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Network traffic analysis, behavioral detection, encrypted traffic analysis (without decryption) |
| **Telemetry Produced** | Flow records (NetFlow/IPFIX), protocol analysis (HTTP, DNS, SMB, Kerberos, etc.), behavioral anomalies (beaconing, data staging, lateral movement), TLS fingerprinting (JA3), threat intelligence matching |
| **Key Fields** | `src_ip`, `dst_ip`, `protocol`, `app_protocol`, `behavior_tags` (beaconing, exfil, scan), `ja3_hash`, `threat_score`, `packet_capture_ref` |
| **L1 Usage** | - Detect threats firewall misses (encrypted C2, lateral movement)<br>- Beaconing detection (JA3, periodicity)<br>- Protocol anomalies (SMB signing disabled, Kerberos delegation)<br>- Pivot to host via IP correlation<br>- PCAP retrieval for deep analysis |
| **Common Vendors** | ExtraHop, Vectra, Darktrace, Corelight, Zeek/Suricata-based, Cisco Secure Network Analytics |

### 6. IDS / IPS (Intrusion Detection/Prevention System)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Signature-based network threat detection (IDS) / prevention (IPS) |
| **Telemetry Produced** | Alert events: signature ID, severity, src/dst IP, port, payload snippet |
| **Key Fields** | `signature_id`, `signature_name`, `severity`, `src_ip`, `dst_ip`, `protocol`, `payload_preview` |
| **L1 Usage** | - Signature-based alert validation<br>- False positive tuning (known benign triggers)<br>- Correlate with host activity (did exploit succeed?)<br>- Network-level view of exploitation attempts |
| **Difference: IDS vs IPS** | IDS = passive (tap/span), alerts only. IPS = inline, can block. |
| **Common Vendors** | Snort, Suricata, Cisco FirePOWER, Palo Alto Threat Prevention, Snort-based cloud services |

### 7. WAF (Web Application Firewall)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Protect web apps: SQLi, XSS, bot mitigation, API protection, rate limiting |
| **Telemetry Produced** | Blocked requests, attack signatures, bot scores, rate limit triggers, API abuse |
| **Key Fields** | `src_ip`, `url`, `method`, `attack_type` (SQLi, XSS, LFI, etc.), `waf_rule_id`, `action`, `bot_score` |
| **L1 Usage** | - Web attack alert triage<br>- Identify targeted applications<br>- Block malicious IPs at WAF<br>- Correlate with app logs (did attack reach app?) |
| **Common Vendors** | Cloudflare, AWS WAF, Azure WAF, Imperva, F5, Akamai, ModSecurity |

---

## 26.4 Identity & Access Products

### 8. IAM / Identity Providers (IdP)
| Product | Telemetry for SOC |
|---------|-------------------|
| **Microsoft Entra ID (Azure AD)** | Sign-in logs (interactive, non-interactive, service principal), audit logs (role changes, app consent), risky users, risky sign-ins, MFA events, Conditional Access failures |
| **Okta** | System Log: authentication, user lifecycle, group changes, admin actions, policy changes, API tokens |
| **Ping Identity / ForgeRock** | Similar: auth events, admin activity, federation events |
| **Key L1 Fields** | `user`, `ip`, `location`, `mfa_result`, `risk_level`, `app`, `protocol` (SAML/OIDC/WS-Fed), `device_id`, `conditional_access_status` |

### 9. PAM (Privileged Access Management)
| Product | Telemetry for SOC |
|---------|-------------------|
| **CyberArk, BeyondTrust, Delinea, HashiCorp Vault** | Session recordings, checkout/check-in, command keystrokes, secret access, emergency access, approval workflows |
| **Key L1 Fields** | `user`, `target_system`, `account_used`, `commands_executed`, `session_duration`, `approval_status` |

---

## 26.5 Email Security Products

| Product | Telemetry for SOC |
|---------|-------------------|
| **Proofpoint, Mimecast, Microsoft Defender for Office 365, Cisco Email Security, Abnormal Security** | Message tracking (sender, recipient, subject, action), malware/phishing verdicts, URL clicks (URL rewriting), attachment sandbox results, impersonation detection, BEC detection, quarantine events |
| **Key L1 Fields** | `sender`, `recipient`, `subject`, `verdict` (clean/spam/phish/malware), `url_verdict`, `attachment_hash`, `spf/dkim/dmarc`, `action` (delivered/quarantined/blocked/rewritten) |

---

## 26.6 Data Protection Products

### 10. DLP (Data Loss Prevention)
| Aspect | Details |
|--------|---------|
| **Primary Function** | Detect/prevent sensitive data exfiltration (PII, PCI, PHI, IP) |
| **Telemetry Produced** | Policy matches: rule triggered, data type, count, user, endpoint, channel (email, web, USB, print, cloud), action (block/encrypt/notify) |
| **Key Fields** | `policy_name`, `data_classification`, `match_count`, `user`, `endpoint`, `channel`, `destination`, `action`, `file_path` |
| **L1 Usage** | - Validate data exfil alerts<br>- Identify what data, where going, who sent<br>- Correlate with user behavior (departing employee?)<br>- False positive: business justification review |
| **Common Vendors** | Forcepoint, Symantec, Microsoft Purview, Digital Guardian, Nightfall |

---

## 26.7 Vulnerability Management

| Product | Telemetry for SOC |
|---------|-------------------|
| **Qualys, Rapid7, Tenable, CrowdStrike Spotlight, Microsoft Defender Vulnerability Management** | Scan results: host, vulnerability (CVE), severity (CVSS), exploitability, patch status, asset criticality |
| **L1 Usage** | - Prioritize patching for exploited CVEs<br>- Correlate vuln with exploit alerts (CVE-2024-XXXX + exploit attempt)<br>- Asset context for alert triage (is vulnerable host critical?) |

---

## 26.8 Cloud Security Products

| Product | Telemetry for SOC |
|---------|-------------------|
| **CSPM** (Wiz, Orca, Palo Alto Prisma, Microsoft Defender for Cloud) | Misconfigurations: public storage, excessive permissions, unencrypted DB, open security groups |
| **CWPP** (Runtime protection for cloud workloads) | Process exec, network, file integrity in containers/VMs/serverless |
| **CIEM** (Cloud Infrastructure Entitlement Management) | Permission analysis: who can do what, toxic combinations, unused permissions |
| **Cloud Trail / Audit Logs** (AWS CloudTrail, Azure Activity Log, GCP Audit Logs) | API calls: who, what, when, where, response |

---

## 26.9 SIEM / XDR / SOAR — The Integration Layer

| Platform | Role in SOC | Key L1 Interaction |
|----------|-------------|-------------------|
| **SIEM** (Splunk, Sentinel, QRadar, Elastic, LogRhythm, Devo) | Central log collection, correlation, search, alerting, dashboards | **Primary workspace** — queries, investigations, alert triage |
| **XDR** (Cortex XDR, Defender XDR, Singularity XDR) | Unified detection/response across endpoint, network, cloud, identity | Single console for cross-layer investigation |
| **SOAR** (XSOAR, Phantom, Sentinel+Logic Apps, Tines, Swimlane) | Playbook automation, enrichment, containment, case management | Execute playbooks, handle human tasks, monitor automation |

---

## 26.10 Product Integration in MXDR Architecture

### Typical MXDR Data Flow
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  ENDPOINT   │     │  NETWORK    │     │  CLOUD/ID   │
│  (EDR)      │     │  (NDR/FW)   │     │  (IdP/CSPM) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────┐
│           NORMALIZATION / PARSING LAYER                 │
│  (CEF/LEEF/JSON → Common Schema: src_ip, user, host...) │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              SIEM / XDR CORRELATION ENGINE              │
│  • Rule-based detection (Sigma, native)                 │
│  • ML/UEBA anomalies                                    │
│  • Threat intel matching                                │
│  • Alert generation + enrichment                        │
└──────────────────────────┬──────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐     ┌──────────┐     ┌──────────┐
    │  SOAR    │     │ TICKETING│     │  ANALYST │
    │ (Auto)   │     │ (Case)   │     │ (Queue)  │
    └──────────┘     └──────────┘     └──────────┘
```

### Normalized Field Names (Critical for Cross-Product Queries)
| Concept | Firewall | EDR | IdP | Proxy | DNS | CloudTrail |
|---------|----------|-----|-----|-------|-----|------------|
| Source IP | `src_ip` | `local_ip` / `src_ip` | `ip` / `client_ip` | `client_ip` | `client_ip` | `sourceIPAddress` |
| Destination IP | `dst_ip` | `remote_ip` | — | `server_ip` | `resolved_ip` | — |
| User | `user` (User-ID) | `user` / `account` | `user` / `identity` | `user` | — | `userIdentity.arn` |
| Host | — | `hostname` / `device` | `device_id` | — | — | `resources[0].ARN` |
| Timestamp | `time_generated` | `timestamp` / `event_time` | `timestamp` | `time` | `timestamp` | `eventTime` |
| Action | `action` | `action_type` | `result` | `action` | `response_code` | `eventName` |

---

## 26.11 L1 Cheat Sheet: Which Product for Which Question?

| Investigation Question | Primary Product | Secondary Products |
|------------------------|-----------------|-------------------|
| What process ran? | EDR | Sysmon (SIEM) |
| What command line? | EDR | Sysmon (SIEM) |
| What network connections? | EDR, NDR, Firewall | Proxy, DNS |
| Who logged in? | IdP (Entra/Okta), AD (SIEM) | VPN, Firewall (User-ID) |
| Was malware detected? | EDR, AV | Email Security, Proxy, Firewall |
| What files touched? | EDR | Sysmon File Create (SIEM) |
| Registry changes? | EDR | Sysmon Registry (SIEM) |
| Scheduled task created? | EDR | Event ID 4698 (SIEM) |
| Service installed? | EDR | Event ID 7045 (SIEM) |
| DNS queries? | EDR, DNS Logs, NDR | Firewall (DNS proxy) |
| Web requests? | Proxy, WAF, NDR | Firewall (URL filtering) |
| Email received? | Email Security | SIEM (if ingested) |
| Cloud API calls? | CloudTrail / Activity Log | CSPM, CWPP |
| Data exfil? | DLP, NDR, Proxy, Firewall | EDR (file read + network) |
| Lateral movement? | EDR (SMB/RPC), NDR (SMB), AD (4624) | Firewall (internal traffic) |
| Privilege escalation? | EDR (token), AD (4672, 4728), PAM | SIEM correlation |
| Vulnerability context? | Vuln Scanner | EDR (exploit attempt), SIEM |

---

## 26.12 Common L1 Mistakes with Security Products

| Mistake | Correction |
|---------|------------|
| Only checking one product (e.g., only EDR) | Pivot across: EDR → Network → IdP → Email → Cloud |
| Not knowing field name differences | Learn normalized schema; use field mapping table |
| Ignoring firewall/NDR because "EDR has network" | EDR = host view only; NDR/FW = network view (different visibility) |
| Not checking IdP logs for cloud/identity alerts | Identity is the new perimeter; Entra ID/Okta critical |
| Treating all products as same maturity | AV = signature only; EDR = behavioral; NDR = network behavioral |
| Not knowing which product can CONTAIN | EDR isolates host; Firewall blocks IP; Email quarantines; IdP disables user |
| Ignoring product health/ingestion status | "No logs" ≠ "No activity" — check ingestion health first |

---

## 26.13 Summary: What L1 Must Know

- [ ] Product categories: AV/EPP, EDR, XDR, Firewall, NDR, IDS/IPS, WAF, IdP, PAM, Email Security, DLP, Vuln Mgmt, CSPM/CWPP/CIEM
- [ ] Primary telemetry each produces (key fields)
- [ ] How L1 uses each for investigation
- [ ] Which product can perform which containment action
- [ ] Normalized field names across products (src_ip, user, host, timestamp)
- [ ] MXDR data flow: Sources → Normalization → SIEM/XDR → SOAR/Ticketing/Analyst
- [ ] Cross-product pivot questions: "Which product answers X?"
- [ ] Common mistakes: single-product tunnel vision, field name confusion, ignoring ingestion health