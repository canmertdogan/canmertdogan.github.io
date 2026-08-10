# Module 17: Threat Intelligence

**Priority: P1 — Context for every alert. L1 uses TI for enrichment, classification, escalation.**

---

## 17.1 Threat Intelligence Fundamentals

### What is Threat Intelligence?
**Evidence-based knowledge** about existing or emerging threats, including context, mechanisms, indicators, implications, and actionable advice. Used to inform decisions.

### Intelligence Cycle (Standard)
```
1. PLANNING & DIRECTION     → Requirements (PIRs: Priority Intelligence Requirements)
2. COLLECTION               → Sources (OSINT, Closed, Technical, Human)
3. PROCESSING               → Normalize, translate, structure (STIX/TAXII)
4. ANALYSIS                 → Connect dots, assess credibility, produce intel
5. DISSEMINATION            → Deliver to consumers (L1, L2, IR, Hunt, Exec)
6. FEEDBACK                 → Evaluate utility, adjust requirements
```

### Intelligence Types (by Consumer)
| Type | Audience | Time Horizon | Example |
|------|----------|--------------|---------|
| **Strategic** | CISO, Exec, Board | Months/Years | Threat landscape, actor motivations, risk trends |
| **Operational** | SOC Manager, IR Lead, Hunt Lead | Days/Weeks | Campaign tracking, TTPs, infrastructure, targeting |
| **Tactical** | **L1/L2 Analysts** | **Hours/Days** | **IOCs (IP, Domain, Hash, URL), Malware configs, Tool signatures** |
| **Technical** | Detection Eng, SIEM, EDR | Real-time | **Atomic IOCs, YARA, Sigma, Snort, STIX patterns** |

**L1 Focus**: **Tactical + Technical** — Enrichment, classification, immediate action.

---

## 17.2 IOC / IOA / TTP — The Hierarchy

| Level | Name | Examples | Lifespan | L1 Action |
|-------|------|----------|----------|-----------|
| **IOC** (Indicator of Compromise) | **Static artifacts** | Hash (MD5/SHA256), IP, Domain, URL, Email, Registry key, Mutex, Filename | **Short** (hours-days, rotate fast) | **Block, Alert, Enrich, Hunt** |
| **IOA** (Indicator of Attack) | **Behavioral patterns** | "PowerShell downloading encoded script", "LSASS memory read", "Scheduled task creating service" | **Medium** (weeks-months, technique stable) | **Detect (Sigma/EDR), Correlate, Map to MITRE** |
| **TTP** (Tactics, Techniques, Procedures) | **Adversary behavior** | T1059.001 (PowerShell), T1003.001 (LSASS dump), T1566.002 (Phishing link) | **Long** (years, fundamental) | **Map alerts, Build detections, Hunt, Strategic planning** |

**Key Insight**: **IOCs expire; IOAs persist; TTPs endure.** L1 triage starts with IOCs, pivots to IOAs, maps to TTPs.

---

## 17.3 IOC Types & Enrichment Fields

| IOC Type | Enrichment Fields | Sources |
|----------|-------------------|---------|
| **IP Address** | Geo, ASN, Org, Hosting Provider, Open Ports, Historical Resolutions, Malicious Activity Tags, Reputation Score, First/Last Seen | AbuseIPDB, AlienVault OTX, VirusTotal, GreyNoise, Shodan, Censys, Internal TIP |
| **Domain** | Registrar, Registration Date, Expiry, Name Servers, MX, TXT, SPF/DMARC, Historical IPs (Passive DNS), Subdomains, SSL Certs, Category, Reputation | WHOIS, PassiveTotal, SecurityTrails, VirusTotal, URLhaus, Cisco Talos, Internal TIP |
| **URL** | Domain enrichment + Path analysis, Redirect chain, Page content, Phishing kit ID, Hosting IP, Cert | URLScan.io, PhishTank, VirusTotal, Hybrid Analysis, Internal Proxy |
| **Hash (File)** | File type, Size, Imports/Exports, Strings, YARA matches, Sandbox verdicts, Family, Compiler, Signer, First Submission, Prevalence | VirusTotal, Hybrid Analysis, MalwareBazaar, Any.Run, Joe Sandbox, Internal Sandbox |
| **Email** | Sender IP/Domain, Headers (SPF/DKIM/DMARC), Attachments (hashes), URLs, Language, Campaign ID | Email Gateway, PhishTank, Internal TIP |
| **Mutex / Registry / Filename** | Malware family association, Persistence location, Prevalence | EDR, Sandbox, Internal TIP |

---

## 17.4 Threat Intelligence Sources

### Open Source (OSINT) — Free
| Platform | Focus | API |
|----------|-------|-----|
| **VirusTotal** | Files, URLs, Domains, IPs, Behavior | Yes (rate limited) |
| **Hybrid Analysis** | Dynamic sandbox reports | Yes |
| **MalwareBazaar** | Malware samples, hashes, tags | Yes |
| **URLhaus** | Malicious URLs, payloads | Yes |
| **AbuseIPDB** | Abusive IPs, reports | Yes |
| **AlienVault OTX** | Pulses (IOCs + context), Actors, Malware | Yes |
| **MISP** | Threat sharing platform (community) | Yes |
| **Cisco Talos** | IP/Domain reputation, Vulnerabilities | Yes |
| **IBM X-Force** | IP/URL/File reputation, Threat research | Yes |
| **GreyNoise** | Internet scanner classification (benign/malicious) | Yes |
| **PassiveTotal / RiskIQ** | Passive DNS, SSL, Host pairs, Infrastructure | Yes (freemium) |
| **SecurityTrails** | Historical DNS, WHOIS, Subdomains, SSL | Yes (freemium) |
| **URLScan.io** | URL screenshot, DOM, Redirects, Certs, IPs | Yes |
| **PhishTank** | Verified phishing URLs | Yes |
| **CERT/CC, CISA, NCSC** | Advisories, Alerts, Vulnerabilities | RSS/Email |

### Commercial / Closed — Higher Fidelity
| Vendor | Strength |
|--------|----------|
| **CrowdStrike Falcon Intelligence** | Actor tracking, Campaigns, Malware families, IOCs |
| **Mandiant (Google Cloud)** | APT expertise, Incident-based intel |
| **Palo Alto AutoFocus / Unit 42** | WildFire sandbox, Campaign tracking |
| **Microsoft Defender Threat Intelligence** | Graph integration, Nation-state tracking |
| **Recorded Future** | Risk scoring, Predictive, Dark web monitoring |
| **Flashpoint / Intel 471** | Underground forums, Ransomware, Fraud |
| **Anomali / ThreatConnect / EclecticIQ** | TIP platforms (aggregate + enrich) |

### Internal Sources
| Source | Value |
|--------|-------|
| **Previous Incidents** | IOCs, TTPs, Actor attribution, Lessons learned |
| **EDR/SIEM Detections** | Behavioral patterns, Anomalous activity |
| **Red Team / Purple Team** | Simulated TTPs, Detection gaps |
| **Vulnerability Scans** | Exploitable assets, Patch status |
| **User Reports** | Phishing emails, Suspicious activity |

---

## 17.5 TIP (Threat Intelligence Platform) — Core Functions

| Function | Description |
|----------|-------------|
| **Aggregation** | Ingest feeds (STIX/TAXII, CSV, JSON, API, Email) |
| **Deduplication** | Merge duplicate IOCs across sources |
| **Enrichment** | Auto-enrich IOCs (Geo, ASN, WHOIS, Passive DNS, Sandbox) |
| **Scoring** | Confidence, Relevance, Severity, TLP, Expiration |
| **Tagging** | Actor, Campaign, Malware Family, MITRE ATT&CK, Sector, Region |
| **Relationships** | Link IOCs → Malware → Actor → Campaign → Victimology |
| **Export / Dissemination** | STIX/TAXII, API, CSV, SIEM/EDR/Firewall push (blocklists) |
| **Hunting** | Pivot from IOC → Related IOCs → Infrastructure → Actor |
| **Reporting** | Strategic/Operational briefs, IOC packages |

---

## 17.6 STIX / TAXII — Standards

### STIX (Structured Threat Information Expression)
**JSON-based** format for representing threat intel objects and relationships.

**Core Objects (STIX 2.1)**:
| Object | Purpose |
|--------|---------|
| **Indicator** | IOC + Pattern (STIX Patterning Language) |
| **Malware** | Malware family, labels, capabilities |
| **Attack-Pattern** | MITRE ATT&CK technique (TTP) |
| **Threat-Actor** | Actor/group, motivation, sophistication |
| **Campaign** | Set of activities over time, objective |
| **Intrusion-Set** | Grouping of campaigns/activity (APT28, FIN7) |
| **Infrastructure** | C2 servers, Domains, IPs, Hosting |
| **Tool** | Software used (Cobalt Strike, Mimikatz) |
| **Vulnerability** | CVE, Exploitability |
| **Observed-Data** | Raw sightings (IP seen at time) |
| **Report** | Intelligence report (PDF/HTML summary) |
| **Relationship** | Links between objects (uses, targets, indicates, attributed-to) |

### TAXII (Trusted Automated Exchange of Indicator Information)
**HTTPS-based** protocol for sharing STIX data.
- **Discovery** → Find collections
- **Collection** → Pull IOCs (polling or streaming)
- **Channel** → Push/Receive real-time

---

## 17.7 TI Enrichment Workflow for L1 (Automated via SOAR)

```
ALERT TRIGGERS
      │
      ▼
┌─────────────────────────────────────────────┐
│  EXTRACT IOCs FROM ALERT                    │
│  - File Hash (SHA256)                       │
│  - Source/Dest IP                           │
│  - Domain/URL                               │
│  - Email Address/Domain                     │
│  - Registry Key / Mutex / Filename          │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  SOAR: PARALLEL ENRICHMENT                  │
│  ├─ VirusTotal (Hash, IP, Domain, URL)      │
│  ├─ AbuseIPDB / GreyNoise (IP)              │
│  ├─ PassiveTotal / SecurityTrails (Domain)  │
│  ├─ URLScan.io / PhishTank (URL)            │
│  ├─ Internal TIP (Actor, Campaign, History) │
│  └─ MITRE ATT&CK Mapping (Technique tags)   │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  CORRELATE & SCORE                          │
│  - Confidence: High/Med/Low (source weight) │
│  - Relevance: Asset, User, Sector match     │
│  - TLP: White/Green/Amber/Red (sharing)     │
│  - Expiration: IOC age, last seen           │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────────────────────────────────────┐
│  OUTPUT TO ANALYST                          │
│  - Enriched IOC Table                       │
│  - Malware Family / Actor / Campaign        │
│  - MITRE ATT&CK Techniques                  │
│  - Related IOCs (Pivot)                     │
│  - Recommended Actions (Block, Hunt, Ignore)│
└─────────────────────────────────────────────┘
```

---

## 17.8 TI Sharing & Classification (TLP)

### Traffic Light Protocol (TLP) — FIRST.org
| Level | Sharing Scope | Use Case |
|-------|---------------|----------|
| **TLP:RED** | **Named recipients only** (personal) | Highly sensitive, active ops, PII |
| **TLP:AMBER** | **Organization + Clients** (need-to-know) | Internal defense, partner sharing |
| **TLP:AMBER+STRICT** | **Organization only** | Sensitive internal |
| **TLP:GREEN** | **Community** (peers, sector) | Sector-wide threat info |
| **TLP:WHITE** | **Public** (no restriction) | Published reports, OSINT |

**L1 Rule**: Never share TLP:RED/AMBER outside authorized channels. Default to TLP:AMBER for internal SOC.

---

## 17.9 Attribution — L1 Perspective

### Attribution Levels (Increasing Confidence)
| Level | Description | L1 Role |
|-------|-------------|---------|
| **None** | No actor link | Report IOCs only |
| **Malware Family** | "Emotet", "Cobalt Strike", "LockBit" | Tag alerts, Map TTPs |
| **Campaign** | "Operation FinancePhish 2024" | Link alerts, Track scope |
| **Intrusion Set / Group** | "FIN7", "APT29", "Lazarus" | Strategic context, Predict TTPs |
| **Nation-State** | "Russia (GRU)", "China (MSS)", "North Korea (Lazarus)" | Executive reporting, Legal/Regulatory |
| **Specific Unit** | "APT29 (Cozy Bear)", "Unit 42" | High-confidence, Rare for L1 |

**L1 Rule**: **Don't over-attribute.** Tag what you know (Malware Family, Campaign). Escalate attribution to Intel Team.

---

## 17.10 Interview Questions for This Module

1. **What is the difference between IOC, IOA, and TTP?**
   - IOC: Static artifact (hash, IP, domain) — short lifespan. IOA: Behavioral pattern (PowerShell download) — medium lifespan. TTP: Adversary tactic/technique (T1059.001) — long lifespan.

2. **What are the four types of threat intelligence and who consumes each?**
   - Strategic (Exec/Board, years), Operational (SOC Manager/IR/Hunt, weeks), Tactical (L1/L2, days), Technical (Detection Eng/SIEM, real-time).

3. **What enrichment fields do you check for a malicious IP address?**
   - Geo, ASN, Org, Hosting Provider, Open Ports, Historical Resolutions, Malicious Tags, Reputation Score, First/Last Seen.

4. **What is the STIX/TAXII standard and what are core STIX objects?**
   - STIX: JSON format for threat intel (Indicator, Malware, Attack-Pattern, Threat-Actor, Campaign, Infrastructure, Tool, Vulnerability, Relationship). TAXII: HTTPS protocol for STIX exchange (Discovery, Collection, Channel).

5. **How does the TLP (Traffic Light Protocol) work and what are the four levels?**
   - RED (named recipients only), AMBER (org+clients), GREEN (community), WHITE (public). Controls sharing sensitivity.

6. **What is the threat intelligence cycle?**
   - Planning → Collection → Processing → Analysis → Dissemination → Feedback.

7. **How do you use threat intelligence during alert triage?**
   - Extract IOCs from alert → Automated enrichment (VT, AbuseIPDB, PassiveTotal, Internal TIP) → Correlate (Actor, Campaign, Malware Family, MITRE) → Score confidence/relevance → Classify alert (TP/FP/BP) → Recommend actions.

8. **What is the difference between a "Malware Family" and an "Intrusion Set"?**
   - Malware Family: Technical grouping (Emotet, Cobalt Strike). Intrusion Set: Actor grouping with intent/capability (FIN7, APT29). One Intrusion Set uses multiple Malware Families.

9. **Name 5 free OSINT threat intel sources and what they provide.**
   - VirusTotal (hash/url/domain/ip reputation), Hybrid Analysis (sandbox), URLhaus (malicious URLs), AbuseIPDB (abusive IPs), AlienVault OTX (pulses/actors).

10. **How does a TIP (Threat Intelligence Platform) help L1 analysts?**
    - Aggregates/deduplicates feeds, auto-enriches IOCs, scores confidence, tags MITRE/actor/campaign, exports blocklists to SIEM/EDR/Firewall, enables pivot hunting.

---

## 17.11 Study Checklist for Module 17

- [ ] Define Threat Intelligence and the 6-step intelligence cycle
- [ ] Distinguish Strategic, Operational, Tactical, Technical intel with consumers/timeframes
- [ ] Compare IOC vs IOA vs TTP (lifespan, examples, L1 action)
- [ ] List enrichment fields for IP, Domain, URL, Hash, Email
- [ ] Categorize 15+ TI sources (OSINT, Commercial, Internal)
- [ ] Explain TIP core functions (aggregation, enrichment, scoring, tagging, export)
- [ ] Describe STIX 2.1 core objects and TAXII protocol
- [ ] Execute TI enrichment workflow (Extract → Parallel Enrich → Correlate → Output)
- [ ] Apply TLP classification (RED/AMBER/GREEN/WHITE)
- [ ] Explain attribution levels and L1 role (don't over-attribute)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 18 — MITRE ATT&CK*