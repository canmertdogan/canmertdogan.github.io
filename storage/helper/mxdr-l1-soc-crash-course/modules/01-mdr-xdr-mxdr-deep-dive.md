# Module 1: MDR / XDR / MXDR Deep Dive

**Priority: P0 — Must know before L1 interview**

---

## 1.1 Core Definitions

### SIEM (Security Information and Event Management)
**What it does**: Centralized log collection, normalization, correlation, alerting, reporting, compliance.
**Data sources**: Firewalls, AD, DNS, proxy, servers, applications, network devices.
**Strengths**: Breadth of visibility, compliance reporting, long-term retention, custom correlations.
**Limitations**: High volume, rule maintenance, limited endpoint context, reactive.

**Key vendors**: Splunk, Microsoft Sentinel, Elastic, QRadar, LogRhythm, Sumo Logic, Graylog.

### EDR (Endpoint Detection and Response)
**What it does**: Continuous endpoint monitoring, behavioral detection, investigation, response.
**Telemetry**: Process execution, file/registry changes, network connections, DLL loads, memory access.
**Strengths**: Deep endpoint visibility, behavioral analytics, automated response (isolation, kill process).
**Limitations**: Endpoint-only view, agent deployment required, blind to network/cloud.

**Key vendors**: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Cortex XDR, Elastic Defend.

### NDR (Network Detection and Response)
**What it does**: Network traffic analysis, protocol parsing, behavioral anomaly detection.
**Telemetry**: NetFlow, full packet capture, DNS, HTTP, TLS metadata, SMB, Kerberos.
**Strengths**: Agentless, east-west visibility, encrypted traffic analysis (JA3, SNI), lateral movement detection.
**Limitations**: Encrypted payload blindness, no endpoint context, placement challenges (cloud/remote).

**Key vendors**: ExtraHop, Corelight, Darktrace, Vectra, Zeek/Suricata (open source).

### XDR (Extended Detection and Response)
**What it does**: Unified detection/response across endpoint + network + cloud + identity + email.
**Architecture**: Native integration — single vendor, single console, correlated detections.
**Strengths**: Cross-layer correlation, reduced tool sprawl, unified investigation, automated response.
**Limitations**: Vendor lock-in, may not best-of-breed each layer, maturity varies.

**Key vendors**: Cortex XDR (Palo Alto), Microsoft Defender XDR, CrowdStrike Falcon XDR, SentinelOne Singularity XDR, Trend Vision One.

### MDR (Managed Detection and Response)
**What it does**: Outsourced SOC — provider monitors your environment, triages, responds.
**Service model**: 24/7 monitoring, alert triage, threat hunting, guided response, reporting.
**Strengths**: Immediate 24/7 coverage, expertise access, reduces hiring burden.
**Limitations**: Less control, context gaps (business knowledge), contract-dependent SLAs.

**Key vendors**: Red Canary, Expel, Arctic Wolf, Secureworks, Mandiant, CrowdStrike Falcon Complete.

### MXDR (Managed XDR)
**What it does**: MDR service built on XDR platform — managed service + unified platform.
**Differentiation**: Single platform (XDR) + managed service (MDR) = MXDR.
**Value prop**: Platform consistency + human expertise + 24/7 coverage.

**Key vendors**: Microsoft (Defender XDR + MXDR partners), Palo Alto (Cortex XDR + Unit 42), CrowdStrike (Falcon XDR + Complete), SentinelOne (Singularity XDR + Vigilance).

### SOAR (Security Orchestration, Automation, and Response)
**What it does**: Playbook automation, case management, integration hub, enrichment.
**Capabilities**: Auto-enrichment (TI, CMDB), containment actions, ticket creation, notifications.
**Role**: Force multiplier — handles repetitive tasks, ensures consistency.

**Key vendors**: Palo Alto Cortex XSOAR, Splunk SOAR, Microsoft Sentinel (Logic Apps), FortiSOAR, Tines.

### UEBA (User and Entity Behavior Analytics)
**What it does**: Baseline normal behavior → detect anomalies (impossible travel, unusual access, data staging).
**Data**: Authentication, file access, email, VPN, cloud activity.
**Output**: Risk scores, behavioral alerts.

### TIP (Threat Intelligence Platform)
**What it does**: Aggregate, deduplicate, enrich, operationalize threat feeds.
**Output**: IOCs with context (actor, campaign, malware family, confidence, TLP).

### Security Data Lake
**What it does**: Cheap long-term storage (Parquet/ORC) + query engine for hunting/compliance.
**Role**: Cold storage for SIEM hot tier; fuels data science, ML training, retrospective hunts.

---

## 1.2 Critical Comparisons

### SIEM vs XDR

| Aspect | SIEM | XDR |
|--------|------|-----|
| **Scope** | Broad (all logs) | Focused (security telemetry) |
| **Integration** | Bring-your-own-parser | Native, pre-built |
| **Correlation** | Rule-based (manual) | Built-in cross-layer |
| **Response** | Manual / SOAR | Native automated |
| **Endpoint visibility** | Limited (forwarded logs) | Deep (agent telemetry) |
| **Deployment** | Complex, months | Faster, opinionated |
| **Best for** | Compliance, custom use cases | Security operations efficiency |

**Reality**: Most orgs run both — SIEM for compliance/log retention + XDR for detection/response.

### EDR vs XDR

| Aspect | EDR | XDR |
|--------|-----|-----|
| **Visibility** | Endpoint only | Endpoint + Network + Cloud + Identity + Email |
| **Correlation** | Local endpoint | Cross-domain |
| **Investigation** | Pivot to other tools | Single console |
| **Response** | Endpoint actions | Cross-domain actions |
| **Data schema** | Proprietary | Unified (ideally) |

**Evolution**: EDR → XDR is vendor consolidation play.

### MDR vs MXDR

| Aspect | MDR | MXDR |
|--------|-----|------|
| **Platform** | Any (provider-agnostic) | Provider's XDR platform |
| **Telemetry** | Customer's existing tools | Unified XDR sensors |
| **Onboarding** | Integrate with your stack | Deploy provider's agents |
| **Consistency** | Varies by customer env | Standardized |
| **Data ownership** | Customer logs stay | May reside in provider cloud |

### EDR vs Antivirus (EPP)

| Aspect | Antivirus / EPP | EDR |
|--------|-----------------|-----|
| **Detection** | Signature, heuristic | Behavioral, ML, behavioral |
| **Visibility** | File scan results | Full process tree, memory, network |
| **Response** | Quarantine file | Kill process, isolate host, rollback |
| **Investigation** | None | Timeline, root cause, hunt |
| **Threat types** | Known malware | Fileless, living-off-land, APT |

**Key point**: EPP prevents; EDR detects/responds. Modern "EPP" often includes EDR (called EPP+EDR or NGAV).

### SIEM vs SOAR

| Aspect | SIEM | SOAR |
|--------|------|------|
| **Primary** | Detection, correlation, search | Automation, orchestration, case mgmt |
| **Alert action** | Generate alert | Enrich, decide, act, ticket |
| **Human role** | Analyze | Approve/override automation |
| **Integration** | Log sources | Security tools (EDR, FW, TI, ITSM) |

**Relationship**: SIEM generates alerts → SOAR automates response workflows.

### NDR vs EDR

| Aspect | NDR | EDR |
|--------|-----|-----|
| **Visibility** | Network traffic | Endpoint activity |
| **Deployment** | Span port, TAP, cloud mirror | Agent on host |
| **Encryption** | Metadata only (JA3, SNI) | Sees pre-encryption |
| **Lateral movement** | Excellent (SMB, RPC, Kerberos) | Good (process + auth) |
| **Remote/Cloud** | Hard | Native |

**Complementary**: NDR sees what endpoints miss (unmanaged devices, IoT, east-west).

### SOC vs MDR

| Aspect | Internal SOC | MDR |
|--------|--------------|-----|
| **Control** | Full | Shared |
| **Context** | Deep business knowledge | Limited |
| **Cost** | High (people, tools, facility) | Predictable OPEX |
| **Scaling** | Slow (hiring) | Fast (contract) |
| **Best for** | Mature orgs, regulated | Mid-market, supplement |

### SOC vs MXDR

MXDR = Your internal L1/L2 + Provider's platform + Provider's 24/7 L1/L2.
**Hybrid model**: Internal team owns day shift + critical incidents; provider covers nights/weekends/overflow.

---

## 1.3 Realistic MXDR Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
                              DATA SOURCES
├──────────────────────────────────────────────────────────────────────────────┤
  ENDPOINT          NETWORK           CLOUD              IDENTITY           EMAIL
  ┌─────────┐       ┌─────────┐       ┌─────────┐        ┌─────────┐       ┌─────────┐
  │ Laptops │       │ Firewall│       │ AWS     │        │ AD /    │       │ M365 /  │
  │ Servers │       │ Switches│       │ Azure   │        │ Entra ID│       │ Gmail   │
  │ Mobile  │       │ Zeek    │       │ GCP     │        │ Okta    │       │ Proofpt │
  │ IoT/OT  │       │ Suricata│       │ SaaS    │        │         │       │         │
  └────┬────┘       └────┬────┘       └────┬────┘        └────┬────┘       └────┬────┘
       │                 │                 │                  │                 │
       ▼                 ▼                 ▼                  ▼                 ▼
┌──────────────────────────────────────────────────────────────────────────────┐
                           XDR PLATFORM (Unified Sensor Layer)
  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
  │ EDR Agent   │  │ NDR Sensor  │  │ Cloud Connector│  │ Identity Conn│
  │ (Kernel)    │  │ (PCAP/NetFlow)│ │ (API/Logs)    │  │ (API/Logs)   │
  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
         │                │                │                │
         └────────────────┼────────────────┼────────────────┘
                          ▼
         ┌────────────────────────────────────────────────┐
         │         NORMALIZATION & ENRICHMENT             │
         │  Common Schema (OCSF/ECS) │ TI Enrichment      │
         │  Asset/User Context       │ Behavioral Baselines│
         └────────────────────┬───────────────────────────┘
                              ▼
         ┌────────────────────────────────────────────────┐
         │           DETECTION ENGINE                     │
         │  ┌─────────┐ ┌─────────┐ ┌─────────┐          │
         │  │ Rules   │ │ ML/AI   │ │ Threat  │          │
         │  │ (Sigma) │ │ Models  │ │ Intel   │          │
         │  └─────────┘ └─────────┘ └─────────┘          │
         └────────────────────┬───────────────────────────┘
                              ▼
         ┌────────────────────────────────────────────────┐
         │              ALERT QUEUE                       │
         │  Severity │ Status │ Assignee │ SLA Timer     │
         └────────────────────┬───────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
                           TIERED SOC OPERATIONS
├──────────────────────────────────────────────────────────────────────────────┤
                                                                                
   ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
   │      L1 TIER        │───►│      L2 TIER        │───►│     L3 TIER     │
   │  (Internal/Provider)│    │    (Internal)       │    │  (Internal/IR)  │
   ├─────────────────────┤    ├─────────────────────┤    ├─────────────────┤
   │ • Alert Triage      │    │ • Deep Investigation│    │ • Threat Hunting│
   │ • Enrichment        │    │ • Malware Analysis  │    │ • Detection Eng │
   │ • FP/BP Closure     │    │ • Forensics         │    │ • Red Team Collab│
   │ • Basic Containment │    │ • Hunt Support      │    │ • IR Leadership │
   │ • Escalation Pkg    │    │ • Detection Tuning  │    │ • APT Tracking  │
   │ • Shift Handover    │    │ • Mentor L1         │    │ • Strategic     │
   └─────────────────────┘    └─────────────────────┘    └─────────────────┘
         │                            │                        │
         └────────────────────────────┼────────────────────────┘
                                      ▼
         ┌────────────────────────────────────────────────┐
         │           CASE MANAGEMENT (SOAR/ITSM)          │
         │  ServiceNow │ Jira │ TheHive │ Cortex XSOAR    │
         │  • Ticket lifecycle  • Playbooks  • Metrics   │
         └────────────────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────┐
         ▼                            ▼                        ▼
   ┌─────────────┐            ┌─────────────┐          ┌─────────────┐
   │ CONTAINMENT │            │ ERADICATION │          │  RECOVERY   │
   │ • Isolate   │            │ • Remove    │          │ • Restore   │
   │ • Block     │            │ • Remediate │          │ • Verify    │
   │ • Disable   │            │ • Patch     │          │ • Monitor   │
   └─────────────┘            └─────────────┘          └─────────────┘
```

---

## 1.4 How They Work Together: Data Flow Example

**Scenario**: Phishing email → Credential theft → VPN login → Lateral movement → Data staging

| Stage | Telemetry Source | Detection | Response |
|-------|------------------|-----------|----------|
| **Email** | Email Security (Proofpoint/M365) | Malicious attachment, sender reputation | Quarantine, block sender |
| **Click** | Proxy / DNS / EDR | User visits phishing URL, enters creds | Block URL, alert on cred submit |
| **Auth** | AD / Entra ID / VPN | Successful login from new geo, impossible travel | MFA challenge, alert |
| **Recon** | EDR / NDR | `whoami`, `net view`, `ldapsearch` on compromised host | Alert, enrich |
| **Lateral** | NDR / AD / EDR | SMB admin$, RDP, Pass-the-Hash, Kerberoasting | Isolate host, disable account |
| **Staging** | EDR / NDR | Large archive creation, unusual outbound | Block egress, capture memory |
| **Exfil** | NDR / Proxy / Cloud | Data transfer to rare domain, cloud storage upload | Block, forensic capture |

**Single pane of glass**: All above correlated in XDR → Single incident timeline → One case.

---

## 1.5 What This Means for L1 Analyst

| Platform | What You See | What You Do |
|----------|--------------|-------------|
| **SIEM** | Raw logs, custom dashboards, search | Deep log queries, compliance reports |
| **EDR** | Process trees, file hashes, MITRE tags | Host isolation, process kill, timeline |
| **NDR** | Network flows, beaconing, SMB anomalies | Pivot to host, correlate with EDR |
| **XDR** | Unified timeline, cross-layer alerts | Single investigation view, auto-enrichment |
| **MXDR** | Shared queue with provider | Handover notes, joint escalation, unified SLA |
| **SOAR** | Playbook execution, enrichment results | Approve actions, review auto-ticketed cases |

**Key insight**: In MXDR, you may *not* have raw SIEM access. You work in the XDR console. Know your platform's query language (KQL, XQL, etc.) and investigation workflow.

---

## 1.6 Interview Questions for This Module

1. **What is the difference between SIEM and XDR?**
   - SIEM: broad log collection, compliance, custom rules. XDR: native multi-layer detection/response, unified console.

2. **How does MDR differ from MXDR?**
   - MDR: service on your tools. MXDR: service on provider's XDR platform.

3. **Why would an organization choose MXDR over building internal 24/7 SOC?**
   - Cost, speed to coverage, expertise access, predictable SLA, staffing relief.

4. **Where does SOAR fit in the MXDR architecture?**
   - Automates enrichment, containment, ticketing between XDR alert queue and case management.

5. **What telemetry does NDR provide that EDR cannot?**
   - East-west traffic, unmanaged devices, encrypted traffic metadata (JA3/SNI), lateral movement via network protocols.

6. **Explain the data flow from endpoint to L1 analyst in an MXDR platform.**
   - EDR agent → XDR normalization → Detection engine → Alert queue → L1 triage → Escalation → Case mgmt.

---

## 1.7 Study Checklist for Module 1

- [ ] Define SIEM, EDR, NDR, XDR, MDR, MXDR, SOAR, UEBA, TIP, Data Lake
- [ ] Compare SIEM vs XDR, EDR vs XDR, MDR vs MXDR, EDR vs AV, SIEM vs SOAR, NDR vs EDR
- [ ] Draw MXDR architecture from memory
- [ ] Explain how email → endpoint → network → cloud telemetry correlates in XDR
- [ ] Identify what L1 sees/does in each platform
- [ ] Answer all interview questions without notes

---

*Next: Module 2 — Alert Triage Methodology (THE core L1 skill)*