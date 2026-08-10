# SIEM / EDR / XDR / MXDR / SOAR Comparison Cheat Sheet

**Priority: P0 — Must know before L1 interview**

---

## Quick Definitions

| Acronym | Full Name | One-Line Purpose |
|---------|-----------|------------------|
| **SIEM** | Security Information and Event Management | Central log collection, correlation, search, alerting |
| **EDR** | Endpoint Detection and Response | Endpoint monitoring, behavioral detection, investigation, response |
| **XDR** | Extended Detection and Response | EDR + native network/cloud/identity integration, cross-layer correlation |
| **MXDR** | Managed XDR | XDR platform + managed SOC service (vendor provides L1/L2/L3) |
| **SOAR** | Security Orchestration, Automation, Response | Connect tools, automate playbooks, standardize response |
| **NDR** | Network Detection and Response | Network traffic analysis, behavioral detection (encrypted traffic) |
| **MDR** | Managed Detection and Response | EDR management service (less cross-layer than MXDR) |
| **EPP** | Endpoint Protection Platform | AV + basic prevention (signatures, exploit prevention) |

---

## Core Capability Comparison

| Capability | SIEM | EDR | XDR | MXDR | SOAR | NDR |
|------------|------|-----|-----|------|------|-----|
| **Log Collection** | ✅ Primary | ❌ Limited | ✅ Via agents/integrations | ✅ Included | ❌ No | ❌ No |
| **Endpoint Visibility** | Via agents | ✅ Native, deep | ✅ Native | ✅ Included | Via EDR | ❌ No |
| **Network Visibility** | Via logs/NDR | ❌ Limited | ✅ Native/NDR | ✅ Included | Via NDR | ✅ Native |
| **Cloud Visibility** | Via logs | ❌ Limited | ✅ Native | ✅ Included | Via cloud | ❌ No |
| **Identity Visibility** | Via logs | ❌ Limited | ✅ Native | ✅ Included | Via IdP | ❌ No |
| **Behavioral Detection** | Rules/ML | ✅ Strong | ✅ Stronger (cross-layer) | ✅ Included | ❌ No | ✅ Network behavioral |
| **Cross-Layer Correlation** | Manual/queries | ❌ Single-layer | ✅ **Native** | ✅ Included | Via playbooks | ❌ Network only |
| **Investigation Tools** | Query language | Process tree, timeline | Unified timeline | Included | Playbook actions | Flow analysis, PCAP |
| **Response Actions** | Limited | Host isolate, kill, block | Host + network + cloud | Included + managed | **Primary** | Limited |
| **Managed Service** | No | No | No | **Yes (L1-L3)** | No | No |
| **Alert Triage** | You do it | You do it | You do it | **Vendor does it** | Automates it | You do it |

---

## Data Flow Architecture

```
TRADITIONAL SOC (SIEM-Centric):
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  ENDPOINT   │  │  NETWORK    │  │  CLOUD/ID   │  │  EMAIL      │
│  (EDR/AV)   │  │  (FW/NDR)   │  │  (CSPM/IdP) │  │  (Email Sec)│
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │
       └────────────────┼────────────────┼────────────────┘
                        ▼
              ┌─────────────────────┐
              │      SIEM           │
              │ (Collect, Correlate,│
              │  Alert, Search)     │
              └──────────┬──────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        ┌─────────┐           ┌─────────┐
        │  SOAR   │           │ ANALYST │
        │(Automate)│           │(Triage) │
        └─────────┘           └─────────┘


MXDR (Vendor-Managed):
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  ENDPOINT   │  │  NETWORK    │  │  CLOUD/ID   │  │  EMAIL      │
│  (Sensor)   │  │  (Sensor)   │  │  (Sensor)   │  │  (Sensor)   │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │
       └────────────────┼────────────────┼────────────────┘
                        ▼
              ┌─────────────────────┐
              │    XDR PLATFORM     │
              │ (Unified detection, │
              │  investigation,     │
              │  response)          │
              └──────────┬──────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        ┌─────────┐           ┌─────────┐
        │ MXDR TEAM│           │  CLIENT │
        │(L1/L2/L3)│           │  PORTAL │
        └─────────┘           └─────────┘
```

---

## SIEM vs XDR — Key Differences

| Aspect | SIEM | XDR |
|--------|------|-----|
| **Primary Focus** | Log aggregation & correlation | Detection & response across layers |
| **Data Source** | Any log source (syslog, API, agent) | Native sensors + integrated logs |
| **Schema** | You normalize (CEF, LEEF, custom) | Vendor-normalized (common schema) |
| **Detection** | Rules you write/maintain | Vendor + custom rules, cross-layer |
| **Investigation** | Query language (KQL/SPL/SQL) | Unified timeline, pivot across layers |
| **Response** | Manual or via SOAR | Native response actions (host, net, cloud) |
| **Maintenance** | High (parsers, rules, storage) | Lower (vendor handles sensors/parsers) |
| **Cost Model** | Volume-based (EPS/GB/day) | Per-endpoint / per-user / per-node |
| **Best For** | Compliance, long-term retention, custom use cases | Modern SOC, faster MTTR, integrated response |

---

## EDR vs XDR — Key Differences

| Aspect | EDR | XDR |
|--------|-----|-----|
| **Scope** | Endpoint only | Endpoint + Network + Cloud + Identity |
| **Correlation** | Single-host | Cross-host, cross-layer |
| **Network Visibility** | Host-level (process connections) | Full network traffic (NDR) |
| **Cloud Visibility** | Limited (if agent on cloud VM) | Native cloud logs (CloudTrail, Activity Log) |
| **Identity Visibility** | Limited (local auth) | Native IdP integration (Entra ID, Okta) |
| **Detection** | Endpoint behavioral | Cross-layer attack chains |
| **Investigation** | Process tree, host timeline | Unified attack timeline |
| **Response** | Host isolate, kill, block file | Host + network block + cloud remediation |
| **Licensing** | Per endpoint | Per endpoint/user/node (bundled) |

---

## MDR vs MXDR — Key Differences

| Aspect | MDR | MXDR |
|--------|-----|------|
| **Scope** | Primarily EDR management | Full XDR platform management |
| **Layers Covered** | Endpoint (+ some network) | Endpoint, Network, Cloud, Identity, Email |
| **Correlation** | EDR alerts | Cross-layer XDR detections |
| **Response** | Host containment | Host + network + cloud + identity |
| **Team** | Vendor analysts (L1/L2) | Vendor analysts (L1/L2/L3) |
| **Client Involvement** | Escalation only | Escalation + portal visibility |
| **Cost** | Lower | Higher |
| **Maturity** | Established | Emerging |

---

## SOAR — Where It Fits

```
SIEM/XDR ───► ALERT ───► SOAR ───► ACTIONS
   │                    │
   │              ┌────┴────┐
   │              ▼         ▼
   │         ENRICHMENT  CONTAINMENT
   │         (VT, OTX,    (Block IP,
   │          WHOIS,      Isolate Host,
   │          DNS)        Disable User)
   │              │         │
   └──────────────┴─────────┘
                    │
                    ▼
              TICKET CREATION
              (ServiceNow, Jira)
                    │
                    ▼
              NOTIFICATION
              (Slack, Email)
```

### SOAR vs SIEM vs XDR Response

| Capability | SIEM | XDR | SOAR |
|------------|------|-----|------|
| **Native Response** | Limited (scripts) | ✅ Host/Net/Cloud | ❌ Needs integrations |
| **Orchestration** | ❌ | Limited | ✅ **Primary** |
| **Playbooks** | ❌ | Basic | ✅ **Advanced** |
| **Human Tasks** | ❌ | Basic | ✅ **Approval workflows** |
| **Case Management** | Basic | Good | ✅ **Full** |
| **Integrations** | Log sources | Native sensors | **100+ tools** |

---

## Vendor Landscape (2024)

| Category | Major Vendors |
|----------|---------------|
| **SIEM** | Splunk, Microsoft Sentinel, Elastic, IBM QRadar, LogRhythm, Devo, Sumo Logic, Securonix, Panther |
| **EDR** | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Cortex XDR (Palo Alto), Elastic Defend, Carbon Black (VMware), Cybereason, Trend Vision One |
| **XDR** | Cortex XDR, Microsoft Defender XDR, Trend Vision One, Singularity XDR (SentinelOne), Stellar Cyber, Huntress |
| **MXDR** | CrowdStrike Falcon Complete, Microsoft Defender Experts, Palo Alto Cortex XDR + Unit 42, Arctic Wolf, Red Canary, Secureworks, Expel, Critical Insight |
| **SOAR** | Cortex XSOAR, Splunk SOAR (Phantom), Microsoft Sentinel + Logic Apps, Tines, Swimlane, FortiSOAR, Siemplify (Chronicle) |
| **NDR** | ExtraHop, Vectra, Darktrace, Corelight, Zeek/Suricata-based, Cisco Secure Network Analytics |
| **MDR** | Red Canary, Expel, Arctic Wolf, Secureworks, eSentire, Critical Insight, Kudelski |

---

## L1 Workflow by Platform

| Platform | L1 Daily Workflow |
|----------|-------------------|
| **SIEM-Centric** | 1. Open alert queue<br>2. Run investigation queries<br>3. Pivot across log sources manually<br>4. Enrich via external tools<br>5. Document in ticket<br>6. Escalate or close |
| **EDR-Centric** | 1. Open EDR alert queue<br>2. View process tree, timeline<br>3. Check network connections<br>4. Pivot to SIEM for auth/cloud<br>5. Contain via EDR (isolate, block)<br>6. Document in ticket |
| **XDR** | 1. Open unified alert<br>2. View cross-layer timeline (host, net, cloud, ID)<br>3. Single pivot across all layers<br>4. Contain across layers (host + net + cloud)<br>5. Document in unified case |
| **MXDR** | 1. Review vendor-triaged alerts in portal<br>2. Vendor provides: analysis, IOCs, containment<br>3. You: validate, approve containment, coordinate internal<br>4. Less investigation, more coordination |

---

## Cost & Staffing Models

| Model | Licensing Cost | Staffing Need | Best For |
|-------|---------------|---------------|----------|
| **Self-Managed SIEM + EDR** | $$$ (volume + endpoints) | High (L1/L2/L3 + Engineers) | Large orgs, custom needs, compliance |
| **Self-Managed XDR** | $$ (bundled per endpoint) | Medium (L1/L2 + Engineers) | Modern SOC, faster deployment |
| **MXDR** | $$$$ (service + platform) | Low (L1 coordination only) | Mid-market, skills gap, 24/7 without hiring |
| **MDR** | $$$ (service + EDR) | Low (L1 coordination) | EDR-focused, smaller budget than MXDR |

---

## Decision Matrix: What Do You Need?

| If You Need... | Choose |
|----------------|--------|
| Compliance, long-term log retention, custom parsing | **SIEM** |
| Deep endpoint visibility, behavioral detection | **EDR** |
| Cross-layer detection, unified investigation, native response | **XDR** |
| 24/7 SOC without hiring 15 analysts, full stack coverage | **MXDR** |
| EDR management + some hunting, lower budget than MXDR | **MDR** |
| Automate enrichment, containment, ticketing | **SOAR** |
| Network behavioral detection, encrypted traffic analysis | **NDR** |

---

## Common Confusion — Clarified

| Misconception | Reality |
|---------------|---------|
| "XDR replaces SIEM" | XDR replaces *some* SIEM use cases; SIEM still needed for compliance, retention, custom logs |
| "MXDR means no SOC team" | MXDR augments — you still need L1 for coordination, internal context, escalation |
| "SOAR replaces analysts" | SOAR automates *tasks*, not *decisions*; analysts still triage, approve, investigate |
| "EDR = AV" | EDR = behavioral detection + response; AV = signatures only |
| "MXDR = MDR + NDR" | MXDR = managed XDR (all layers); MDR = managed EDR primarily |
| "SIEM does correlation, XDR doesn't" | XDR does *better* correlation (native cross-layer); SIEM = broader log sources |

---

## ONE-PAGE PRINT VERSION

```
SIEM / EDR / XDR / MXDR / SOAR — QUICK REFERENCE
=================================================

DEFINITIONS:
SIEM  = Log aggregation, correlation, search, alerting (YOU triage)
EDR   = Endpoint monitoring, behavioral detection, response (host only)
XDR   = EDR + Network + Cloud + Identity (native cross-layer)
MXDR  = XDR platform + MANAGED SOC service (vendor L1/L2/L3)
SOAR  = Orchestration, Automation, Response (connect tools, playbooks)
NDR   = Network traffic analysis, behavioral (encrypted traffic)
MDR   = Managed EDR service (less cross-layer than MXDR)
EPP   = AV + basic prevention (signatures, exploit prevention)

KEY DIFFERENCES:
SIEM vs XDR:  SIEM = you normalize/write rules; XDR = vendor schema + native cross-layer
EDR vs XDR:   EDR = endpoint only; XDR = endpoint + net + cloud + identity
MDR vs MXDR:  MDR = managed EDR; MXDR = managed XDR (full stack)
SOAR role:    Automates enrichment/containment/ticketing across ALL tools

DATA FLOW (Traditional):
Endpoint/Net/Cloud/Email → SIEM → Analyst (+ SOAR for automation)

DATA FLOW (MXDR):
All Sensors → XDR Platform → MXDR Team (L1/L2/L3) → Client Portal/Coordination

L1 WORKFLOW:
SIEM-Centric:  Query → Pivot → Enrich → Ticket → Escalate
EDR-Centric:   Process Tree → Timeline → Contain → Pivot SIEM → Ticket
XDR:           Unified Timeline → Cross-Layer Pivot → Multi-Layer Contain → Case
MXDR:          Review Vendor Analysis → Approve Contain → Coordinate Internal

VENDORS:
SIEM:     Splunk, Sentinel, Elastic, QRadar, Devo
EDR:      CrowdStrike, Defender, SentinelOne, Cortex, Elastic, Cybereason
XDR:      Cortex XDR, Defender XDR, Vision One, Singularity, Stellar
MXDR:     Falcon Complete, Defender Experts, Cortex+Unit42, Arctic Wolf, Red Canary
SOAR:     XSOAR, Phantom, Sentinel+Logic Apps, Tines, Swimlane
NDR:      ExtraHop, Vectra, Darktrace, Corelight
MDR:      Red Canary, Expel, Arctic Wolf, Secureworks

COST/STAFFING:
Self SIEM+EDR: $$$ + High staff (L1/L2/L3 + Engineers)
Self XDR:      $$  + Med staff (L1/L2 + Engineers)
MXDR:          $$$$ + Low staff (L1 coordination only)

INTERVIEW Qs:
"What's the difference between SIEM and XDR?"
"When would you choose MXDR over self-managed XDR?"
"What does SOAR do that XDR doesn't?"
"How does MXDR change the L1 role?"
```