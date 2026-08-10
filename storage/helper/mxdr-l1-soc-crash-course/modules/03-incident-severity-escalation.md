# Module 3: Incident Severity and Escalation

**Priority: P0 — Must know before L1 interview. Drives SLA, response, communication.**

---

## 3.1 Severity vs Priority vs Impact vs Urgency — They Are NOT the Same

| Concept | Question It Answers | Scale | Owner |
|---------|---------------------|-------|-------|
| **Severity** | How bad *technically* is this threat? | P1/P2/P3/P4 (Critical/High/Medium/Low) | L1 Analyst (initial) |
| **Priority** | How fast must *business* respond? | P1/P2/P3/P4 | L1 + Manager (asset context) |
| **Impact** | What is potential damage if real? | Data loss, financial, reputational, operational | L2/L3 (investigation) |
| **Urgency** | How quickly must we act? | Minutes / Hours / Days | L1 (based on activity) |
| **Confidence** | How sure are we this is real? | High / Medium / Low | L1 (evidence-based) |

### Key Insight
> **Severity ≠ Priority**
> - P1-severity ransomware on a test lab server → P3 priority (low business impact)
> - P2-severity suspicious login on CEO's laptop → P1 priority (high business impact)
> - P3-severity malware on file server with customer PII → P1 priority (regulatory impact)

---

## 3.2 Severity Definitions (Industry Standard)

### P1 — Critical (Immediate Threat to Business)
**Active breach in progress. Data theft, encryption, or destruction occurring NOW.**
- Active ransomware encryption
- Confirmed data exfiltration
- Domain Controller compromise
- Privileged account (Domain Admin, Enterprise Admin) confirmed compromised
- Active C2 with confirmed command execution
- Worm spreading laterally
- Critical vulnerability exploited on internet-facing asset

**SLA**: Acknowledge 15 min, Contain 1 hr, Update every 30 min

### P2 — High (Significant Threat, Containment Urgent)
**Compromise likely. Attacker has foothold. Could escalate to P1.**
- Malware execution with C2 callback (confirmed)
- Successful brute force / password spray on privileged account
- Suspicious authentication: impossible travel, MFA bypass, new device on admin
- Lateral movement detected (Pass-the-Hash, SMB admin$, RDP)
- Persistence established (scheduled task, service, Run key, WMI)
- Credential dumping (LSASS access, mimikatz, comsvcs.dll)
- Phishing with credential harvest + successful login
- Vulnerability exploited on internal critical asset

**SLA**: Acknowledge 30 min, Contain 4 hrs, Update every 2 hrs

### P3 — Medium (Suspicious Activity, Investigation Needed)
**Indicators of compromise. Not yet confirmed breach. Could be precursor.**
- Suspicious PowerShell (encoded, download cradle, AMSI bypass)
- Single failed login anomaly (not brute force)
- Unusual process execution (LOLBins, unsigned scripts)
- New binary execution (unknown hash, rare path)
- Network connection to suspicious IP/domain (not confirmed C2)
- Registry modification (persistence locations)
- Scheduled task creation (non-admin, unusual)
- Phishing email delivered (no click/credential entry confirmed)
- Vulnerability scan from internal source

**SLA**: Acknowledge 2 hrs, Investigate 24 hrs, Update daily

### P4 — Low (Informational / Hygiene)
**Baseline deviation. No immediate threat. Track for patterns.**
- Policy violation (unapproved software, USB use)
- Failed login (isolated, low volume)
- Port scan (external, blocked)
- Expired certificate, misconfiguration
- Threat intel hit on historical log (no current activity)
- Compliance finding

**SLA**: Batch review weekly, Trend analysis monthly

---

## 3.3 Priority Matrix: Severity × Asset Criticality

| Asset Tier | P1 Severity | P2 Severity | P3 Severity | P4 Severity |
|------------|-------------|-------------|-------------|-------------|
| **Tier 0** (DC, PKI, PAM, Root CA) | **P1** | **P1** | **P2** | P3 |
| **Tier 1** (Critical Apps, DB, File Servers, VPN, Email) | **P1** | **P2** | **P3** | P4 |
| **Tier 2** (Standard Servers, Workstations, Laptops) | **P2** | **P3** | **P4** | P4 |
| **Tier 3** (Test, Dev, IoT, Kiosk, Non-prod) | **P3** | **P4** | **P4** | P4 |

**Tier Definitions**:
- **Tier 0**: Compromise = full domain compromise. Identity control plane.
- **Tier 1**: Business-critical applications and data. High value target.
- **Tier 2**: Standard employee endpoints and workloads.
- **Tier 3**: Non-production, isolated, or low-value assets.

---

## 3.4 Escalation Criteria: When to Escalate IMMEDIATELY (P1/P2)

### Immediate Escalation Triggers (Do not wait for full investigation)
| Trigger | Why | L1 Action |
|---------|-----|-----------|
| **Active ransomware** | Encryption in progress | Isolate host → Escalate P1 |
| **Domain Controller alert** | Keys to kingdom | Escalate P1 (even if FP later) |
| **Domain Admin / Enterprise Admin compromise** | Full domain control | Disable account → Escalate P1 |
| **Confirmed data exfiltration** | Data leaving now | Block egress → Escalate P1 |
| **Worm / self-spreading malware** | Uncontained spread | Network segment isolate → Escalate P1 |
| **Critical vuln exploited on internet-facing** | Public breach risk | WAF/block → Escalate P1 |
| **MFA bypass on privileged account** | Strong signal of compromise | Disable → Escalate P1 |
| **C2 with active command execution** | Attacker at keyboard | Isolate → Escalate P1 |

### Escalate After Triage Confirms (P2)
| Finding | Escalation Path |
|---------|-----------------|
| Malware + C2 callback confirmed | L2 for memory forensics, scope |
| Lateral movement (any technique) | L2 for lateral path mapping |
| Persistence mechanism found | L2 for full persistence enumeration |
| Credential dumping evidence | L2 for credential scope, reset |
| Phishing + credential use confirmed | L2 for mailbox search, user interview |
| Privilege escalation (local/system) | L2 for scope, cleanup |

### Investigate Further Before Escalating (P3/P4)
| Scenario | Time-box | Escalate If |
|----------|----------|-------------|
| Suspicious PowerShell (no payload) | 30 min | Payload found, C2, persistence |
| Unusual process (no network, no files) | 20 min | Child processes, network, TI hit |
| Single suspicious login | 15 min | Impossible travel, MFA bypass, privileged |
| New binary (unknown hash) | 30 min | Malicious TI, behavior, persistence |
| Suspicious domain connection | 20 min | Beaconing, data transfer, TI confirm |

---

## 3.5 Escalation Procedures

### L1 → L2 Escalation (Standard)
```
1. CLASSIFY as True Positive (P1/P2/P3)
2. BUILD Escalation Package (see Module 2)
3. ASSIGN in case management: Tier=L2, Severity=P#, SLA clock starts
4. NOTIFY: @L2-oncall in Slack/Teams + case link
5. EXECUTE approved containment (if P1/P2): isolate, block, disable
6. DOCUMENT: Time, actions, evidence, handoff notes
7. MONITOR: Watch for new alerts on same entities
```

### L2 → L3 / IR Escalation
```
Triggers:
- Scope exceeds single host / user
- APT / nation-state indicators
- Ransomware on multiple systems
- Data exfiltration confirmed
- Root cause unknown after L2 investigation
- Need for forensic preservation (legal/regulatory)
- Threat hunting required across environment

L2 Actions:
- Declare "Incident" (formal)
- Engage IR lead / CISO notification
- Preserve evidence (memory, disk, logs)
- Activate incident response plan
- Stakeholder communication (legal, PR, exec)
```

### L1 → Management Escalation (Communication)
```
When:
- P1 incident declared
- Customer-facing impact
- Regulatory notification required (GDPR 72hr, etc.)
- Media / public attention risk
- SLA breach imminent

L1 Actions:
- Notify SOC Manager immediately (phone/Slack urgent)
- Provide: What, When, Who, Impact, Actions taken, Next steps
- Manager handles: Executive comms, legal, customer notification
```

---

## 3.6 SLA Definitions (Typical MXDR)

| Metric | P1 Critical | P2 High | P3 Medium | P4 Low |
|--------|-------------|---------|-----------|--------|
| **Acknowledge** | 15 min | 30 min | 2 hrs | 8 hrs |
| **Triage Complete** | 30 min | 1 hr | 4 hrs | 24 hrs |
| **Containment** | 1 hr | 4 hrs | 24 hrs | N/A |
| **Root Cause** | 4 hrs | 24 hrs | 72 hrs | N/A |
| **Recovery** | 24 hrs | 72 hrs | 1 week | N/A |
| **Status Updates** | 30 min | 2 hrs | Daily | Weekly |
| **Closure Report** | 48 hrs | 5 days | 10 days | 30 days |

**SLA Clock Starts**: When alert hits queue (not when analyst picks up).
**SLA Pauses**: Only for "Waiting on Customer" (explicit, documented).
**SLA Breach**: Auto-escalation to Manager + Incident Commander.

---

## 3.7 Severity Determination Workflow (L1 Decision Tree)

```
ALERT TRIAGED AS TRUE POSITIVE
            │
            ▼
    ┌───────────────────┐
    │  ACTIVE THREAT?   │──Yes──► P1 (Critical)
    │ (Ransomware, C2   │
    │  commands, exfil, │
    │  worm, DC compromise)
    └─────────┬─────────┘
              │ No
              ▼
    ┌───────────────────┐
    │  PRIVILEGED       │──Yes──► P1 (Critical)
    │  ACCOUNT          │
    │  COMPROMISED?     │
    │ (DA, EA, Tier 0)  │
    └─────────┬─────────┘
              │ No
              ▼
    ┌───────────────────┐
    │  CONFIRMED        │──Yes──► P2 (High)
    │  COMPROMISE?      │
    │ (Malware+C2,      │
    │  Lateral, Persist,│
    │  Cred dump,       │
    │  Phish+login)     │
    └─────────┬─────────┘
              │ No
              ▼
    ┌───────────────────┐
    │  SUSPICIOUS       │──Yes──► P3 (Medium)
    │  ACTIVITY?        │
    │ (Suspicious PS,   │
    │  unusual proc,    │
    │  new binary,      │
    │  suspicious net)  │
    └─────────┬─────────┘
              │ No
              ▼
         P4 (Low) / Benign Positive
```

### Apply Asset Tier Multiplier
```
Base Severity × Asset Tier = Final Priority
P2 on Tier 0 → P1
P3 on Tier 1 → P2
P1 on Tier 3 → P2 (rare, but possible)
```

---

## 3.8 Example Scenarios with Severity/Priority

| Scenario | Technical Severity | Asset Tier | Business Priority | Final Priority | Escalation |
|----------|-------------------|------------|-------------------|----------------|------------|
| Ransomware on DC | P1 | Tier 0 | P1 | **P1** | Immediate L2+IR |
| Ransomware on test server | P1 | Tier 3 | P3 | **P2** | L2 within 4hr |
| Mimikatz on file server | P2 | Tier 1 | P2 | **P2** | L2 within 4hr |
| Mimikatz on dev laptop | P2 | Tier 3 | P4 | **P3** | L2 within 24hr |
| Suspicious PS on CEO laptop | P3 | Tier 1 | P1 | **P1** | Immediate L2 |
| Suspicious PS on intern laptop | P3 | Tier 2 | P3 | **P3** | L2 within 24hr |
| Failed login x50 on service acct | P3 | Tier 1 | P2 | **P2** | L2 within 4hr |
| Failed login x5 on standard user | P4 | Tier 2 | P4 | **P4** | Batch review |
| C2 beacon on web server (DMZ) | P2 | Tier 1 | P2 | **P2** | L2 within 4hr |
| C2 beacon on IoT sensor | P2 | Tier 3 | P4 | **P3** | L2 within 24hr |

---

## 3.9 Communication During Escalation

### L1 → L2 Handoff Message (Template)
```
🚨 ESCALATION: INC-2024-001234 | P2 | Malware + C2
Host: FILESRV-01 (Tier 1 - Customer DB)
User: svc_app (Service Account)
Time: 2024-01-15 03:12 UTC
Alert: Suspicious Process - Cobalt Strike Beacon (EDR)
Evidence:
- Process: rundll32.exe → powershell.exe (encoded) → dllhost.exe
- Network: Beaconing to 203.0.113.45:443 every 60s (JA3: Cobalt Strike)
- File: C:\Windows\Temp\beacon.dll (VT: 45/72 Cobalt Strike)
- Auth: Service account, no interactive logon, password 2019
Containment: Host isolated (EDR), IP blocked (Firewall)
MITRE: T1059.001, T1055, T1071.001, T1505.003
Questions: Lateral scope? Credential access? Persistence?
```

### L1 → Manager Notification (P1 Only)
```
🔴 P1 INCIDENT: INC-2024-001234 | Active Ransomware
Scope: 3 hosts (FILESRV-01, APP-SRV-02, WKSTN-045)
Impact: Customer DB encrypted, App offline
Actions: All 3 isolated, network segments blocked, DR initiated
Timeline: Detected 03:12, Contained 03:45
Next: IR team engaged, forensic preservation, legal notified
ETA Update: 04:15
```

---

## 3.10 Common Escalation Mistakes

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| Under-escalating (P2→P3) | SLA breach, delayed containment | Err on side of higher severity; L2 can downgrade |
| Over-escalating (P3→P1) | Alert fatigue, resource waste | Use decision tree; justify with evidence |
| Escalating without package | L2 wastes time gathering basics | Always package: host, user, process, net, TI, timeline |
| Not executing containment | Threat spreads during handoff | P1/P2: Contain FIRST, then escalate |
| Forgetting to notify Manager (P1) | Comms gap, legal risk | P1 = immediate Manager notification |
| No SLA tracking | Breaches unnoticed | Case management auto-timers; dashboard |
| Closing without root cause | Recurrence | P1/P2 require RCA; P3 requires "why not TP" |

---

## 3.11 Interview Questions for This Module

1. **Explain the difference between Severity and Priority with an example.**
   - Severity = technical criticality. Priority = business urgency. Example: Ransomware on test server = P1 severity, P3 priority.

2. **What are the four severity levels and their SLAs?**
   - P1: 15min ack, 1hr contain. P2: 30min ack, 4hr contain. P3: 2hr ack, 24hr investigate. P4: 8hr ack, batch.

3. **A Domain Controller generates a "Suspicious PowerShell" alert (normally P3). What priority?**
   - Tier 0 asset → P3 becomes P2 (or P1 if privileged context). Asset tier multiplies severity.

4. **When do you escalate immediately without full triage?**
   - Active ransomware, DC compromise, Domain Admin compromise, confirmed exfil, worm spreading, critical vuln exploited, MFA bypass on privileged, active C2 commands.

5. **What must be in an L1→L2 escalation package?**
   - Alert details, host/user context, process tree, command lines, network + TI, file hashes, auth timeline, MITRE mapping, containment actions taken, recommended next steps.

6. **How do you handle an alert where you're unsure between P2 and P3 after 20 minutes?**
   - Classify as P2 (err on side of caution), escalate with "inconclusive - needs deeper investigation", note time spent and gaps.

7. **What is the asset tier model and why does it matter?**
   - Tier 0 (Identity), Tier 1 (Critical apps/data), Tier 2 (Standard), Tier 3 (Non-prod). Determines priority multiplier and response urgency.

---

## 3.12 Study Checklist for Module 3

- [ ] Define Severity, Priority, Impact, Urgency, Confidence — distinguish each
- [ ] Recite P1/P2/P3/P4 definitions and SLAs
- [ ] Apply Asset Tier multiplier (Tier 0-3) to severity scenarios
- [ ] List 8 immediate escalation triggers
- [ ] Write L1→L2 escalation package from memory
- [ ] Write L1→Manager P1 notification from memory
- [ ] Classify 10 example scenarios with correct severity/priority
- [ ] Identify 7 common escalation mistakes and fixes
- [ ] Answer all 7 interview questions without notes

---

*Next: Module 4 — Windows Security & Event Logs*