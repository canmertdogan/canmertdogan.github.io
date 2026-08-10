# Module 24: Incident Response for L1 SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## 24.1 Incident Response Lifecycle (NIST SP 800-61)

```
┌─────────────────────────────────────────────────────────────────────────────┐
                        INCIDENT RESPONSE LIFECYCLE
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │  PREPARATION │────▶│  DETECTION   │────▶│   ANALYSIS   │
    │              │     │  & ALERTING  │     │  & TRIAGE    │
    └──────────────┘     └──────────────┘     └──────┬───────┘
                                                     │
                                                     ▼
    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │  LESSONS     │◀────│  RECOVERY    │◀────│  ERADICATION │
    │  LEARNED     │     │              │     │              │
    └──────────────┘     └──────────────┘     └──────┬───────┘
                                                     │
                                                     ▼
                                              ┌──────────────┐
                                              │ CONTAINMENT  │
                                              │  (Immediate) │
                                              └──────────────┘
```

---

## 24.2 Phase 1: Preparation (Continuous)

### L1 Responsibilities in Preparation
- **Know the playbooks**: Read and understand all L1-relevant playbooks
- **Tool proficiency**: SIEM, EDR, ticketing, SOAR, communication tools
- **Contact lists**: On-call schedules, escalation contacts, vendor support
- **Environment knowledge**: Critical assets, network segments, crown jewels
- **Baseline awareness**: Normal traffic patterns, typical admin activity
- **Documentation**: Keep runbooks, cheat sheets, query library updated

### Preparation Artifacts L1 Should Have Ready
| Artifact | Purpose |
|----------|---------|
| **Runbook/Playbook access** | Step-by-step for common scenarios |
| **Query library** | Saved investigations for account, host, IOC |
| **Critical asset list** | DC, file servers, DB, crown jewel apps |
| **Network diagram** | Segmentation, DMZ, trust boundaries |
| **Escalation matrix** | Who to call for what severity |
| **Communication templates** | Slack/email templates for notification |
| **Evidence preservation checklist** | What to capture before containment |

---

## 24.3 Phase 2: Detection & Alerting

### L1 Role: First Responder
```
ALERT RECEIVED
      │
      ▼
┌─────────────────────────────────────────┐
│  INITIAL ASSESSMENT (2-5 minutes)       │
├─────────────────────────────────────────┤
│  1. Read alert: What triggered?         │
│  2. Identify: Host, User, IP, Process   │
│  3. Check: Severity, Priority, SLA      │
│  4. Determine: Known FP? Known TP?      │
│  5. Decide: Investigate / Escalate /    │
│     Auto-close (with justification)     │
└─────────────────────────────────────────┘
```

### Alert Triage Decision Matrix
| Alert Characteristic | Action |
|---------------------|--------|
| Known FP pattern (documented) | Auto-close with "Known FP" reason |
| High severity + high confidence | Immediate investigation + containment prep |
| High severity + low confidence | Rapid investigation to confirm/deny |
| Low severity + high volume | Aggregate, pattern analysis, rule tuning ticket |
| Unknown severity/confidence | Standard investigation workflow |

---

## 24.4 Phase 3: Analysis & Triage (L1 Core)

### The Investigation Framework
For **EVERY** alert, answer these 20 questions (from Module 2):

1. What triggered the alert?
2. Which asset is involved?
3. Which user is involved?
4. What happened?
5. When did it happen?
6. What process caused it?
7. What parent process spawned it?
8. What command line was executed?
9. What network connections occurred?
10. What files were created/modified?
11. What authentication occurred?
12. What happened BEFORE the alert?
13. What happened AFTER the alert?
14. Is there evidence of persistence?
15. Is there lateral movement?
16. Is there C2 communication?
17. Is there data exfiltration?
18. Is it malicious, benign, or inconclusive?
19. What evidence supports the conclusion?
20. Should it be escalated?

### Evidence Collection Checklist (Before Containment)
```
☐ Alert details (raw alert JSON, screenshot)
☐ Host info: hostname, IP, OS, role, criticality
☐ User info: username, department, privilege level, MFA status
☐ Process tree: full ancestry with command lines
☐ Network connections: inbound/outbound, ports, protocols, duration
☐ File activity: created, modified, deleted, hashes
☐ Authentication: logon type, source, success/failure, MFA
☐ Registry changes: persistence keys, service modifications
☐ Scheduled tasks/services: new or modified
☐ Threat intel: IP/domain/hash reputation
☐ Related alerts: same host, user, IP, technique (last 7 days)
☐ SIEM query results: saved query links/outputs
☐ EDR console screenshots: process tree, timeline, detections
```

---

## 24.5 Phase 4: Containment (Immediate)

### L1 Containment Authority: What You CAN Do
| Action | When Authorized | Approval Required |
|--------|----------------|-------------------|
| Block IP at firewall | Known malicious IP (TI confirmed) | Usually pre-approved via playbook |
| Block domain at proxy/DNS | Known malicious domain | Usually pre-approved via playbook |
| Quarantine email | Known phishing/malware | Pre-approved for high-confidence |
| Block file hash at EDR | Known malware hash | Pre-approved |
| Isolate host (EDR network quarantine) | Active ransomware, confirmed C2, active hands-on-keyboard | **L2/L3 approval required** |
| Disable user account | Confirmed compromise, impossible travel | **L2/L3 approval required** |
| Reset password | Credential theft confirmed | **L2/L3 approval required** |

### Containment Decision Tree
```
CONTAINMENT NEEDED?
      │
      ├─▶ NO (Benign/FP) → Document, Close
      │
      └─▶ YES
            │
            ├─▶ AUTOMATED (Pre-approved playbook)
            │     • Block known bad IP/domain/hash
            │     • Quarantine known phishing email
            │     • Execute via SOAR, document in ticket
            │
            └─▶ MANUAL (Requires approval)
                  │
                  ├─▶ ISOLATE HOST → L2/L3 approval + ticket
                  ├─▶ DISABLE ACCOUNT → L2/L3 approval + ticket  
                  ├─▶ RESET PASSWORD → L2/L3 approval + ticket
                  └─▶ BLOCK LEGITIMATE BUSINESS IP → Change Advisory Board
```

### Containment Evidence Preservation (CRITICAL)
**BEFORE isolating a host or disabling an account:**
```
☐ Capture volatile memory (if forensic capability exists)
☐ Export EDR timeline/process tree (full history)
☐ Collect SIEM query results for all related activity
☐ Screenshot EDR console: detections, process tree, network
☐ Capture network connections: netstat/ss output if accessible
☐ List running processes: ps/tasklist output
☐ Check for encryption/ransomware activity (file extensions, notes)
☐ Document time of containment action and who authorized
```

---

## 24.6 Phase 5: Eradication

### L1 Role in Eradication: SUPPORT ONLY
**L1 does NOT perform eradication independently.**

| Eradication Action | L1 Role | Owner |
|-------------------|---------|-------|
| Malware removal | Provide IOCs, hashes, affected hosts | IR Team / IT Ops |
| Persistence removal | Identify persistence mechanisms (cron, services, run keys) | IR Team / IT Ops |
| Credential rotation | Provide compromised account list | IR Team / Identity Team |
| Vulnerability patching | Identify exploited vuln | IT Ops / Vuln Mgmt |
| System rebuild | Provide scope of compromise | IR Team / IT Ops |

### What L1 Provides for Eradication
- Complete IOC list: IPs, domains, hashes, file paths, registry keys
- Affected asset inventory: hosts, accounts, applications
- Attack timeline: initial access → execution → persistence → lateral → C2
- MITRE ATT&CK technique mapping
- Persistence mechanisms discovered
- Lateral movement paths identified

---

## 24.7 Phase 6: Recovery

### L1 Role in Recovery: MONITOR & VALIDATE
| Recovery Action | L1 Responsibility |
|----------------|-------------------|
| System restoration | Verify restored systems generate expected telemetry |
| Account re-enablement | Monitor for anomalous login after reset |
| Network unblocking | Confirm blocked IPs/domains no longer accessed |
| Enhanced monitoring | Deploy temporary detection rules for re-infection |
| User notification | Coordinate with IT for user communication |

### Recovery Validation Checklist
```
☐ Restored host checks into EDR/SIEM normally
☐ No recurrence of original IOCs/behaviors
☐ Enhanced detection rules firing as expected (test events)
☐ User accounts: MFA enforced, passwords rotated, no suspicious logins
☐ Network blocks: No new connections to previously malicious infrastructure
☐ Vulnerability: Confirmed patched (scan or patch management verification)
☐ Business application: Functional testing passed
```

---

## 24.8 Phase 7: Lessons Learned

### L1 Contribution to Post-Incident Review
- **Timeline accuracy**: Your ticket notes feed the official timeline
- **Detection gaps**: "We didn't see X until Y" → New detection rule
- **Process friction**: "Playbook step 3 failed because..." → Playbook fix
- **Tool limitations**: "Couldn't query Z because..." → Tool enhancement request
- **Knowledge gaps**: "I didn't know how to..." → Training need

### Post-Incident Report Sections L1 Should Complete
| Section | L1 Input |
|---------|----------|
| Detection | Which alert triggered? Time to detect? |
| Analysis | Key findings, evidence collected, queries run |
| Containment | Actions taken, time to contain, approvals |
| Impact | Systems affected, data accessed, business impact |
| Root Cause | Initial access vector, vulnerabilities exploited |
| Recommendations | Detection improvements, playbook updates, training |

---

## 24.9 L1 Incident Response Playbooks (Common Scenarios)

### Playbook: Ransomware Detection
```
TRIGGER: EDR alert "Ransomware behavior detected" OR "Mass file encryption"

IMMEDIATE (0-5 min):
1. Verify alert: Check EDR console for encryption activity, ransom notes
2. Identify host(s): hostname, IP, user, criticality
3. CHECK: Is encryption ACTIVE right now? (EDR real-time view)

IF ACTIVE ENCRYPTION:
4. ISOLATE HOST IMMEDIATELY (pre-approved for ransomware)
   → EDR: Network quarantine (allow management only)
   → Document time, authority
5. Alert L2/L3: "ACTIVE RANSOMWARE - HOST ISOLATED - [hostname]"
6. Create incident ticket: Severity CRITICAL

IF NOT ACTIVE (Historical):
4. Collect evidence: Encrypted file samples, ransom note, process tree
5. Check spread: SIEM query for same process/hash on other hosts
6. Threat intel: Hash reputation, ransomware family identification
7. Escalate to IR: Severity HIGH

EVIDENCE TO COLLECT:
- Ransom note content / file extension
- Encrypting process: name, path, command line, hash
- File count encrypted (EDR estimate)
- Network connections at time of encryption
- Shadow copy deletion events (vssadmin, wmic)
- Persistence mechanisms on host
```

### Playbook: C2 Beaconing
```
TRIGGER: Network alert "Beaconing to suspicious IP" OR "Regular callback detected"

INVESTIGATION (10-15 min):
1. Verify beaconing: Regular interval, long duration, same destination
2. Identify process: Which process making connections?
3. Check process: Legitimate? Signed? Known good?
4. Threat intel: Destination IP/domain reputation
5. Host context: User, role, criticality, recent alerts
6. Scope: Other hosts connecting to same IP?

DECISION:
- Legitimate app (teams, slack, updates) → Document, tune rule, close
- Unknown/suspicious process + bad reputation → CONTAINMENT
- Unknown process + unknown reputation → ESCALATE to L2

CONTAINMENT (if approved):
1. Block destination IP/domain at firewall/proxy
2. Isolate host (if high confidence + critical asset or active C2)
3. Capture process memory/dump (if capability exists)
4. Create incident ticket with IOCs
```

### Playbook: Phishing with Credential Theft
```
TRIGGER: Email security alert "Credential phishing - user clicked" OR
         User reported phishing + successful login from new location

INVESTIGATION:
1. Email analysis: Sender, URLs, attachment, SPF/DKIM/DMARC
2. URL reputation: PhishTank, URLScan, VT
3. User activity: Did they enter credentials? (Proxy logs, MFA logs)
4. Post-click activity: New logins, impossible travel, privilege use
5. Credential reuse: Check if same password used elsewhere (if known)

CONTAINMENT:
1. Reset user password (force MFA re-registration)
2. Block phishing URL/domain at proxy/DNS
3. Quarantine email from all mailboxes
4. Revoke active sessions (O365/Entra ID)
5. Check for mailbox rules/forwarding rules created

ESCALATION:
- If credentials used for VPN/remote access → HIGH
- If admin account compromised → CRITICAL
- If lateral movement detected → CRITICAL
```

---

## 24.10 Severity Classification for L1

### Standard Severity Matrix
| Severity | Definition | Response Time | Escalation | Examples |
|----------|------------|---------------|------------|----------|
| **CRITICAL (P1)** | Active threat to critical assets, data exfil, ransomware encrypting | Immediate (0-15 min) | L2/L3 + Manager + CISO notification | Ransomware active, Domain Controller compromise, Data exfil in progress, APT activity confirmed |
| **HIGH (P2)** | Confirmed compromise, malware execution, credential theft, C2 | <1 hour | L2/L3 + Manager | Malware execution, Successful phishing + credential use, Privilege escalation, Lateral movement detected |
| **MEDIUM (P3)** | Suspicious activity, probable compromise, policy violation | <4 hours | L2 (next shift if quiet) | Suspicious PowerShell, Brute force success, New persistence, Policy violation (unapproved software) |
| **LOW (P4)** | Anomalous but likely benign, low confidence, informational | <24 hours | L1 handles, trend analysis | Failed brute force (blocked), Port scan, Single suspicious login (no follow-on), Known FP pattern |

### Priority vs Severity
- **Severity**: Technical impact (what happened)
- **Priority**: Business urgency (when must we act)
- **They can differ**: Low severity but high priority (CEO laptop), High severity but lower priority (non-critical server, contained)

---

## 24.11 Communication During Incident

### Internal Communication (Slack/Teams)
```
#incident-INC-2024-001234
@channel INCIDENT DECLARED: CRITICAL - Ransomware on WKS-0452 (Marketing)
🔴 Host isolated at 10:23 UTC by Analyst J. Doe (approved by L2 Smith)
📋 Ticket: INC-2024-001234
🎯 IOCs: hash=a1b2c3..., IP=192.0.2.100, domain=evil.ransom
👤 User: j.smith (Marketing, standard privs)
📊 Scope check: Querying for same hash on other hosts...
⏰ Next update: 10:40 UTC
```

### Stakeholder Notification Template
```
Subject: [SEVERITY] Security Incident - [Brief Description] - [Ticket#]

Incident: INC-2024-001234
Severity: HIGH
Status: Contained / Investigating / Recovering
Detected: 2024-01-15 10:23 UTC
Affected: WKS-0452 (Marketing laptop)
User: j.smith
Summary: Suspicious PowerShell download cradle executed from Word doc. 
         Host isolated. Credentials reset. Investigation ongoing.
Impact: Single endpoint. No data exfiltration detected. Business ops unaffected.
Actions: Host isolated, IOCs blocked, password reset, IR engaged.
Next Update: 2024-01-15 14:00 UTC
Contact: SOC Analyst J. Doe (j.doe@company.com, Slack @jdoe)
```

---

## 24.12 When L1 Should NOT Act Independently

| Situation | Why | Correct Action |
|-----------|-----|----------------|
| Domain Controller compromise | Enterprise-wide impact, complex remediation | Immediate L2/L3 escalation |
| Confirmed data exfiltration | Legal/regulatory implications | L2/L3 + Legal + Privacy |
| Ransomware on server/shared storage | Business continuity, complex recovery | L2/L3 + IR Team |
| Privileged account (Domain Admin) compromise | Keys to the kingdom | CRITICAL escalation, emergency response |
| Active hands-on-keyboard adversary | Requires threat hunting, counter-ops | L3 + Threat Hunting |
| Insider threat (HR/Legal) | Legal sensitivity, evidence handling | L2/L3 + Legal + HR |
| Regulatory reportable breach | 72-hour notification (GDPR), etc. | L2/L3 + Legal + Compliance |
| Supply chain / vendor compromise | Third-party coordination | L2/L3 + Vendor Mgmt |

---

## 24.13 L1 Incident Response Checklist (Per Incident)

```
INCIDENT: INC-XXXXXXXX
ANALYST: ________________
DATE: ________________

[ ] 1. ACKNOWLEDGE ALERT
     [ ] Read alert fully
     [ ] Note ticket/alert ID
     [ ] Start timer (SLA)

[ ] 2. INITIAL TRIAGE (2-5 min)
     [ ] Identify: Host, User, IP, Process
     [ ] Check: Known FP? Recent similar?
     [ ] Determine: Severity, Priority
     [ ] Decision: Investigate / Escalate / Close

[ ] 3. INVESTIGATION
     [ ] Answer 20 investigation questions
     [ ] Run query templates (Account/Host/IOC)
     [ ] Collect evidence (screenshots, query exports)
     [ ] Check threat intel for IOCs
     [ ] Map to MITRE ATT&CK

[ ] 4. DETERMINATION
     [ ] TP / FP / Benign / Inconclusive
     [ ] Document evidence for conclusion

[ ] 5. CONTAINMENT (if TP)
     [ ] Verify pre-approved actions
     [ ] Get approval for manual actions
     [ ] Execute containment
     [ ] PRESERVE EVIDENCE FIRST
     [ ] Document: What, When, Who approved

[ ] 6. TICKET DOCUMENTATION
     [ ] Summary, Detection, Timestamp
     [ ] Affected Host/User/IP
     [ ] IOCs, Evidence, Findings
     [ ] MITRE ATT&CK mapping
     [ ] Severity, Recommended Action
     [ ] Escalation path

[ ] 7. NOTIFICATION
     [ ] Slack/Teams incident channel
     [ ] Stakeholder email (if HIGH/CRITICAL)
     [ ] Handoff notes for next shift

[ ] 8. POST-CONTAINMENT
     [ ] Monitor for recurrence
     [ ] Support IR team with IOCs/scope
     [ ] Update detection rules if needed
     [ ] Lessons learned notes
```

---

## 24.14 Summary: What L1 Must Know

- [ ] 7-phase IR lifecycle (NIST) and L1 role in each
- [ ] Initial triage: 2-5 minute assessment framework
- [ ] 20-question investigation framework
- [ ] Evidence collection BEFORE containment
- [ ] Containment authority: what's pre-approved vs needs approval
- [ ] Never isolate host/disable account without L2/L3 approval
- [ ] Eradication/recovery: L1 supports, doesn't lead
- [ ] Severity classification (Critical/High/Medium/Low) with examples
- [ ] Communication templates for internal and stakeholder notification
- [ ] When to immediately escalate (DC, ransomware, admin compromise, data exfil)
- [ ] Complete incident checklist from acknowledgment to handoff