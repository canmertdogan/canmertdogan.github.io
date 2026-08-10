# SOC Escalation Cheat Sheet for L1 Analysts

**Priority: P0 — Must know before L1 interview**

---

## Escalation Principles

| Principle | Description |
|-----------|-------------|
| **Escalate Early** | Better to escalate and be wrong than miss a critical incident |
| **Escalate with Context** | Never escalate a raw alert — always include investigation findings |
| **Know Your Authority** | L1 has pre-approved containment; L2/L3 for high-impact actions |
| **Document Everything** | Escalation note = handoff document for next tier |
| **Follow the Matrix** | Use severity + asset + data sensitivity to determine path |

---

## Escalation Matrix by Severity

| Severity | Escalate To | Timeline | Method | Required Info |
|----------|-------------|----------|--------|---------------|
| **CRITICAL** | L2/L3 + SOC Manager + CISO (if Tier 0/PII) | **Immediate** (within 15 min) | Phone/Slack urgent + ticket + email | Full ticket, containment status, impact assessment |
| **HIGH** | L2/L3 + SOC Manager | **< 1 hour** | Slack + ticket | Full ticket, containment actions taken |
| **MEDIUM** | L2 (or next shift lead) | **< 4 hours** | Ticket assignment + Slack | Ticket with investigation summary |
| **LOW** | L1 handles / Trend analysis | **< 24 hours** | Ticket only | Ticket with disposition |
| **INFO** | No escalation | N/A | Ticket only | Closed with documentation |

---

## L1 Containment Authority (Pre-Approved)

| Action | When Authorized | Approval Required | Evidence to Capture |
|--------|-----------------|-------------------|---------------------|
| **Block IP at Firewall/Proxy** | Known malicious IP (TI High confidence); DDoS source | Pre-approved via playbook | FW rule ID, timestamp, analyst |
| **Block Domain at Proxy/DNS** | Known malicious domain (TI High); Phishing delivery | Pre-approved via playbook | Proxy policy ID, timestamp |
| **Quarantine Email** | Known phishing/malware (High confidence); Business impact if FP | Pre-approved for High confidence | Message trace ID, count quarantined |
| **Block File Hash at EDR** | Known malware hash (VT >10/90); Ransomware | Pre-approved | EDR hash block ID, timestamp |
| **Delete/Block Scheduled Task** | Malicious persistence (4698/4702 confirmed) | Pre-approved | Task name, XML, timestamp |

---

## L1 Containment — REQUIRES L2/L3 APPROVAL

| Action | When Required | Approval From | Escalation Path |
|--------|---------------|---------------|-----------------|
| **Isolate Host (EDR Network Quarantine)** | Active ransomware; Confirmed C2; Hands-on-keyboard; Lateral movement | **L2/L3** | Slack urgent → Ticket → L2 approval → Execute |
| **Disable User Account** | Confirmed credential compromise; Impossible travel + MFA bypass; Privileged account abuse | **L2/L3 + Identity Team** | Slack urgent → Ticket → L2 + Identity approval |
| **Reset User Password / Force MFA Re-enroll** | Credential theft confirmed; Phishing + successful login; MFA fatigue | **L2/L3 + Identity Team** | Slack → Ticket → L2 + Identity approval |
| **Block Legitimate Business IP/Domain** | False positive risk high; Business-critical service | **Change Advisory Board (CAB)** | Ticket → Manager → CAB (next business day) |
| **Revoke Cloud Sessions / Rotate Keys** | Cloud credential compromise (AWS/Azure/GCP) | **L2/L3 + Cloud Team** | Slack → Ticket → L2 + Cloud approval |
| **Modify Firewall Rules (Allow)** | Emergency access for IR/forensics | **L2/L3 + Network Team** | Slack urgent → Ticket → L2 + Network approval |

---

## NEVER — L1 Does Not Do These

| Action | Why | Correct Path |
|--------|-----|--------------|
| **Reboot Compromised Host** | Destroys volatile evidence (memory, encryption keys) | Isolate only; Forensics acquires memory first |
| **Run AV/EDR Scan on Compromised Host** | May destroy artifacts, tip off attacker | Isolate → Forensics image → Scan offline |
| **Delete Suspicious Files** | Spoliation; Chain of custody broken | Preserve; Document location; Forensics collects |
| **Modify GPO / AD Structure** | Enterprise-wide impact; Requires change control | L2/L3 + Identity + CAB |
| **Patch Production Systems** | Change management; May break apps | Vuln Mgmt + Change Control |
| **Notify Legal / PR / Law Enforcement** | Legal privilege; Regulatory requirements | L2/L3 + Legal + Management |
| **Public Statements** | Reputation; Legal liability | Management + Legal + PR |
| **Root Cause Remediation** | Requires full investigation | IR Team + System Owners |
| **Pay Ransom** | Legal/ethical; No guarantee | Management + Legal + Law Enforcement |

---

## Escalation Paths by Scenario

| Scenario | First Escalation | Second Escalation | Final Authority |
|----------|------------------|-------------------|-----------------|
| **Ransomware (Active)** | L2 IR (Immediate) | SOC Manager + CISO | IR Lead / CISO |
| **Domain Controller Compromise** | L3 IR (Immediate) | SOC Manager + CISO + Identity | CISO / External IR |
| **Privileged Account Compromise** | L2 IR + Identity Team | SOC Manager | CISO |
| **Data Exfiltration (PII/IP)** | L2 IR + Legal | SOC Manager + CISO + Legal | CISO / Legal / DPO |
| **Active C2 / Hands-on-Keyboard** | L2 IR | SOC Manager | IR Lead |
| **Lateral Movement to Tier 0/1** | L2 IR | L3 IR + Identity | CISO |
| **Golden Ticket / Kerberos Attack** | L3 IR (Immediate) | SOC Manager + CISO | CISO / External IR |
| **Cloud Credential Compromise** | L2 IR + Cloud Team | SOC Manager | Cloud Sec Lead |
| **Insider Threat** | L2 IR + Legal + HR | SOC Manager + Legal | Legal / CISO |
| **Supply Chain / Vendor Compromise** | L2 IR + Vendor Mgmt | SOC Manager + Legal | CISO / Legal |
| **Regulatory Reportable Breach** | Legal (Immediate) | SOC Manager + CISO | Legal / DPO |

---

## Escalation Communication Templates

### Slack Urgent Escalation
```
@channel 🚨 ESCALATION: CRITICAL - [Incident Type]
Ticket: INC-YYYYMMDD-NNNN
Analyst: [Name]
Severity: CRITICAL
Status: [Contained / Investigating / Active]

Summary: [One sentence: what, where, impact]
Containment: [Done / Pending approval / Not needed]
Impact: [Systems, data, users affected]
Urgency: [Why now — active threat, velocity, velocity]

Need from L2/L3: [Specific ask: approval, action, resources]
```

### Ticket Escalation Note
```
ESCALATION NOTE — 2024-01-15 10:35 UTC
Escalated By: J. Doe (SOC-045)
Escalated To: L2 IR (S. Johnson)
Reason: CRITICAL — Ransomware on Tier 1 file server (FS01)
Containment: Host WKS-0452 isolated at 10:30. FS01 network access restricted.
Impact: 500GB encrypted on FS01\CustomerData (PII). VSS deleted.
Active: Encryption stopped. No spread detected.
Legal: Notified (PII). Backup restoration initiated.
Request: L2 to lead IR. Coordinate with IT for FS01 restoration. 
         Assess full scope. Determine notification requirements.
```

### Email to Management (CRITICAL)
```
Subject: [CRITICAL] Security Incident - [Type] - [Ticket ID]

Incident: INC-20240115-001234
Severity: CRITICAL
Status: Contained / Investigating
Detected: 2024-01-15 10:23 UTC
Contained: 2024-01-15 10:35 UTC

Affected: FS01 (File Server - Tier 1, Customer PII)
User: j.smith (Marketing - initial vector)
Vector: Spearphishing attachment (Invoice_Jan2024.docm)

Summary: Ransomware (LockBit) executed via phishing. 
         500GB encrypted on FS01. VSS deleted. 
         Host isolated. Backup restoration in progress.

Impact: Customer PII potentially exposed. 
        Business operations: File share unavailable.
        Regulatory: GDPR 72hr notification likely required.

Actions Taken: Host isolated, IOCs blocked, creds reset, 
               Legal notified, IR engaged, backup restore started.

Next Update: 2024-01-15 14:00 UTC
Contact: SOC Analyst J. Doe (j.doe@company.com, Slack @jdoe)
```

---

## Shift Handoff for Escalated Incidents

```
================================================================================
SHIFT HANDOFF — ESCALATED INCIDENTS
================================================================================
Date: 2024-01-15 18:00 UTC
Outgoing: J. Doe (SOC-045)
Incoming: [Assigned Analyst]

ESCALATED INCIDENTS:
─────────────────────
1. INC-20240115-001234 [CRITICAL] — Ransomware on FS01
   Status: CONTAINED — Host isolated, FS01 restricted, IR engaged
   Owner: L2 S. Johnson (on-call until 22:00)
   Pending: Backup restoration, scope verification, legal notification
   Next Action: Verify restoration progress at 20:00

2. INC-20240115-001235 [HIGH] — Admin credential compromise
   Status: IN PROGRESS — Creds reset, MFA re-enrolled, sessions revoked
   Owner: L2 M. Chen (on-call)
   Pending: Audit admin activity last 7 days, check for persistence
   Next Action: Review audit logs at 19:00

WATCHLIST (Not Yet Escalated):
─────────────────────
• INC-20240115-001236 [MEDIUM] — Suspicious PS on WKS-0211 (j.doe)
  Monitoring for follow-on. Escalate if C2/persistence detected.

• INC-20240115-001237 [LOW] — Password spray from 91.219.236.245
  No success. IP blocked. Monitor for delayed success (72h).

CONTACTS:
─────────────────────
L2 On-Call: S. Johnson (Slack @sjohnson, Phone: +1-555-0101)
L3 On-Call: M. Chen (Slack @mchen, Phone: +1-555-0102)
SOC Manager: A. Brown (Slack @abrown)
Legal On-Call: Legal PagerDuty
Identity Team: identity-oncall@company.com
================================================================================
```

---

## Post-Escalation L1 Responsibilities

| Responsibility | Description |
|----------------|-------------|
| **Monitor** | Watch for related alerts, same IOCs, same host/user/IP |
| **Support** | Provide additional queries, evidence, context to IR team |
| **Communicate** | Update ticket with new findings, stakeholder notifications |
| **Coordinate** | Facilitate access (host, logs, people) for IR team |
| **Document** | Continue ticket updates; handoff at shift change |
| **Learn** | Participate in post-incident review; note detection gaps |

---

## Common Escalation Mistakes

| Mistake | Consequence | Correct Approach |
|---------|-------------|------------------|
| Escalating without investigation | Wastes L2/L3 time; "boy who cried wolf" | Always triage first; include findings |
| Escalating raw alert | No context; L2 must re-investigate | Include: timeline, IOCs, evidence, MITRE |
| Not documenting containment | No proof action taken; audit finding | Screenshot + timestamp + approver |
| Escalating to wrong tier | Delay in response | Use matrix: Critical→L2/L3, High→L2, Medium→L2 |
| No urgency in communication | Delay in action | CRITICAL = phone/Slack urgent; High = Slack + ticket |
| Forgetting shift handoff | Next analyst unaware | Always handoff escalated incidents |
| Not updating ticket after escalation | Stale info; confusion | Update ticket in real-time |

---

## ONE-PAGE PRINT VERSION

```
SOC ESCALATION — L1 QUICK REFERENCE
====================================

ESCALATION PRINCIPLES:
✅ Escalate EARLY with CONTEXT
✅ Know YOUR authority (pre-approved vs needs approval)
✅ DOCUMENT everything (ticket = legal record)
✅ Use MATRIX (severity + asset + data = path)

L1 PRE-APPROVED CONTAINMENT (Playbook):
• Block IP (TI High confidence)
• Block Domain (TI High)
• Quarantine Email (High confidence phishing)
• Block Hash (Known malware)
• Delete Malicious Scheduled Task

REQUIRES L2/L3 APPROVAL:
🔴 Isolate Host (EDR quarantine)          → L2/L3
🔴 Disable User Account                   → L2/L3 + Identity
🔴 Reset Password / Force MFA             → L2/L3 + Identity
🔴 Block Legit Business IP/Domain         → CAB
🔴 Revoke Cloud Sessions / Rotate Keys    → L2/L3 + Cloud
🔴 Modify FW Allow Rules                  → L2/L3 + Network

NEVER (L1 Does NOT):
❌ Reboot compromised host
❌ Run AV scan on compromised host
❌ Delete suspicious files
❌ Modify GPO/AD
❌ Patch production
❌ Notify Legal/PR/Law Enforcement
❌ Public statements
❌ Root cause remediation
❌ Pay ransom

ESCALATION MATRIX:
CRITICAL → L2/L3 + Manager + CISO (Immediate, phone/Slack urgent)
HIGH     → L2/L3 + Manager (<1hr, Slack + ticket)
MEDIUM   → L2 / Next Shift Lead (<4hr, ticket + Slack)
LOW      → L1 handles (<24hr, ticket only)
INFO     → No escalation

SCENARIO PATHS:
Ransomware Active        → L2 IR → Manager → CISO
DC Compromise            → L3 IR → Manager → CISO → External IR
Privileged Account Comp  → L2 IR + Identity → Manager → CISO
Data Exfil (PII/IP)      → L2 IR + Legal → Manager → CISO + Legal
Golden Ticket            → L3 IR → Manager → CISO → External IR
Insider Threat           → L2 IR + Legal + HR → Manager → Legal
Regulatory Breach        → Legal → Manager → CISO → DPO

COMMUNICATION:
Slack Urgent: @channel 🚨 ESCALATION: CRITICAL - [Type]
              Ticket: INC-...
              Summary: [One sentence]
              Containment: [Done/Pending]
              Need: [Specific ask]

TICKET NOTE: Time, Analyst, To, Reason, Containment, Impact, Request

SHIFT HANDOFF: Status, Owner, Pending, Next Action, Contacts

MISTAKES:
❌ Escalate raw alert          ✅ Triage first + findings
❌ No containment proof        ✅ Screenshot + timestamp + approver
❌ Wrong tier                  ✅ Use matrix
❌ No urgency                  ✅ CRITICAL = phone/Slack urgent
❌ No handoff                  ✅ Always handoff escalated
```