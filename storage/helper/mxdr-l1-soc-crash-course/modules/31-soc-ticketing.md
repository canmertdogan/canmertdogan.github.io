# Module 31: SOC Ticketing — Writing Professional Incident Cases

**Priority: P0 — Must know before L1 interview**

> A ticket is your work product. It's the legal record, the handoff document, the metrics source, and the evidence for audits. Write every ticket like it will be read by a judge, your CISO, and the next-shift analyst at 3 AM.

---

## 31.1 Why Ticket Quality Matters

| Audience | What They Need |
|----------|----------------|
| **Next-shift analyst** | Complete context to continue without re-investigating |
| **L2/L3 IR team** | All IOCs, evidence, scope, containment status to act immediately |
| **Management** | Business impact, severity, status, decisions needed |
| **Legal/Compliance** | Chain of custody, evidence preservation, notification timeline |
| **Audit** | Complete, accurate, timely documentation |
| **Metrics/SOC Manager** | MTTR, severity accuracy, escalation correctness, closure quality |

---

## 31.2 Standard SOC Ticket Template

```
================================================================================
INCIDENT TICKET: INC-YYYYMMDD-XXXX
================================================================================

BASIC INFORMATION
-----------------
Ticket ID:          INC-20240115-001234
Status:             Open / In Progress / Contained / Resolved / Closed
Created:            2024-01-15 10:23:45 UTC
Updated:            2024-01-15 14:30:00 UTC
Analyst:            J. Doe (SOC-045)
Shift:              Day (06:00-18:00 UTC)
Severity:           Critical / High / Medium / Low / Informational
Priority:           P1 / P2 / P3 / P4
SLA Target:         2024-01-15 11:23:45 UTC (1 hour for High)
SLA Met:            Yes / No / At Risk

DETECTION
---------
Detection Source:   CrowdStrike Falcon / Microsoft Sentinel / User Report / Email Security
Detection Rule:     "PowerShell Encoded Command Execution" (Rule ID: EDR-PS-001)
Alert ID:           CS-ALERT-20240115-045231
Alert Timestamp:    2024-01-15 10:23:45 UTC
Alert Severity:     High

AFFECTED ENTITIES
-----------------
Primary User:       j.smith (Marketing Department, Standard Privileges)
Primary Host:       WKS-0452 (Windows 11, Marketing Laptop, CrowdStrike EDR)
Primary IP:         192.168.1.45 (Internal)
Source IP:          203.0.113.100 (External, Malicious - VT 15/90)
Destination IP:     203.0.113.100 (C2)
Domain:             evil.com (Malicious - Registered 2023-11-02, Russia)
File Hash:          a1b2c3d4e5f67890... (SHA256 of payload.ps1)

IOCS (Structured)
-----------------
- Type: IPv4        Value: 203.0.113.100      Confidence: High   Source: EDR + VT + AbuseIPDB
- Type: Domain      Value: evil.com           Confidence: High   Source: EDR + URLScan
- Type: File Hash   Value: a1b2c3d4... (SHA256) Confidence: High  Source: EDR Process Event
- Type: URL         Value: http://evil.com/payload.ps1  Confidence: High  Source: Decoded PS

EVIDENCE COLLECTED
------------------
[ ] EDR Timeline Export: WKS-0452_20240115_102345.csv (SHA256: abc123...)
[ ] EDR Process Tree Screenshot: WKS-0452_process_tree_1025.png
[ ] EDR Detection Details: WKS-0452_detection_1024.png
[ ] SIEM Query: Auth events for j.smith (4624/4625) - attached CSV
[ ] SIEM Query: Process events on WKS-0452 (4688) - attached CSV
[ ] SIEM Query: Network connections to 203.0.113.100 - attached CSV
[ ] Threat Intel: VirusTotal result for payload.ps1 - attached JSON
[ ] Threat Intel: AbuseIPDB for 203.0.113.100 - attached JSON
[ ] Email Headers: Phishing email to j.smith - attached .eml
[ ] Chain of Custody Log: evidence_log_INC-20240115-001234.txt

INVESTIGATION SUMMARY
---------------------
Timeline:
  09:45 UTC  - Phishing email delivered to j.smith (Invoice_Jan2024.docm)
  10:22 UTC  - j.smith opens document → WINWORD.EXE launches
  10:23 UTC  - WINWORD.EXE spawns powershell.exe with encoded command
  10:23 UTC  - EDR alerts on encoded PowerShell (download cradle)
  10:23 UTC  - PowerShell connects to evil.com (203.0.113.100)
  10:24 UTC  - Payload downloaded: Cobalt Strike beacon (stager)
  10:25 UTC  - Beacon injected into svchost.exe (masquerading)
  10:30 UTC  - Beaconing established (60s interval, HTTPS)
  10:35 UTC  - Host isolated via EDR (L2 approval: S. Johnson)
  10:40 UTC  - IOCs blocked at firewall/proxy
  10:45 UTC  - Credential reset initiated for j.smith

Key Findings:
1. Initial Access: Spearphishing attachment (T1566.001) — macro-enabled .docm
2. Execution: PowerShell encoded command (T1059.001) — download cradle (T1105)
3. Defense Evasion: Masquerading as svchost.exe (T1036.003), AMSI bypass attempt
4. C2: Cobalt Strike HTTPS beacon (T1071.001) to evil.com
5. Persistence: Not yet established (contained early)
6. Credential Access: Not observed (contained before)
6. Lateral Movement: Not observed (isolated)

MITRE ATT&CK MAPPING
--------------------
| Tactic               | Technique ID | Technique Name                    | Observed |
|---------------------|--------------|-----------------------------------|----------|
| Initial Access      | T1566.001    | Spearphishing Attachment          | ✅       |
| Execution           | T1059.001    | PowerShell                        | ✅       |
| Execution           | T1204.002    | Malicious File                    | ✅       |
| Execution           | T1105        | Ingress Tool Transfer             | ✅       |
| Defense Evasion     | T1027.010    | Command Obfuscation (Base64)      | ✅       |
| Defense Evasion     | T1036.003    | Masquerading (svchost)            | ✅       |
| Defense Evasion     | T1562.001    | Disable Security Tools (AMSI)     | ⚠️ Attempted |
| C2                  | T1071.001    | Application Layer Protocol (HTTPS)| ✅       |

CONTAINMENT ACTIONS
-------------------
| Action                    | Time (UTC)     | Approved By   | Status    | Evidence |
|---------------------------|----------------|---------------|-----------|----------|
| EDR Network Quarantine    | 10:35          | L2 S. Johnson | Complete  | EDR Console Screenshot |
| Firewall Block (IP)       | 10:40          | Pre-approved  | Complete  | FW Rule ID: BLK-20240115-001 |
| Proxy Block (Domain)      | 10:40          | Pre-approved  | Complete  | Proxy Policy: BLK-DOM-20240115-002 |
| EDR Block Hash            | 10:41          | Pre-approved  | Complete  | EDR Hash Block: a1b2c3d4... |
| Credential Reset (j.smith)| 10:45          | Identity Team | In Progress | Ticket: IDM-20240115-005 |

SCOPE ASSESSMENT
----------------
- Other hosts with evil.com traffic: NONE (SIEM query 7 days)
- Other hosts with payload hash: NONE (EDR query)
- Other users with same phishing email: 3 recipients (all reported, no clicks)
- Lateral movement indicators: NONE
- Data exfiltration indicators: NONE (beaconing only, <1KB/beacon)

SEVERITY JUSTIFICATION
----------------------
Severity: HIGH
Reasoning:
- Confirmed malware execution (Cobalt Strike) on corporate endpoint
- Active C2 channel established
- Initial access via spearphishing (targeted)
- Standard user (not admin) — limited blast radius
- Contained within 12 minutes of detection
- No lateral movement, no data exfil, no persistence established

RECOMMENDED ACTIONS
-------------------
Immediate (Next 1 Hour):
1. ✅ Complete credential reset for j.smith (force MFA re-enrollment)
2. ✅ Verify firewall/proxy blocks effective (test connection)
3. ✅ Confirm no other hosts beaconing to evil.com (continuous monitoring)
4. 🔄 Full malware scan on WKS-0452 (post-isolation)

Short-term (Next 24 Hours):
1. Re-image WKS-0452 (malware in memory, persistence risk)
2. Review email security: why did phishing deliver? (DMARC gap)
3. Update blocklists: evil.com, 203.0.113.100, payload hash
4. Hunt for Cobalt Strike artifacts across fleet (named pipes, Malleable C2)

Long-term (Next Week):
1. Phishing simulation for Marketing department
2. Review macro security policies (disable by default)
3. Evaluate EDR detection coverage for download cradles
4. Update runbook: "PowerShell Download Cradle Response"

ESCALATION
----------
Escalated To:     L2 IR Team (S. Johnson)
Escalation Time:  2024-01-15 10:30 UTC
Reason:           Confirmed malware execution + active C2
Handoff Notes:    Host isolated, IOCs blocked, creds resetting. 
                  No lateral movement. Ready for IR deep dive 
                  (memory analysis, full scope, attribution).

ANALYST NOTES
-------------
- Phishing email had DMARC fail but was delivered — email security gap
- User reported email at 10:50 (after opening) — good reporting culture
- EDR detection on encoded PS was critical — without it, dwell time would be hours
- Recommend tuning: alert on WINWORD→PS chain regardless of encoding

NEXT UPDATE DUE:  2024-01-15 14:00 UTC
================================================================================
```

---

## 31.3 Field-by-Field Guide

### Required Fields (Never Skip)
| Field | Purpose | Tips |
|-------|---------|------|
| **Ticket ID** | Unique tracker | Format: INC-YYYYMMDD-NNNN |
| **Status** | Workflow state | Open → In Progress → Contained → Resolved → Closed |
| **Severity** | Technical impact | Critical/High/Medium/Low — use matrix (Module 24) |
| **Priority** | Business urgency | P1-P4 — may differ from severity |
| **Detection Source** | Where it came from | Enables detection coverage metrics |
| **Affected Entities** | Who/what/where | User, Host, IPs, Domains — be specific |
| **IOCs** | Actionable indicators | Structured: Type, Value, Confidence, Source |
| **Timeline** | Chronological facts | UTC timestamps, one event per line |
| **Key Findings** | Analytical conclusions | Not raw data — your analysis |
| **MITRE Mapping** | Standardized taxonomy | Tactic + Technique ID + Name |
| **Containment** | Actions taken | What, When, Who approved, Evidence |
| **Severity Justification** | Why this severity | Critical for audits, management |
| **Recommended Actions** | Next steps | Categorized by timeframe |
| **Escalation** | Who/when/why | L2/L3, management, legal |
| **Analyst Notes** | Context, gaps, insights | "Why I decided X", "What I couldn't confirm" |

### Optional but Valuable
| Field | When to Include |
|-------|-----------------|
| **Scope Assessment** | Any multi-host/user incident |
| **Business Impact** | Customer data, revenue systems, execs |
| **Related Tickets** | Previous incidents, same campaign |
| **Threat Actor Attribution** | If known (APT28, FIN7, etc.) |
| **Regulatory Impact** | GDPR, PCI, HIPAA notification needs |

---

## 31.4 Good vs Bad Ticket Examples

### BAD TICKET (What NOT to Do)
```
Ticket: Something weird on WKS-0452
User clicked a bad email. PowerShell ran. I think it's malware.
Blocked the IP. Reset password. 
Severity: High.
```

**Problems**: No ticket ID, no timestamps, no IOCs, no evidence, no MITRE, no containment proof, vague severity justification, no escalation info, no recommended actions.

### GOOD TICKET (Template Above)
See the full template — it has every field, specific timestamps, structured IOCs, evidence list, timeline, MITRE table, containment proof, justified severity, categorized actions.

---

## 31.5 Common Ticket Writing Mistakes

| Mistake | Fix |
|---------|-----|
| Writing "malware" without specifying family/behavior | Say "Cobalt Strike beacon" or "Emotet loader" |
| Listing raw logs as "Evidence" | Say "EDR timeline export showing X, Y, Z" |
| Missing timestamps or using local time | Always UTC, ISO 8601: `2024-01-15T10:23:45Z` |
| No severity justification | Always explain WHY Critical/High/Medium |
| "Investigated and closed" with no findings | Document what you checked and concluded |
| No MITRE mapping | Map every confirmed technique |
| Containment without approval evidence | "Approved by L2 S. Johnson at 10:35 UTC" |
| Subjective language ("looks bad", "seems weird") | Objective: "42/90 VT detections, C2 beaconing observed" |
| Missing IOCs | Every IP, domain, hash, URL from investigation |
| No handoff notes for escalation | L2 needs: what's done, what's left, what's urgent |

---

## 31.6 Ticket Lifecycle States

```
OPEN → IN PROGRESS → CONTAINED → RESOLVED → CLOSED
         ↓              ↓           ↓
      (investigating) (contained) (remediated)
```

| State | Criteria | Analyst Actions |
|-------|----------|-----------------|
| **Open** | Ticket created, triage started | Acknowledge, begin investigation |
| **In Progress** | Active investigation | Update every 30 min, collect evidence |
| **Contained** | Threat stopped from spreading | Document containment, begin eradication support |
| **Resolved** | Root cause addressed, system clean | Verify remediation, update ticket, request close |
| **Closed** | All actions complete, validated | Final review, metrics capture, lessons learned |

**Never skip states**. Don't go Open → Closed.

---

## 31.7 Shift Handoff Format

When your shift ends, add a **HANDOFF** section at top of ticket:

```
================================================================================
SHIFT HANDOFF — 2024-01-15 18:00 UTC
================================================================================
Outgoing Analyst: J. Doe (SOC-045)
Incoming Analyst: [To be assigned]
Ticket Status:    CONTAINED — Host isolated, IOCs blocked, creds resetting

WHAT'S DONE:
✅ Host WKS-0452 isolated via EDR
✅ IOCs blocked at FW/Proxy/EDR
✅ Credential reset initiated for j.smith
✅ Scope checked: no lateral, no other hosts affected

WHAT'S PENDING:
🔄 Credential reset completion (Identity Team — ETA 18:30)
🔄 Full malware scan on isolated host
🔄 Email security gap investigation (DMARC delivery)

CRITICAL NEXT STEPS:
1. Verify credential reset complete — confirm MFA re-enrolled
2. If scan finds persistence → escalate to L2 for re-image decision
3. Monitor for any new beaconing to evil.com or related IOCs

ESCALATION CONTACT: L2 S. Johnson (Slack @sjohnson, on-call until 22:00)
================================================================================
```

---

## 31.8 Metrics Your Tickets Feed

| Metric | Ticket Field Source |
|--------|---------------------|
| **MTTD** (Mean Time to Detect) | Alert Timestamp vs Incident Start |
| **MTTT** (Mean Time to Triage) | Created → In Progress |
| **MTTC** (Mean Time to Contain) | Created → Contained |
| **MTTR** (Mean Time to Resolve) | Created → Resolved |
| **Severity Accuracy** | Initial vs Final severity |
| **Escalation Rate** | % tickets escalated to L2/L3 |
| **FP Rate** | % closed as False Positive |
| **Ticket Quality Score** | Audit: completeness, accuracy, timeliness |

---

## 31.9 Quick Reference: Ticket Checklist

Before submitting/updating ticket:

```
[ ] Ticket ID format correct (INC-YYYYMMDD-NNNN)
[ ] Status matches actual state
[ ] Severity matches matrix (Module 24)
[ ] All entities identified (User, Host, IPs, Domains)
[ ] IOCs table complete (Type, Value, Confidence, Source)
[ ] Evidence listed with hashes/filenames
[ ] Timeline in UTC, chronological, one event per line
[ ] Key findings = analysis, not raw data
[ ] MITRE table: Tactic + Technique ID + Name (at least 3 for TP)
[ ] Containment: What, When, Who approved, Evidence
[ ] Scope assessed (other hosts/users/Ioc hits)
[ ] Severity justification written
[ ] Recommended actions: Immediate / Short-term / Long-term
[ ] Escalation documented (who, when, why, handoff notes)
[ ] Analyst notes: context, gaps, decisions, uncertainties
[ ] Shift handoff added (if shift change)
[ ] No speculative language ("might be", "probably")
[ ] No sensitive data in ticket (PII, passwords) — reference only
```

---

## 31.10 Interview Ticket Exercise

**Practice**: You have 20 minutes. Write a complete ticket for Lab 10 (Module 30).

**Scenario Recap**:
- Alert: EDR "PowerShell download cradle" on WKS-0452
- User: j.smith (Marketing)
- Process: WINWORD → PS (encoded) → download from evil.com
- Network: Connection to 203.0.113.100 (VT 12/90)
- Email: Invoice_Jan2024.docm at 09:45 (SPF/DKIM fail)
- EDR: Cobalt Strike beacon injected into svchost.exe
- Containment: Host isolated 10:35 (L2 approval)
- Scope: No other hosts, no lateral, no exfil

**Grade yourself against the checklist above.**

---

## Summary: What L1 Must Demonstrate

- [ ] Fill every field of the standard ticket template
- [ ] Write in objective, evidence-based language
- [ ] Structure IOCs, timeline, MITRE mapping as tables
- [ ] Document containment with approval chain
- [ ] Justify severity with specific reasoning
- [ ] Categorize recommended actions by timeframe
- [ ] Write clear escalation handoff notes
- [ ] Produce professional shift handoff
- [ ] Self-audit against quality checklist
- [ ] Complete ticket in <20 minutes for typical incident