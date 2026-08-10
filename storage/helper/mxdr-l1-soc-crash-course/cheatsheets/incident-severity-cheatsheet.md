# Incident Severity Cheat Sheet for SOC Analysts

**Priority: P0 — Must know before L1 interview**

---

## Severity vs Priority — Not the Same

| Concept | Definition | Scale | Who Sets It |
|---------|------------|-------|-------------|
| **Severity** | Technical impact of the threat | Critical / High / Medium / Low / Informational | Analyst (based on evidence) |
| **Priority** | Business urgency of response | P1 / P2 / P3 / P4 | Analyst + Manager (business context) |
| **Impact** | Potential damage if threat succeeds | Critical / High / Medium / Low | Analyst (asset value + data sensitivity) |
| **Urgency** | How fast response must happen | Immediate / Hours / Days / Weeks | Analyst (threat velocity) |
| **Confidence** | Likelihood this is a true positive | High / Medium / Low | Analyst (evidence quality) |

**Key Insight**: A Critical severity alert on a test server may be P3 priority. A Medium severity alert on the CEO's laptop may be P1 priority.

---

## Severity Matrix (Standard 5-Level)

| Severity | Label | Technical Definition | Response Target | Escalation |
|----------|-------|---------------------|-----------------|------------|
| **5** | **CRITICAL** | Active threat to critical assets; confirmed compromise of Tier 0/1; data exfil in progress; ransomware encrypting; Golden Ticket; DC compromise | **Immediate** (0-15 min) | L2/L3 + Manager + CISO notification |
| **4** | **HIGH** | Confirmed malware execution; credential theft; active C2; lateral movement; privilege escalation; successful phishing with follow-on | **< 1 hour** | L2/L3 + Manager |
| **3** | **MEDIUM** | Suspicious activity; probable compromise; policy violation; brute force success; new persistence; suspicious PowerShell (no follow-on) | **< 4 hours** | L2 (next shift if quiet) |
| **2** | **LOW** | Anomalous but likely benign; low confidence; failed attacks; blocked exploits; single suspicious login (no follow-on) | **< 24 hours** | L1 handles; trend analysis |
| **1** | **INFORMATIONAL** | No threat; compliance; scan results; vulnerability notices; hunting results | **No SLA** | Documentation only |

---

## Asset Criticality Tiers (Impact Modifier)

| Tier | Assets | Severity Bump |
|------|--------|---------------|
| **Tier 0** | Domain Controllers, AD FS, PKI, PAM, Identity Providers (Entra ID/Okta), Root CAs | **+2 levels** (Medium → Critical) |
| **Tier 1** | File servers (sensitive data), Database servers, Email servers, VPN/Remote Access, Critical Apps (ERP, CRM), Backup systems | **+1 level** (Low → Medium, Medium → High) |
| **Tier 2** | Standard servers, Application servers, Web servers (internal), Development/Staging | **Base severity** |
| **Tier 3** | Workstations, Laptops, Non-sensitive IoT, Printers, Guest WiFi | **-1 level** (High → Medium, Critical → High) |

**Example**: Suspicious PowerShell on Tier 0 DC = **CRITICAL** (base High +2). Same on Tier 3 laptop = **MEDIUM** (base High -1).

---

## Data Sensitivity Impact

| Data Type | Classification | Severity Bump if Exfiltrated/Encrypted |
|-----------|----------------|----------------------------------------|
| **PII/SPII** (SSN, medical, financial) | Restricted | **+2 levels** |
| **Intellectual Property** (source code, designs, trade secrets) | Restricted | **+2 levels** |
| **Credentials/Keys** (passwords, API keys, certificates, tokens) | Restricted | **+2 levels** |
| **Financial Records** (PCI, SOX, banking) | Confidential | **+1 level** |
| **Internal Communications** (email, Teams, Slack) | Confidential | **+1 level** |
| **Public Data** (marketing, public web) | Public | **No bump** |

---

## Threat Velocity (Urgency Modifier)

| Velocity | Indicators | Urgency | Response Window |
|----------|------------|---------|-----------------|
| **Active/Real-time** | Ransomware encrypting; active hands-on-keyboard; data exfil in progress; worm spreading | **Immediate** | Minutes |
| **Recent/Active C2** | Beaconing now; recent malware execution (< 1 hr); active lateral movement | **Urgent** | < 1 hour |
| **Recent Compromise** | Malware executed hours ago; credentials used; persistence established | **High** | < 4 hours |
| **Dormant/Historical** | Old artifacts; historical logs; no recent activity | **Standard** | < 24 hours |

---

## Decision Tree: Assigning Severity

```
START: Alert Received
    │
    ▼
Is this a KNOWN FALSE POSITIVE pattern?
    │
    ├─ YES → Severity: INFORMATIONAL (close with doc)
    │
    ▼
Is there CONFIRMED MALICIOUS ACTIVITY?
    (Malware execution, C2, credential use, exfil, encryption)
    │
    ├─ YES → Base: HIGH or CRITICAL
    │         │
    │         ▼
    │    Check Asset Tier (Tier 0/1 = bump up)
    │    Check Data Sensitivity (PII/IP = bump up)
    │    Check Threat Velocity (Active = CRITICAL)
    │         │
    │         ▼
    │    FINAL SEVERITY
    │
    ▼
Is there HIGH-CONFIDENCE SUSPICIOUS ACTIVITY?
    (Persistence, privilege escalation, lateral movement indicators)
    │
    ├─ YES → Base: MEDIUM-HIGH
    │         (apply asset/data/velocity modifiers)
    │
    ▼
Is this ANOMALOUS but LOW CONFIDENCE?
    (Single suspicious login, failed exploit, policy violation)
    │
    ├─ YES → Base: LOW-MEDIUM
    │
    ▼
DEFAULT: INFORMATIONAL (document and trend)
```

---

## Specific Scenario Severity Guide

| Scenario | Base Severity | Asset Tier 0/1? | PII/IP Data? | Active Now? | **Final Severity** |
|----------|---------------|-----------------|--------------|-------------|-------------------|
| Ransomware encrypting file server | CRITICAL | Yes (+2) | Yes (+2) | Yes | **CRITICAL** |
| Ransomware on workstation | HIGH | No | No | Yes | **HIGH** |
| Admin credential theft (Domain Admin) | CRITICAL | Yes (+2) | N/A | Yes | **CRITICAL** |
| Standard user credential theft | HIGH | No | Maybe | Check | HIGH / CRITICAL |
| C2 beaconing from workstation | HIGH | No | No | Yes | HIGH |
| C2 beaconing from DC | CRITICAL | Yes (+2) | N/A | Yes | CRITICAL |
| Lateral movement to file server | HIGH | Yes (+1) | Yes (+2) | Check | CRITICAL |
| Phishing click, no creds entered | MEDIUM | No | No | N/A | MEDIUM |
| Phishing click, creds entered, MFA blocked | HIGH | No | No | Check | HIGH |
| Phishing click, creds entered, MFA bypassed | CRITICAL | Check | Check | Yes | CRITICAL |
| Brute force success (standard user) | HIGH | No | No | Check | HIGH |
| Brute force success (admin) | CRITICAL | Check | N/A | Yes | CRITICAL |
| Suspicious PowerShell (no follow-on) | MEDIUM | Check | No | No | MEDIUM |
| Scheduled task persistence (standard user) | MEDIUM | No | No | No | MEDIUM |
| Kerberoasting detected | HIGH | No | No | No | HIGH |
| Golden Ticket detected | CRITICAL | Yes (+2) | N/A | Yes | CRITICAL |
| Data exfil (1GB PII) | CRITICAL | Check | Yes (+2) | Yes | CRITICAL |
| Port scan from internet | LOW | No | No | No | LOW |
| Blocked SQL injection | LOW | No | No | No | INFORMATIONAL |

---

## Severity Communication Templates

### Slack/Teams Alert
```
🚨 [CRITICAL] INC-20240115-001234
Ransomware on FS01 (Tier 1) — Active encryption
Analyst: J. Doe | Contained: 10:35 UTC | IR Engaged
```

### Email to Management
```
Subject: [CRITICAL] Security Incident - Ransomware on File Server - INC-20240115-001234

Severity: CRITICAL
Asset: FS01 (Tier 1 - Customer PII Database)
Status: Contained at 10:35 UTC
Impact: 500GB encrypted, VSS deleted, backup restoration in progress
Actions: Host isolated, IR engaged, Legal notified (PII)
Next Update: 14:00 UTC
```

---

## SLA Targets by Severity

| Severity | MTTD (Detect) | MTTT (Triage) | MTTC (Contain) | MTTR (Resolve) |
|----------|---------------|---------------|----------------|----------------|
| **CRITICAL** | < 5 min | < 15 min | < 1 hour | < 24 hours |
| **HIGH** | < 15 min | < 30 min | < 4 hours | < 72 hours |
| **MEDIUM** | < 1 hour | < 2 hours | < 8 hours | < 7 days |
| **LOW** | < 4 hours | < 8 hours | < 24 hours | < 30 days |
| **INFORMATIONAL** | N/A | N/A | N/A | N/A |

---

## Common Severity Mistakes

| Mistake | Why Wrong | Correct Approach |
|---------|-----------|------------------|
| Everything is HIGH/CRITICAL | Alert fatigue, desensitization | Use matrix; reserve CRITICAL for true emergencies |
| Severity = Priority | Ignores business context | Severity = technical; Priority = business urgency |
| No asset context | Workstation = DC in severity | Always check asset tier |
| No data sensitivity | PII exfil = same as public data | Classify data, bump severity |
| Static severity | Doesn't update with new info | Re-assess as investigation progresses |
| No confidence factor | Low confidence = HIGH | Low confidence = MEDIUM max until confirmed |
| Ignoring velocity | Dormant artifact = active threat | Check timestamp, recent activity |

---

## ONE-PAGE PRINT VERSION

```
INCIDENT SEVERITY — SOC L1 QUICK REFERENCE
===========================================

SEVERITY ≠ PRIORITY
Severity = Technical Impact          Priority = Business Urgency
Impact = Potential Damage            Urgency = Response Speed

5-LEVEL SEVERITY:
5 CRITICAL  = Active threat to Tier 0/1, exfil, ransomware, Golden Ticket, DC compromise
             → Immediate (0-15 min) → L2/L3 + CISO
4 HIGH      = Confirmed malware, C2, cred theft, lateral, priv esc, phishing w/ follow-on
             → <1 hour → L2/L3 + Manager
3 MEDIUM    = Suspicious, probable compromise, policy violation, brute force success
             → <4 hours → L2 (next shift)
2 LOW       = Anomalous, likely benign, blocked attacks, single suspicious login
             → <24 hours → L1 handles
1 INFO      = No threat, compliance, scans, hunting results
             → No SLA → Document only

ASSET TIER MODIFIERS:
Tier 0 (DC, PKI, PAM, IdP)        = +2 levels
Tier 1 (DB, File server, Email)   = +1 level
Tier 2 (Standard servers)         = Base
Tier 3 (Workstations, IoT)        = -1 level

DATA SENSITIVITY MODIFIERS:
PII/IP/Credentials/Keys           = +2 levels
Financial/Internal Comms          = +1 level
Public                            = No bump

THREAT VELOCITY:
Active now (encrypting, exfil)    = Immediate / CRITICAL
Recent C2 / execution (<1hr)      = Urgent / HIGH
Recent compromise (hours)         = High / HIGH-MEDIUM
Dormant / Historical              = Standard

DECISION TREE:
1. Known FP? → INFO
2. Confirmed malicious? → HIGH/CRITICAL + modifiers
3. High-confidence suspicious? → MEDIUM/HIGH + modifiers
4. Anomalous low-confidence? → LOW/MEDIUM
5. Default → INFO

COMMON SCENARIOS:
Ransomware on FS          = CRITICAL (Tier 1 + PII + Active)
Ransomware on Laptop      = HIGH
Domain Admin Compromise   = CRITICAL (Tier 0)
User Credential Theft     = HIGH (→ CRITICAL if MFA bypassed)
C2 from Workstation       = HIGH
C2 from DC                = CRITICAL
Lateral to File Server    = CRITICAL (Tier 1 + PII)
Phishing Click (no creds) = MEDIUM
Phishing + MFA Bypass     = CRITICAL
Brute Force Success       = HIGH (→ CRITICAL if Admin)
Kerberoasting             = HIGH
Golden Ticket             = CRITICAL
Data Exfil (PII)          = CRITICAL
Port Scan / Blocked SQLi  = LOW / INFO

SLA TARGETS:
CRITICAL: Detect 5m | Triage 15m | Contain 1h | Resolve 24h
HIGH:     Detect 15m | Triage 30m | Contain 4h | Resolve 72h
MEDIUM:   Detect 1h  | Triage 2h  | Contain 8h | Resolve 7d
LOW:      Detect 4h  | Triage 8h  | Contain 24h | Resolve 30d

MISTAKES TO AVOID:
❌ Everything HIGH/CRITICAL     ✅ Use matrix
❌ Severity = Priority          ✅ Separate technical vs business
❌ Ignore asset tier            ✅ Check CMDB every time
❌ Ignore data sensitivity      ✅ Classify data
❌ Static severity              ✅ Re-assess with new evidence
❌ Ignore confidence            ✅ Low confidence = MEDIUM max
```