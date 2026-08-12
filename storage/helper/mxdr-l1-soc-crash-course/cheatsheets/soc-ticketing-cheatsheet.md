# SOC Ticketing & SLA Cheat Sheet for SOC Analysts

**Priority: P1 — Your ticket is the legal record, the handoff document, and the source of every metric you are judged on; write every one as if a judge, your CISO, and the next-shift analyst at 3 AM will read it.**

---

## Anatomy of a Good Ticket

A ticket is your legal record and handoff document. **If it is not in the ticket, it did not happen.**

| Field | What It Must Contain | Tip |
|-------|----------------------|-----|
| **Ticket ID** | Unique tracker | Format `INC-YYYYMMDD-NNNN` |
| **Status** | Real workflow state | Open / In Progress / Contained / Resolved / Closed |
| **Severity + Priority** | Technical vs business urgency | May differ — see section below |
| **Detection Source** | Where it came from | Tool, rule ID, alert ID |
| **Affected asset/user** | Who and what is hit | User, host, IPs, domains — be specific |
| **Event timeline** | First/last observed | UTC, one event per line |
| **IOCs collected** | Structured indicators | Type, Value, Confidence, Source |
| **Evidence/artifacts** | Proof, not claims | Filenames, hashes, screenshots |
| **Investigation steps taken** | What you checked | Queries run, scope, conclusions |
| **Current status** | Where it stands now | Honest state, not hopeful state |
| **Next owner** | Who acts next | L2, Identity, IT, next shift |
| **References** | Correlating cases | Related tickets, MITRE IDs |

Key findings are **analysis, not raw data** — "EDR timeline showing powershell.exe spawned from WINWORD.EXE at 10:23 UTC," not "see attached logs."

### Structured IOC Example

| Type | Value | Confidence | Source |
|------|-------|------------|--------|
| IPv4 | 203.0.113.100 | High | EDR + VirusTotal (15/90) + AbuseIPDB |
| Domain | evil.com | High | EDR + URLScan |
| File Hash (SHA256) | a1b2c3d4e5f67890... | High | EDR process event |
| URL | http://evil.com/payload.ps1 | High | Decoded PowerShell |

---

## Severity & Priority Refresher

**Severity** is how bad technically. **Priority** is how fast business must respond. They differ:

- P1-severity ransomware on a **test lab server** → P3 priority (low business impact)
- P2-severity suspicious login on the **CEO's laptop** → P1 priority (high business impact)
- P3-severity malware on a file server with **customer PII** → P1 priority (regulatory impact)

### Quick Severity Assignment

| Level | Definition | Typical Examples |
|-------|------------|------------------|
| **P1 — Critical** | Active breach, data theft/encryption now | Ransomware encrypting, confirmed exfil, DC/Domain Admin compromise, active C2, worm |
| **P2 — High** | Compromise likely, could escalate | Malware + C2, lateral movement, persistence, credential dumping, phish + login |
| **P3 — Medium** | Suspicious, not confirmed | Encoded/download-cradle PowerShell, new binary, suspicious net connection, phish no click |
| **P4 — Low** | Baseline deviation, hygiene | Isolated failed login, port scan, expired cert |

### Priority = Severity x Asset Tier

| Asset Tier | P1 Severity | P2 Severity | P3 Severity | P4 Severity |
|------------|-------------|-------------|-------------|-------------|
| **Tier 0** (DC, PKI, PAM) | **P1** | **P1** | **P2** | P3 |
| **Tier 1** (Critical apps, DB, Email) | **P1** | **P2** | **P3** | P4 |
| **Tier 2** (Standard servers/laptops) | **P2** | **P3** | **P4** | P4 |
| **Tier 3** (Test, dev, IoT, kiosk) | **P3** | **P4** | **P4** | P4 |

When unsure between P2 and P3, classify **P2** — err on the side of caution and escalate as "inconclusive, needs deeper investigation"; L2 can downgrade.

---

## SLA Basics

**SLA (Service Level Agreement)** is the contractual time you have to act. Three rules:

- **Clock starts when the alert hits the queue**, not when you pick it up.
- **Clock pauses only for documented "Waiting on Customer"** — explicit, timestamped, with the ask.
- **A breach auto-escalates** to your Manager and Incident Commander.

### Typical SLA Targets (per severity)

| Metric | P1 Critical | P2 High | P3 Medium | P4 Low |
|--------|-------------|---------|-----------|--------|
| **Acknowledge** | 15 min | 30 min | 2 hrs | 8 hrs |
| **Triage complete** | 30 min | 1 hr | 4 hrs | 24 hrs |
| **Containment** | 1 hr | 4 hrs | 24 hrs | N/A |
| **Root cause** | 4 hrs | 24 hrs | 72 hrs | N/A |
| **Recovery** | 24 hrs | 72 hrs | 1 week | N/A |
| **Status updates** | 30 min | 2 hrs | Daily | Weekly |

### Detection-to-Triage vs Response vs Resolution

| Term | Meaning | How L1 Protects It |
|------|---------|--------------------|
| **MTTD** (Detect) | Alert time vs incident start | Report detection gaps |
| **MTTT** (Triage) | Created → In Progress | Pick up new tickets fast |
| **MTTR** (Resolve) | Created → Resolved | Never park; drive to next owner |
| **Response** | Acknowledge + first action | Acknowledge on time |

**Avoiding breaches**: acknowledge fast, update honestly, pause only with a documented customer dependency, and escalate early if a target is at risk.

---

## Ticket Lifecycle

```
OPEN → IN PROGRESS → CONTAINED → RESOLVED → CLOSED
         ↓              ↓           ↓
     (investigating) (contained) (remediated)
```

| State | What It Means | What L1 Controls |
|-------|---------------|------------------|
| **Open** | Created, triage started | Acknowledge, begin investigation |
| **In Progress** | Active investigation | Update every 30 min, collect evidence |
| **Contained** | Threat stopped spreading | Document containment + approver, support eradication |
| **Resolved** | Root cause addressed, clean | Verify remediation, update, request close |
| **Closed** | All actions complete, validated | Final review, metrics, lessons |

**Never skip states** — never Open → Closed. Every transition is documented, timestamped, and honest.

---

## Working the Queue

| Practice | Why |
|----------|-----|
| **Highest severity first, then oldest** | Critical threats and stale tickets cost the most |
| **Triage new tickets promptly** | MTTT is measured; first triage often decides the SLA |
| **Update status honestly** | Stale "In Progress" breaks metrics and trust |
| **Never abandon a ticket** | Reassign with a note before moving on |
| **Own the handoff** | Every open ticket gets a written next step |
| **Watch watchlist re-trips** | Re-alerting entities mean it is not over |

If you cannot finish, do not park: **hand off with context, not hope.**

---

## Communication Hygiene

Write updates in plain language — no jargon, no raw log dumps.

### Good Update Format

Summary → status → actions → next owner → next update time.

### Interim Update Example

```
UPDATE 14:00 UTC — INC-20240115-001234 [HIGH]
Status: Contained. Host WKS-0452 isolated, IOCs blocked, credential reset in progress.
New: No other hosts reached evil.com in 7 days.
Next owner: L2 S. Johnson. Next update: 16:00 UTC.
```

### Shift Handoff Format (overnight handoff)

```
SHIFT HANDOFF — 2024-01-15 18:00 UTC
Outgoing: J. Doe (SOC-045)   Incoming: [Assigned]
Status: CONTAINED — host isolated, IOCs blocked, creds resetting

DONE: Host isolated (EDR); IP/domain/hash blocked; cred reset initiated; scope checked — no lateral, no other hosts.

PENDING: Cred reset completion (Identity, ETA 18:30); full malware scan; email security gap review.

CRITICAL NEXT: Verify cred reset + MFA. If persistence found, escalate to L2 for re-image. Monitor for re-beaconing.

ESCALATION CONTACT: L2 S. Johnson, on-call until 22:00.
```

---

## Escalation Hygiene

**Escalate early with context — never a raw alert.**

| Severity | Escalate To | Timeline | Method |
|----------|-------------|----------|--------|
| **P1 Critical** | L2/L3 + SOC Manager (+ CISO if Tier 0/PII) | < 15 min | Phone/Slack urgent + ticket |
| **P2 High** | L2/L3 + SOC Manager | < 1 hour | Slack + ticket |
| **P3 Medium** | L2 or next shift lead | < 4 hours | Ticket + Slack |
| **P4 Low** | L1 handles, trend analysis | < 24 hours | Ticket only |

**Escalate immediately (do not wait for full triage)**: active ransomware, DC or Domain Admin compromise, confirmed exfil, worm spreading, critical vuln exploited, MFA bypass on privileged account, active C2 with commands.

**What to bring**: ticket ID, host, user, process tree, command lines, network + intel, hashes, auth timeline, MITRE mapping, containment taken, and a specific ask for L2. For a P1, notify your Manager immediately — they handle exec, legal, and customer comms.

**Containment first**: for P1/P2, contain (or request approved containment), then escalate.---

## Common Ticket-Writing Mistakes

| Mistake | Fix |
|---------|-----|
| Vague title ("alert on server") | "Encoded PowerShell on WKS-0452 — download cradle" |
| Missing timestamps or local time | Always UTC, ISO 8601: `2024-01-15T10:23:45Z` |
| Raw-log dumps as "evidence" | Summarize what the log shows and why it matters |
| No source IP or host | Every finding names its entity |
| Status stuck at Open | Honest state + next owner on every pass |
| No severity justification | Explain WHY Critical/High/Medium |
| Subjective language ("looks bad") | Objective: "42/90 VT, C2 beaconing" |
| Evidence not attached | List filenames/hashes before closing |
| "Investigated and closed" — no findings | Document what you checked |
| No MITRE mapping | Map every confirmed technique: tactic + ID |

---

## Quality Checklist Before Closing

| Check | Verified When |
|-------|---------------|
| **All IOCs documented** | Every IP, domain, hash, URL with confidence + source |
| **Containment done and proven** | What, when, who approved, evidence |
| **Customer notified** | Plain-language update sent and confirmed |
| **Ticket references evidence** | Artifacts named, hashed, linked to ticket |
| **Severity justified** | Why this level, defensible to audit |
| **Next steps defined** | Immediate / short-term / long-term actions |
| **L2/IR handoff written** | What's done, what's pending, what's urgent |
| **No PII or secrets in the ticket** | Reference only — no passwords |
Any unchecked box keeps the ticket open.

---

## Metrics That Measure L1

You are measured on the numbers your tickets generate.
| Metric | What It Measures | Why It Matters to You |
|--------|------------------|------------------------|
| **MTTR** | Mean time to resolve | Faster, complete resolution is core |
| **Triage SLA** | Acknowledge/triage timeliness | Your discipline keeps contracts intact |
| **Escalation quality** | Right tier, right package | Fewer wasted L2 cycles = more trust |
| **False-positive rate** | % closed as FP | You are the detection feedback loop |
| **Ticket quality score** | Completeness, accuracy, timeliness | Directly from audit of your tickets |
| **Severity accuracy** | Initial vs final severity | Right-first-time classification protects the queue |

A clean, complete, on-time ticket is the strongest work product you ship as an L1.

---

## Summary — L1 Must Know

- [ ] Fill every field: ID, status, severity/priority, entities, timeline, IOCs, evidence, next owner
- [ ] Use UTC timestamps and ISO 8601 in every entry
- [ ] Write findings as analysis with evidence, never raw log dumps
- [ ] Justify severity with specific reasoning and the asset tier multiplier
- [ ] Know your SLA targets per severity and that the clock starts at the queue
- [ ] Pause the clock only for documented "Waiting on Customer"
- [ ] Move tickets through lifecycle states honestly — never Open → Closed
- [ ] Triage new tickets promptly; work highest severity, then oldest
- [ ] Hand off open tickets with a written overnight handoff at shift change
- [ ] Escalate early with context and a full package, never a raw alert
- [ ] Complete the before-closing checklist: IOCs, containment proof, customer notified
- [ ] Treat MTTR, triage SLA, escalation quality, and FP rate as signals to improve
