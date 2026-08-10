# Module 32: Advanced But Optional Topics

**Priority: P3 — Optional / Specialized (Beyond normal L1 requirements)**

> **Clearly labeled as beyond normal L1 requirements.** Study these only after mastering all P0/P1 modules. These are for career growth, not interview passing.

---

## 32.1 APT (Advanced Persistent Threat)

### What L1 Should Know
- **Definition**: Sophisticated, well-resourced adversaries (nation-state) conducting long-term campaigns
- **Characteristics**: Custom malware, zero-days, living-off-the-land, anti-forensics, strategic objectives
- **L1 Role**: Detect IOCs from threat intel feeds, escalate anomalies, don't try to attribute
- **Common APT Groups**: APT28/29 (Russia), APT41 (China), Lazarus (NK), FIN7 (crime)

### What L1 Should NOT Do
- ❌ Attribute attacks to specific APT groups
- ❌ Hunt for unknown APT TTPs
- ❌ Analyze custom malware

---

## 32.2 Threat Hunting

### What It Is
Proactive, hypothesis-driven search for threats that evaded automated detection.

### Hunt Types
| Type | Description | L1 Involvement |
|------|-------------|----------------|
| **Intel-led** | Hunt for specific IOCs/TTPs from threat reports | Run provided queries, triage hits |
| **Hypothesis-led** | "I think attacker did X, let me search for evidence" | Execute hunt queries designed by L3 |
| **Anomaly-led** | Statistical outliers (ML/UEBA) | Investigate high-risk anomalies |

### L1 Role in Hunting
- Execute hunt queries provided by threat hunters/L3
- Triage results using standard investigation framework
- Escalate confirmed findings
- Document negative results ("hunted for X, found nothing in 30 days")

### Hunt Frameworks
- **PEAK**: Prepare, Execute, Act, Knowledge
- **Sqrrl/OWASP**: Hypothesis → Data → Analytics → Enrichment → Response

---

## 32.3 Detection Engineering

### What It Is
Creating, testing, and maintaining detection rules (SIEM, EDR, NDR).

### Detection Lifecycle
```
Idea → Rule Development → Unit Test → Integration Test → Deploy → Monitor → Tune → Retire
```

### Rule Formats L1 Should Recognize
| Format | Used By | Example |
|--------|---------|---------|
| **Sigma** | Vendor-agnostic, YAML | `title: Suspicious PowerShell` |
| **KQL** | Sentinel, Defender | `DeviceProcessEvents | where ...` |
| **SPL** | Splunk | `index=edr sourcetype=process ...` |
| **YARA** | File/memory patterns | `rule emodet { strings: $a="Emotet" }` |
| **Snort/Suricata** | Network IDS | `alert tcp any any -> any 443 (msg:"C2";)` |

### L1 Role
- Test rules in staging (provide feedback on FP/TP)
- Suggest rule ideas from investigation gaps
- Document detection blind spots
- **NOT**: Write production rules (Detection Engineer role)

---

## 32.4 Sigma Rules

### What Is Sigma?
Generic, open-source detection rule format (YAML). Write once, convert to any SIEM/EDR.

### Basic Structure
```yaml
title: Suspicious PowerShell Download Cradle
id: d1a2b3c4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell download cradles via IEX + WebClient
author: SOC Team
date: 2024/01/15
references:
  - https://attack.mitre.org/techniques/T1059.001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
  condition: selection
falsepositives:
  - Legitimate admin scripts using download patterns
level: high
```

### L1 Interaction
- Recognize Sigma rules in detection library
- Test converted rules in your SIEM
- Provide FP feedback to detection engineers

---

## 32.5 YARA Rules

### What Is YARA?
Pattern-matching language for identifying and classifying malware files.

### Basic Structure
```yara
rule Emotet_Loader
{
    meta:
        description = "Detects Emotet loader variants"
        author = "Threat Intel Team"
        date = "2024-01-15"
        mitre = "T1059.003"
    strings:
        $mutex = "Global\\EmotetMutex" ascii wide
        $c2_pattern = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:443/ ascii
        $import1 = "CreateMutexA" ascii
        $import2 = "InternetOpenA" ascii
    condition:
        $mutex and (2 of ($import*)) or $c2_pattern
}
```

### L1 Interaction
- Submit suspicious files for YARA scanning
- Understand YARA hits in sandbox reports
- Know that YARA = file/memory, Sigma = logs/behavior

---

## 32.6 Suricata / Snort

### What Are They?
Network Intrusion Detection/Prevention Systems (NIDS/NIPS). Rule-based network traffic analysis.

### Rule Example (Snort/Suricata syntax)
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"ET TROJAN Cobalt Strike Beacon Malleable C2";
    flow:established,to_server;
    tls.fingerprint:ja3_fingerprint_match;
    threshold:type both, track by_src, count 5, seconds 300;
    classtype:trojan-activity;
    sid:2024001; rev:1;
)
```

### L1 Interaction
- Understand NIDS alerts in SIEM
- Know that Suricata = modern, multi-threaded, Eve JSON output
- Recognize common rule sets: Emerging Threats (ET), Snort Community, custom

---

## 32.7 KQL Advanced

### Beyond Basics (P2/P3)
```kql
// Time series with anomaly detection
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| make-series Failures=count() default=0 on TimeGenerated step 1h by Account
| extend Anomaly=series_decompose_anomalies(Failures, 1.5, -1, 'linefit')

// Machine learning clustering
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| summarize CommandLines=make_set(ProcessCommandLine) by DeviceName
| evaluate bag_unpack(CommandLines)

// Join with threat intel reference set
let TiFeed = _GetThreatIntelFeed();
DeviceNetworkEvents
| where Timestamp > ago(4h)
| join kind=inner TiFeed on RemoteIP == IndicatorValue
| where IndicatorType == "IP"
```

---

## 32.8 SPL Advanced

### Beyond Basics (P2/P3)
```spl
// Streamstats for sessionization
index=edr sourcetype=edr_process
| streamstats current=f last(_time) as prev_time by hostname, process_name
| eval interval=_time - prev_time
| where interval < 10

// Machine Learning Toolkit (MLTK)
| fit DensityFunction algorithm=GaussianMixture
| apply DensityFunction

// Subsearch for correlation
index=winevents EventCode=4624
[ search index=edr sourcetype=edr_process FileName="mimikatz.exe"
  | fields src_ip ]
```

---

## 32.9 Memory Forensics (Volatility 3)

### What L1 Should Know Exists
| Plugin | Purpose |
|--------|---------|
| `windows.pslist.PsList` | Process list |
| `windows.netscan.NetScan` | Network connections |
| `windows.cmdline.CmdLine` | Process command lines |
| `windows.malfind.Malfind` | Injected code/hollowed processes |
| `windows.hollowprocesses.HollowProcesses` | Process hollowing |
| `windows.filescan.FileScan` | File handles |
| `windows.registry.RegScan` | Registry keys in memory |
| `windows.dumpregistry.DumpRegistry` | Extract registry hives |

### L1 Role
- **Request** memory acquisition from IR/Forensics
- **Read** Volatility output provided by forensics team
- **Correlate** memory findings with logs/EDR
- **NOT**: Run Volatility, acquire memory, analyze internals

---

## 32.10 Reverse Engineering

### What L1 Should Know Exists
| Tool | Purpose |
|------|---------|
| **IDA Pro / Ghidra** | Disassembler/decompiler |
| **x64dbg / WinDbg** | Debugger |
| **PE-bear / CFF Explorer** | PE header analysis |
| **Strings / FLOSS** | String extraction (incl. obfuscated) |
| **CAPA** | Capability detection (what can this binary do?) |

### L1 Role
- Submit samples to sandbox/RE team
- Read RE reports: capabilities, IOCs, ATT&CK mapping
- Use CAPA output for quick triage
- **NOT**: Reverse engineer malware

---

## 32.11 Malware Analysis Advanced

### Static vs Dynamic
| Type | What It Is | L1 Involvement |
|------|------------|----------------|
| **Static** | Analyze without executing (strings, imports, PE structure) | Submit hash/file, read report |
| **Dynamic** | Execute in sandbox (Cuckoo, CAPE, Any.Run, Joe) | Submit, analyze behavioral report |
| **Hybrid** | Both | Read combined report |

### Sandbox Report Sections L1 Must Read
- **MITRE ATT&CK mapping** (techniques observed)
- **IOCs** (IPs, domains, files, registry, mutexes)
- **Behavioral summary** (injection, persistence, C2, exfil)
- **Network traffic** (PCAP, DNS, HTTP)
- **Dropped/created files**
- **Similarity clustering** (malware family)

---

## 32.12 Cloud Detection Engineering

### Beyond Basics
- **CloudTrail/Activity Log parsing** at scale
- **CSPM policy-as-code** (Terraform, Rego/OPA)
- **CIEM detection** (permission escalation paths)
- **Container runtime security** (Falco, Tracee, Tetragon)
- **Serverless/Function monitoring** (Lambda, Cloud Functions)

### L1 Awareness
- Know these exist and generate alerts you may triage
- Understand cloud-specific MITRE (Cloud Matrix)
- Correlate cloud alerts with on-prem/endpoint

---

## 32.13 Learning Path After L1

### L1 → L2 (6-18 months)
1. Master all P0/P1 modules
2. Lead investigations independently
3. Mentor new L1s
4. Contribute to detection tuning
4. Participate in threat hunts
5. Begin learning: memory forensics, malware analysis basics, detection engineering

### L2 → L3 (2-4 years)
1. Deep forensic analysis (memory, disk)
2. Malware reverse engineering
3. Threat hunting (hypothesis-led)
4. Detection engineering (write/maintain rules)
5. Incident response leadership
6. Attribution basics

### L3 → Principal/Lead
1. Strategic threat intelligence
2. Detection architecture
3. Team leadership
4. Cross-functional security programs

---

## 32.14 Certifications Worth Considering (Post-L1)

| Certification | Focus | L1 Relevance |
|---------------|-------|--------------|
| **CompTIA Security+** | Foundational | Good baseline |
| **CompTIA CySA+** | SOC Analyst | **Directly relevant** |
| **GIAC GCIH** | Incident Handling | Strong for L1→L2 |
| **GIAC GCFA** | Forensic Analysis | L2/L3 |
| **GIAC GNFA** | Network Forensics | L2/L3 |
| **GIAC GREM** | Malware Reverse Engineering | L3 |
| **EC-Council CEH** | Ethical Hacking | Understanding attacker |
| **(ISC)² CISSP** | Management/Leadership | Senior roles |
| **Vendor-specific** | Splunk, Sentinel, CrowdStrike, etc. | Role-specific |

---

## 32.15 Recommended Advanced Resources

### Books
- *Practical Malware Analysis* (Sikorski & Honig)
- *The Art of Memory Forensics* (Ligh et al.)
- *Windows Internals* (Pavel Yosifovich et al.)
- *MITRE ATT&CK Defender's Guide* (MITRE)

### Practice Platforms
- **TryHackMe** (SOC Level 1/2 paths)
- **Hack The Box** (Pro Labs: Dante, Rasta)
- **RangeForce** (SOC modules)
- **LetsDefend** (SOC simulation)
- **Blue Team Labs Online** (BTL)

### Communities
- **r/blueteamsec** (Reddit)
- **SANS Blue Team Summit**
- **MITRE ATT&CK Community**
- **Sigma Rule Repository** (GitHub)
- **Detection Engineering Weekly** (newsletter)

---

## Summary: What L1 Must Know About Advanced Topics

- [ ] **Awareness only**: Know these topics exist and what they are
- [ ] **Terminology**: APT, threat hunting, detection engineering, Sigma, YARA, Suricata, Volatility, RE
- [ ] **Boundaries**: Clear on what L1 does vs L2/L3/Detection Engineering/Forensics/RE
- [ ] **Career path**: L1 → L2 → L3 → Principal, with skill progression
- [ ] **Certifications**: CySA+ for L1, GCIH for L2, GCFA/GREM for L3
- [ ] **Practice platforms**: TryHackMe, HTB, LetsDefend for hands-on

> **Remember**: Master the P0/P1 curriculum first. These advanced topics are for **after** you're competent as an L1 analyst.