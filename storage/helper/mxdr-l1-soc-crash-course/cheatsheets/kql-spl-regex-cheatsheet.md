# KQL / SPL & Regex Cheat Sheet for SOC Analysts

**Priority: P1 — Alerts lack context by design; KQL, SPL, and regex are the tools you use to gather evidence, build timelines, and prove true/false positive in every investigation.**

---

## Why Query Skills Matter for L1

Your **SIEM is your primary interface**. The triage workflow (Module 2) always lands on a query: pivot on user, asset, and source IP, build a T-60/T+60 timeline, and test hypotheses like password spray vs brute force. You cannot classify an alert without query evidence.

The **L1 query workflow**:
1. **Parse the alert** — what fields are available?
2. **Form a hypothesis** — what am I looking for?
3. **Build the query** — translate hypothesis to SIEM syntax
4. **Execute, analyze, refine** — filter, aggregate, pivot
5. **Document evidence** — then decide TP / FP / BP / Inconclusive

Two rules that save you every time: **filter early (time first) and project columns early**. Bad queries cause timeouts and missed evidence; slow queries blow your triage time budget.

---

## KQL Core Pipeline Operators

KQL is **table-based**: you start with a table name, then chain operations with the pipe `|`. Reading order is top-to-bottom — each operator consumes the output of the one above it.

| Operator | Purpose | Example |
|----------|---------|---------|
| `where` | Filter rows | `where EventID == 4625` |
| `project` | Pick/rename columns | `project TimeGenerated, Account, IpAddress` |
| `extend` | Add a computed column | `extend Result = iff(EventID == 4624, "Success", "Failure")` |
| `summarize` | Aggregate | `summarize count() by Account` |
| `order by` / `sort by` | Sort results | `sort by FailedCount desc` |
| `take` | Limit rows | `take 50` |
| `distinct` | Unique combinations | `distinct Account, IpAddress` |
| `join` | Combine two tables | `join kind=inner TiFeed on $left.IpAddress == $right.IP` |
| `search` | Full-text across tables | `search "203.0.113.45"` |
| `union` | Combine tables by rows | `union SecurityEvent, DeviceProcessEvents` |
| `range` | Generate a series | `range Hour from ago(24h) to now() step 1h` |

```kql
// Failed logons with a time filter, projection, and sort
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where AccountType != "Machine"
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| sort by TimeGenerated desc
| take 100
```

Use `has` (case-insensitive substring) over `contains` for performance, and filter by time **before** anything else.

---

## KQL Time Handling

Time filters are mandatory on every query — starting without one is the #1 L1 mistake (timeouts, cost, noise).

```kql
// Relative windows
SecurityEvent | where TimeGenerated > ago(1h)
SecurityEvent | where TimeGenerated > ago(24h)

// since == ago (relative-time keyword)
SecurityEvent | where TimeGenerated since 4h

// Exact range
SecurityEvent
| where TimeGenerated between (datetime(2024-01-15T10:00:00Z) .. datetime(2024-01-15T14:00:00Z))
```

**Time bucketing** (`bin`) powers trend/beaconing analysis:

```kql
// Failed logons per hour, per account
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedCount = count() by bin(TimeGenerated, 5m), Account
| render timechart
```

| Use Case | KQL | SPL |
|----------|-----|-----|
| Last 1 hour | `ago(1h)` | `earliest=-1h` |
| Last 24 hours | `ago(24h)` | `earliest=-24h` |
| Last 7 days | `ago(7d)` | `earliest=-7d` |
| Exact range | `between (datetime(..) .. datetime(..))` | `earliest=... latest=...` |
| Bucket size | `bin(TimeGenerated, 5m)` | `bucket _time span=5m` |

---

## KQL String Functions & Field Extraction

| Function | Purpose | Example |
|----------|---------|---------|
| `contains` / `has` | Substring (case-insensitive) | `where CommandLine has "powershell"` |
| `has_cs` | Case-sensitive `has` | `where CommandLine has_cs "-enc"` |
| `startswith` / `endswith` | Prefix / suffix | `where Account !endswith "$"` |
| `matches regex` | Regex match | `where ProcessCommandLine matches regex "-enc\\s+"` |
| `parse` | Pattern-based extraction | `parse QueryResults with * ";" DnsIp ";"` |
| `split` | Split into array | `extend parts = split(Path, "\\")` |
| `tostring` | Convert to string | `extend Src = tostring(IpAddress)` |
| `format_datetime` | Format timestamps | `extend T = format_datetime(TimeGenerated, "yyyy-MM-dd HH:mm:ss")` |
| `extract()` | Regex capture | `extend Enc = extract(@"-enc\s+(\S+)", 1, CommandLine)` |
| `base64_decode_tostring` | Decode base64 | `extend Decoded = base64_decode_tostring(Enc)` |

Extract and decode an encoded PowerShell payload:

```kql
DeviceProcessEvents
| where Timestamp > ago(4h)
| where FileName =~ "powershell.exe"
| extend EncodedPart = extract(@"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(EncodedPart)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Decoded
```

---

## KQL Ready-to-Use Investigation Queries

**Failed logons summarized by account/IP** (brute force, password spray):

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where AccountType != "Machine"
| summarize FailedCount = count(), UniqueIPs = dcount(IpAddress)
    by Account, Computer
| where FailedCount >= 10
| sort by FailedCount desc
```

**Top source IPs from firewall logs** (`CommonSecurityLog`):

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction =~ "deny"
| summarize Denied = count() by SourceIP
| order by Denied desc
| take 20
```

**New processes with encoded PowerShell** (obfuscation, download cradles):

```kql
DeviceProcessEvents
| where Timestamp > ago(4h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "-encodedcommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp desc
```

**Signin anomalies** — single user, many apps/IPs, or risky sign-ins (`SigninLogs`):

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"                          // success
| where RiskLevelDuringSignIn in ("medium", "high")
| summarize SignIns = count(), Apps = dcount(AppDisplayName)
    by UserPrincipalName, IPAddress
| where SignIns > 1
| order by SignIns desc
```

**Beaconing** — many connections, low interval variance:

```kql
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemoteIPType == "Public"
| summarize Connections = count(),
    StdDevInterval = stddev(todouble(Timestamp) - todouble(prev(Timestamp)))
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where Connections >= 10 and StdDevInterval < 30
```

---

## Sentinel Data Tables You Will Query

| Table | What It Contains | Typical Use |
|-------|------------------|-------------|
| **SecurityEvent** | Windows events from agents (4624, 4625, 4688...) | Auth, process, account activity |
| **SigninLogs** | Azure AD / Entra ID interactive sign-ins | Impossible travel, brute force, risky sign-ins |
| **DeviceProcessEvents** | EDR process creation (MDE) | Process trees, command lines, LOLBins |
| **DeviceNetworkEvents** | EDR network connections (MDE) | C2, beaconing, rare ports |
| **CommonSecurityLog** | Normalized firewall/proxy/IPS events | Top source IPs, denied traffic |
| **Syslog** | Raw syslog from network/Unix devices | Linux/network investigation |
| **AzureDiagnostics** | Azure resource/service logs | Cloud resource investigation |
| **DeviceFileEvents** | EDR file create/modify (MDE) | Malware drops, staging |

Pair the table with the right columns: `SecurityEvent.EventID`/`Account`/`IpAddress`, `SigninLogs.UserPrincipalName`/`IPAddress`/`ResultType`, `DeviceProcessEvents.FileName`/`ProcessCommandLine`/`InitiatingProcessFileName`.

---

## SPL Core Commands

SPL is **search-first**: the base search comes before the first pipe, and indexed fields are fast — put time and field filters there.

```spl
index=windows EventCode=4625 earliest=-1h
| stats count by Account
| sort - count
```

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Base + full-text filter | `index=windows EventCode=4625` |
| `table` | Pick columns | `table _time, Account, src_ip` |
| `fields` | Keep only listed fields | `fields Account, src_ip, _time` |
| `stats` | Aggregate | `stats count, dc(src_ip) by Account` |
| `top` | Top values | `top 20 src_ip` |
| `sort` | Sort results | `sort - count` |
| `dedup` | Unique rows by field | `dedup src_ip` |
| `rex` | Regex field extraction | `rex field=command_line "-enc\s+(?<encoded>\S+)"` |
| `eval` | Compute a new field | `eval LocalTime=strftime(_time, "%H:%M:%S")` |
| `where` | Post-search filter | `where count > 10` |
| `timechart` | Time series | `timechart span=1h count by Account` |
| `transaction` | Group related events | `transaction user maxspan=1h` |

Use `dc()` (distinct count), `like()` for SQL-style wildcard matching, and `head`/`tail` to limit output.

---

## SPL Time Handling

Time filters belong in the **base search** — never scan all time then filter.

```spl
# Relative time
index=windows earliest=-1h latest=now

# Bucketing for trends
index=windows EventCode=4625 earliest=-7d
| timechart span=1h count by Account
| bucket _time span=5m
```

| Use Case | Syntax |
|----------|--------|
| Last 1 hour | `earliest=-1h` |
| Last 24 hours | `earliest=-24h latest=now` |
| Exact window | `earliest=01/15/2024:00:00:00 latest=01/15/2024:04:00:00` |
| Bucket size | `bucket _time span=5m` |

**Common Splunk index names** used across environments:

| Index | Content |
|-------|---------|
| `windows` / `winevents` | Windows security/app logs |
| `linux` / `ossec` | Linux syslog / HIDS alerts |
| `firewall` | Firewall deny/allow flows |
| `proxy` | Web proxy traffic |
| `edr` | Endpoint process/network events |
| `dns` | DNS query logs |

---

## SPL Ready-to-Use Queries

**Failed logons per user** (brute force / spray):

```spl
index=windows EventCode=4625 earliest=-24h
| where Account_Type!="Machine"
| stats count as FailedCount dc(src_ip) as UniqueIPs by Account, Computer
| where FailedCount >= 10
| sort - FailedCount
```

**Top source IPs** from firewall logs:

```spl
index=firewall earliest=-24h action=deny
| stats count by src_ip
| sort - count
| head 20
```

**Encoded PowerShell** (with `rex` extraction + decode):

```spl
index=edr sourcetype=edr_process earliest=-4h process_name="powershell.exe"
| where like(command_line, "%-enc%") OR like(command_line, "%-encodedcommand%")
| rex field=command_line "-enc(?:odedcommand)?\s+(?<encoded>[A-Za-z0-9+/=]+)"
| eval decoded=base64_decode(encoded)
| table _time, hostname, user, command_line, encoded, decoded
```

**Process tree** — suspicious parent/child pair:

```spl
index=edr sourcetype=edr_process earliest=-24h
parent_process_name="winword.exe" process_name="powershell.exe"
| table _time, hostname, user, process_name, command_line, parent_process_name, parent_command_line
```

---

## Regex: The Building Blocks

Regex = **pattern matching on text**. You use it in KQL (`matches regex`, `extract`), SPL (`rex`), and command line (`grep -E`) to find IOCs inside raw log lines.

| Element | Syntax | Matches |
|---------|--------|---------|
| **Digit** | `\d` / `[0-9]` | A single digit |
| **Word char** | `\w` | Letter, digit, or underscore |
| **Whitespace** | `\s` | Space, tab, newline |
| **Any char** | `.` | Any single character |
| **Character class** | `[a-f0-9]`, `[^0-9]` | Set / negated set of chars |
| **Anchor start** | `^` | Start of line/string |
| **Anchor end** | `$` | End of line/string |
| **Zero or more** | `*` | `\d*` — greedily as many as possible |
| **One or more** | `+` | `\d+` |
| **Zero or one** | `?` | `https?` (both http and https) |
| **Count range** | `{n,m}` | `[0-9]{1,3}`, exactly `{32}` |
| **Alternation** | `(a|b)` | Either `a` or `b` |
| **Capturing group** | `(...)` | Also captures into group 1, 2, ... |
| **Non-capturing group** | `(?:...)` | Group without capture |
| **Word boundary** | `\b` | Edge of a word — prevents matching inside longer text |

**Lazy vs greedy**: greedy quantifiers (`.+`, `.*`) consume as much as possible; add `?` to make them lazy (`.+?`) and stop at the first match. In `-enc "JABjAGw..." more data "end"`, greedy `".*"` would grab everything to the final quote — lazy `".*?"` stops at the first. This is the classic IOC-extraction bug.

---

## Regex Patterns for SOC

Put patterns in **capturing groups** when you need the value (`extract(..., 1, ...)` in KQL, `(?<name>...)` in `rex`). Always use `\b` boundaries so `123.45.67.8` doesn't match inside a longer string.

| Indicator | Pattern | Notes |
|-----------|---------|-------|
| **IPv4 (loose)** | `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` | Fast; allows 999.x octets |
| **IPv4 (strict)** | `\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b` | Octets validated 0-255 |
| **Domain** | `\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b` | No scheme prefix |
| **Email** | `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` | |
| **URL** | `https?://[^\s"'<>]+` | Stops at whitespace/quotes |
| **MD5 hash** | `\b[0-9a-fA-F]{32}\b` | |
| **SHA1 hash** | `\b[0-9a-fA-F]{40}\b` | |
| **SHA256 hash** | `\b[0-9a-fA-F]{64}\b` | |
| **SMB path** | `\\\\[^\s\\]+\\[^\s\\]+` | UNC share `\\server\share` |
| **Base64** | `[A-Za-z0-9+/]{40,}={0,2}` | 40+ chars, optional padding |
| **Hex string** | `\b(?:0x)?[0-9a-fA-F]{16,}\b` | Long hex blobs, shellcode |

**SOC examples:**

```regex
# Encoded PowerShell block (-enc <base64>)
-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)

# User agent / C2 beacon marker in proxy logs
(?i)(cmd|powershell|wget|curl)\.exe

# SMB admin share lateral movement
\\\\[^\\]+\\admin\$

# IPv4 inside a raw syslog line (then pivot on it)
(?:[0-9]{1,3}\.){3}[0-9]{1,3}
```

**Grep on the command line** (file-based hunting, `-E` = extended, `-i` = ignore case, `-o` = output match only):

```bash
grep -Eo 'https?://[^ "]+' proxy.log          # extract URLs
grep -E '\b[0-9a-fA-F]{64}\b' hashes.txt       # find SHA256 values
grep -i 'encodedcommand' *.ps1                 # hunt encoded PowerShell
```

---

## Summary — L1 Must Know

- [ ] Start every query with a time filter (`ago()`, `earliest=`) — never scan all time
- [ ] Filter early and `project`/`table` columns early; `summarize`/`stats` before `join`
- [ ] KQL pipeline: `where` → `summarize count() by` → `sort` → `take`, reading top-to-bottom
- [ ] Write the failed-logon brute force query in both KQL and SPL from memory (4625, filter machine accounts, `count() >= 10`)
- [ ] Hunt encoded PowerShell with `has "-enc"` / `like("%-enc%")`, then extract and decode the base64
- [ ] Know the Sentinel tables you query: `SecurityEvent`, `SigninLogs`, `DeviceProcessEvents`, `CommonSecurityLog`, `Syslog`
- [ ] Use `bin()` (KQL) and `bucket`/`timechart` (SPL) for beaconing and trend analysis
- [ ] Use `rex field=X "(?<name>...)"` in SPL and `extract()` / `matches regex` in KQL for regex extraction
- [ ] Recognize the SOC regex set: IPv4, domain, URL, email, MD5/SHA1/SHA256, SMB path, base64
- [ ] Know greedy vs lazy quantifiers and add `\b` boundaries so patterns don't match inside longer text
- [ ] Use `grep -Eio` for quick IOC hunting in local logs during investigations
- [ ] Save every good query — you will reuse brute-force, beaconing, and IOC-search queries daily
