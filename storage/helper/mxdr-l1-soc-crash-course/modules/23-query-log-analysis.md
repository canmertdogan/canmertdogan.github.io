# Module 23: Query and Log Analysis

**Priority: P0 — Must know before L1 interview**

---

## 23.1 Why Query Skills Matter for L1

### Reality Check
- **SIEM is your primary interface** — you live in the query window
- **Alerts lack context** — you must query to investigate
- **Speed matters** — SLA clock starts at alert creation
- **Bad queries = missed evidence** — false negatives
- **Inefficient queries = wasted time** — false positives, timeouts

### The L1 Query Workflow
```
Alert Received
      │
      ▼
Parse Alert: What fields are available?
      │
      ▼
Form Hypothesis: What am I looking for?
      │
      ▼
Build Query: Translate hypothesis → SIEM syntax
      │
      ▼
Execute → Analyze Results → Refine Query
      │
      ▼
Find Evidence → Document → Decide → Escalate/Close
```

---

## 23.2 Core Query Concepts (Platform Agnostic)

### Data Model Understanding
Before querying, know your data:
| Concept | Description | Example |
|---------|-------------|---------|
| **Index/Table** | Logical data container | `windows_security`, `firewall_logs`, `edr_alerts` |
| **Field/Column** | Individual attribute | `EventID`, `SourceIP`, `User`, `CommandLine` |
| **Data Type** | string, integer, ip, timestamp, boolean | `SourceIP` = ip, `EventID` = integer |
| **Timestamp** | When event occurred | `@timestamp`, `TimeGenerated`, `_time` |
| **Normalization** | Standardized field names across sources | `src_ip`, `dest_ip`, `user` across all logs |

### Essential Query Operations
| Operation | Purpose | Example |
|-----------|---------|---------|
| **Filter/Where** | Reduce dataset | `EventID == 4625` |
| **Search/Contains** | Text matching | `CommandLine contains "powershell"` |
| **Regex** | Pattern matching | `CommandLine regex "-enc\\s+"` |
| **Time Range** | Limit to window | `last 4 hours`, `between 10:00 and 14:00` |
| **Fields/Select** | Choose columns | `select Time, User, SourceIP, EventID` |
| **Aggregation** | Count, sum, unique | `count by User`, `dcount(SourceIP)` |
| **Sort/Order** | Order results | `sort by Time desc` |
| **Limit/Top** | Restrict rows | `top 100`, `limit 50` |
| **Join/Lookup** | Enrich with external data | `join VT_Results on Hash` |
| **Stats/Chart** | Visualize | `timechart count by EventID` |

---

## 23.3 KQL (Kusto Query Language) — Microsoft Sentinel/Defender

### Basic Syntax
```kql
// Table name
SecurityEvent

// Pipe operator chains operations
| where TimeGenerated > ago(4h)
| where EventID == 4625
| where AccountType != "Machine"

// Select specific columns
| project TimeGenerated, Computer, Account, IpAddress, LogonType

// Sort and limit
| sort by TimeGenerated desc
| take 50
```

### Common KQL Patterns for SOC

#### 1. Failed Logon Analysis
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where AccountType != "Machine"
| summarize 
    FailedCount = count(), 
    UniqueIPs = dcount(IpAddress),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Account, Computer
| where FailedCount >= 10
| sort by FailedCount desc
```

#### 2. PowerShell Encoded Command Detection
```kql
DeviceProcessEvents
| where Timestamp > ago(4h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "-encodedcommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp desc
```

#### 3. Suspicious Process Tree (Word → PowerShell)
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "winword.exe" and FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

#### 4. Network Connection to Rare Port
```kql
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemotePort !in (80, 443, 53, 22, 3389, 445, 135, 139)
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where ConnectionCount > 5
| sort by ConnectionCount desc
```

#### 5. Beaconing Detection (Regular Intervals)
```kql
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemoteIPType == "Public"
| summarize 
    Connections = count(), 
    AvgInterval = avg(todouble(Timestamp) - todouble(prev(Timestamp))),
    StdDevInterval = stddev(todouble(Timestamp) - todouble(prev(Timestamp))),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where Connections >= 10
| where StdDevInterval < 30  // Low variance = regular beaconing
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Connections, AvgInterval, StdDevInterval, FirstSeen, LastSeen
```

#### 6. Threat Intel Enrichment Join
```kql
let maliciousIPs = externaldata (IP:string, ThreatType:string, Confidence:int)
    @"https://ti-feed.example.com/malicious_ips.csv"
    with (format="csv", ignoreFirstRecord=true);

DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| join kind=inner maliciousIPs on $left.RemoteIP == $right.IP
| project Timestamp, DeviceName, RemoteIP, ThreatType, Confidence, InitiatingProcessFileName
```

### KQL Functions Cheat Sheet
| Function | Purpose | Example |
|----------|---------|---------|
| `ago(4h)` | Relative time | `where Time > ago(4h)` |
| `between()` | Time range | `where Time between (datetime(2024-01-01) .. datetime(2024-01-02))` |
| `has` / `has_cs` | Substring match (case insensitive/sensitive) | `where CommandLine has "powershell"` |
| `matches regex` | Regex match | `where CommandLine matches regex "-enc\\s+"` |
| `startswith` / `endswith` | Prefix/suffix | `where FileName startswith "temp"` |
| `in` / `!in` | List membership | `where EventID in (4624, 4625, 4634)` |
| `summarize` | Aggregation | `summarize count() by User` |
| `dcount()` | Distinct count | `dcount(SourceIP)` |
| `make_set()` | Collect unique values | `make_set(SourceIP)` |
| `arg_max()` | Row with max value | `arg_max(TimeGenerated, *)` |
| `top` / `limit` | Row limit | `top 100 by TimeGenerated desc` |
| `join` | Combine tables | `join kind=leftouter TiFeed on IP` |
| `lookup` | Reference set join | `lookup MaliciousHashes on SHA256` |
| `parse` / `extract` | Field extraction | `parse CommandLine with * " -enc " EncodedCommand` |
| `extend` | Create new column | `extend Decoded = base64_decode(EncodedCommand)` |
| `mv-expand` | Expand arrays | `mv-expand Tags` |

---

## 23.4 SPL (Splunk Processing Language)

### Basic Syntax
```spl
index=winevents sourcetype=xmlwineventlog
earliest=-4h
EventCode=4625
| where Account_Type!="Machine"
| stats count as FailedCount dc(src_ip) as UniqueIPs min(_time) as FirstAttempt max(_time) as LastAttempt by Account, Computer
| where FailedCount >= 10
| sort - FailedCount
| head 50
```

### Common SPL Patterns for SOC

#### 1. Failed Logon Analysis
```spl
index=winevents sourcetype=xmlwineventlog
earliest=-24h
EventCode=4625
| where Account_Type!="Machine"
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| stats count as FailedCount dc(src_ip) as UniqueIPs min(_time) as FirstAttempt max(_time) as LastAttempt by Account, Computer
| eval FirstAttempt=strftime(FirstAttempt, "%Y-%m-%d %H:%M:%S")
| eval LastAttempt=strftime(LastAttempt, "%Y-%m-%d %H:%M:%S")
| where FailedCount >= 10
| sort - FailedCount
```

#### 2. PowerShell Encoded Command
```spl
index=edr sourcetype=edr_process
earliest=-4h
process_name="powershell.exe"
| where like(command_line, "%-enc%") OR like(command_line, "%-encodedcommand%")
| table _time, hostname, user, command_line, parent_process_name, sha256
| sort - _time
```

#### 3. Suspicious Process Tree
```spl
index=edr sourcetype=edr_process
earliest=-24h
parent_process_name="winword.exe" process_name="powershell.exe"
| table _time, hostname, user, process_name, command_line, parent_process_name, parent_command_line
```

#### 4. Beaconing Detection
```spl
index=edr sourcetype=edr_network
earliest=-4h
dest_ip_type="public"
| stats count as Connections avg(eval(_time - lag(_time))) as AvgInterval stdev(eval(_time - lag(_time))) as StdDevInterval min(_time) as FirstSeen max(_time) as LastSeen by hostname, process_name, dest_ip, dest_port
| where Connections >= 10 AND StdDevInterval < 30
| eval FirstSeen=strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
| eval LastSeen=strftime(LastSeen, "%Y-%m-%d %H:%M:%S")
```

### SPL Functions Cheat Sheet
| Function | Purpose | Example |
|----------|---------|---------|
| `earliest=-4h` | Relative time | `earliest=-24h latest=now` |
| `stats` | Aggregation | `stats count by user` |
| `dc()` | Distinct count | `dc(src_ip)` |
| `eval` | Create calculated field | `eval decoded=base64_decode(encoded)` |
| `where` | Filter results | `where count > 10` |
| `sort` | Sort | `sort - count` |
| `head` / `tail` | Limit rows | `head 100` |
| `rex` | Regex extraction | `rex field=cmd "-enc\s+(?<encoded>\S+)"` |
| `join` / `lookup` | Enrichment | `lookup malicious_ips ip as dest_ip` |
| `transaction` | Group related events | `transaction user maxspan=1h` |
| `timechart` | Time series | `timechart count by EventCode` |
| `chart` | Pivot table | `chart count over user by EventCode` |
| `makemv` / `mvexpand` | Multi-value fields | `makemv delim="," tags` |

---

## 23.5 SQL Basics for Log Analysis

### When You'll Use SQL
- Querying security data lakes (Athena, BigQuery, Snowflake)
- Direct database investigation (CMDB, asset inventory)
- Custom detection engineering

### Essential SQL for SOC
```sql
-- Failed logons last 24 hours
SELECT 
    account_name,
    computer_name,
    COUNT(*) as failed_count,
    COUNT(DISTINCT source_ip) as unique_ips,
    MIN(event_time) as first_attempt,
    MAX(event_time) as last_attempt
FROM windows_security_logs
WHERE event_id = 4625
  AND account_type != 'Machine'
  AND event_time >= NOW() - INTERVAL '24 hours'
GROUP BY account_name, computer_name
HAVING COUNT(*) >= 10
ORDER BY failed_count DESC;

-- PowerShell encoded commands
SELECT 
    event_time,
    hostname,
    user_name,
    command_line,
    parent_process_name,
    sha256
FROM edr_process_events
WHERE process_name = 'powershell.exe'
  AND (command_line ILIKE '%-enc%' OR command_line ILIKE '%-encodedcommand%')
  AND event_time >= NOW() - INTERVAL '4 hours'
ORDER BY event_time DESC;

-- Beaconing detection
WITH network_stats AS (
    SELECT 
        hostname,
        process_name,
        dest_ip,
        dest_port,
        COUNT(*) as connections,
        AVG(EXTRACT(EPOCH FROM (event_time - LAG(event_time) OVER (PARTITION BY hostname, process_name, dest_ip, dest_port ORDER BY event_time)))) as avg_interval,
        STDDEV(EXTRACT(EPOCH FROM (event_time - LAG(event_time) OVER (PARTITION BY hostname, process_name, dest_ip, dest_port ORDER BY event_time)))) as stddev_interval,
        MIN(event_time) as first_seen,
        MAX(event_time) as last_seen
    FROM edr_network_events
    WHERE dest_ip_type = 'Public'
      AND event_time >= NOW() - INTERVAL '4 hours'
    GROUP BY hostname, process_name, dest_ip, dest_port
    HAVING COUNT(*) >= 10
)
SELECT *
FROM network_stats
WHERE stddev_interval < 30
ORDER BY connections DESC;
```

---

## 23.6 Field Extraction & Parsing

### Common Parsing Scenarios

#### Extract Base64 from PowerShell Command
```kql
// KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| extend EncodedPart = extract(@"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(EncodedPart)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, EncodedPart, Decoded
```

```spl
// SPL
index=edr sourcetype=edr_process process_name="powershell.exe"
| rex field=command_line "-enc(?:odedcommand)?\s+(?<encoded>[A-Za-z0-9+/=]+)"
| eval decoded=base64_decode(encoded)
| table _time, hostname, user, command_line, encoded, decoded
```

#### Parse DNS Query from Sysmon
```kql
// KQL - Sysmon Event ID 22 (DNS Query)
DeviceDnsEvents
| where Timestamp > ago(4h)
| parse QueryResults with * ";" DnsIp ";"
| project Timestamp, DeviceName, QueryName, QueryType, DnsIp, ProcessName
```

#### Extract URL from Proxy Logs
```kql
// KQL
WebProxy
| where TimeGenerated > ago(4h)
| extend URL = strcat("http", iff(Url startswith "https", "s", ""), "://", Host, UrlPath)
| project TimeGenerated, ClientIP, User, URL, ResponseCode, BytesSent, BytesReceived
```

---

## 23.7 Time Handling — Critical for SOC

### Timezone Awareness
```kql
// KQL - Convert to specific timezone
| extend LocalTime = datetime_utc_to_local(TimeGenerated, "Pacific Standard Time")
| extend LocalTime = TimeGenerated + 5h  // Manual offset (avoid - use IANA tz)
```

```spl
// SPL - Timezone handling
| eval LocalTime=strftime(_time, "%Y-%m-%d %H:%M:%S %Z")
| eval LocalTime=_time - 18000  // EST offset in seconds
```

### Time Bucketing for Trend Analysis
```kql
// KQL - Hourly buckets
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedCount = count() by bin(TimeGenerated, 1h), Account
| render timechart
```

```spl
// SPL - Hourly buckets
index=winevents EventCode=4625 earliest=-7d
| timechart span=1h count by Account
```

### Relative Time Best Practices
| Use Case | KQL | SPL |
|----------|-----|-----|
| Last 4 hours | `ago(4h)` | `earliest=-4h` |
| Last 24 hours | `ago(24h)` | `earliest=-24h` |
| Last 7 days | `ago(7d)` | `earliest=-7d` |
| Specific range | `between (datetime(2024-01-01) .. datetime(2024-01-02))` | `earliest=01/01/2024:00:00:00 latest=01/02/2024:00:00:00` |
| Business hours only | `where TimeGenerated between (startofday(ago(1d)) + 8h .. startofday(ago(1d)) + 18h)` | `where (strftime(_time, "%H") >= 8 AND strftime(_time, "%H") <= 18)` |

---

## 23.8 Query Performance Optimization

### Do's and Don'ts

| ✅ DO | ❌ DON'T |
|------|----------|
| Filter early (time, then indexed fields) | Search all time, filter late |
| Use `has` for exact substring | Use `contains` or regex when `has` works |
| Specify columns with `project`/`table` early | Keep all columns through pipeline |
| Use `summarize` before `join` | Join raw events (explodes rows) |
| Limit results with `take`/`head` | Return unlimited rows |
| Use materialized views/reference sets | Repeat same enrichment in every query |
| Test on small time range first | Run heavy query on 30 days first |

### KQL Optimization Example
```kql
// ❌ SLOW: Filters late, no column projection
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30d)
| join kind=inner (DeviceInfo | project DeviceName, OSPlatform) on Computer == DeviceName
| summarize count() by Account, OSPlatform

// ✅ FAST: Time first, project early, summarize before join
let failedLogons = SecurityEvent
    | where TimeGenerated > ago(24h)  // Smaller window first
    | where EventID == 4625
    | project TimeGenerated, Computer, Account, IpAddress;

failedLogons
| summarize FailedCount = count() by Computer, Account
| where FailedCount > 5
| join kind=inner (DeviceInfo | project DeviceName, OSPlatform) on $left.Computer == $right.DeviceName
| project Account, Computer, FailedCount, OSPlatform
```

---

## 23.9 Building Investigation Queries: Step by Step

### Methodology: From Alert to Evidence

**Alert**: "Multiple failed logons for user j.smith from IP 203.0.113.45"

#### Step 1: Understand Alert Fields
```kql
// What fields does this alert type provide?
SecurityAlert
| where AlertName == "Multiple Failed Logons"
| take 1
| project-away SystemAlertId, TenantId  // Remove noise
```

#### Step 2: Pivot on Key Entities
```kql
// Pivot 1: All activity for this USER
SecurityEvent
| where TimeGenerated > ago(24h)
| where Account == "j.smith"
| summarize EventCount = count() by EventID
| sort by EventCount desc

// Pivot 2: All activity from this SOURCE IP
SecurityEvent
| where TimeGenerated > ago(24h)
| where IpAddress == "203.0.113.45"
| summarize EventCount = count() by EventID, Account
| sort by EventCount desc

// Pivot 3: All activity on TARGET HOST
SecurityEvent
| where TimeGenerated > ago(24h)
| where Computer == "WKS-0452"
| where EventID in (4624, 4625, 4634, 4647, 4672, 4688)
| sort by TimeGenerated desc
```

#### Step 3: Build Timeline
```kql
// Unified timeline around alert time
let alertTime = datetime(2024-01-15T10:23:45Z);
union 
    (SecurityEvent | where TimeGenerated between (alertTime - 2h .. alertTime + 2h) | where Account == "j.smith" | project TimeGenerated, EventID, Computer, IpAddress, LogonType, Type = "Auth"),
    (DeviceProcessEvents | where Timestamp between (alertTime - 2h .. alertTime + 2h) | where AccountName == "j.smith" | project Timestamp, FileName, ProcessCommandLine, Type = "Process"),
    (DeviceNetworkEvents | where Timestamp between (alertTime - 2h .. alertTime + 2h) | where DeviceName == "WKS-0452" | project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, Type = "Network")
| sort by TimeGenerated asc
```

#### Step 4: Hypothesis Testing
```kql
// Hypothesis: Password spray (one IP, many users)
SecurityEvent
| where TimeGenerated > ago(4h)
| where EventID == 4625
| where IpAddress == "203.0.113.45"
| summarize TargetedUsers = make_set(Account), FailedCount = count() by IpAddress
| where array_length(TargetedUsers) > 10

// Hypothesis: Brute force (one user, many attempts)
SecurityEvent
| where TimeGenerated > ago(4h)
| where EventID == 4625
| where Account == "j.smith"
| summarize Attempts = count(), UniqueIPs = dcount(IpAddress) by Account
| where Attempts > 20

// Hypothesis: Successful login after failures
SecurityEvent
| where TimeGenerated > ago(4h)
| where Account == "j.smith"
| where EventID in (4624, 4625)
| extend Result = iff(EventID == 4624, "Success", "Failure")
| summarize Events = make_list(pack(TimeGenerated, Result, IpAddress, LogonType)) by Account
| mv-expand Events
| project Account, TimeGenerated = Events[0], Result = Events[1], IpAddress = Events[2], LogonType = Events[3]
| sort by TimeGenerated asc
```

---

## 23.10 Common L1 Query Mistakes

| Mistake | Impact | Fix |
|---------|--------|-----|
| No time filter / too wide | Timeout, cost, noise | Always start with `ago(4h)` or relevant window |
| Searching `_raw` / full text | Slow, imprecise | Use extracted fields: `CommandLine`, `EventID` |
| Case-sensitive search missing variants | Missed events | Use `has` (case-insensitive) or `has_cs` intentionally |
| Not handling machine accounts | Noise in auth logs | Filter `AccountType != "Machine"` or `Account !endswith "$"` |
| Joining on non-unique fields | Cartesian explosion | Summarize first, join on unique keys |
| Ignoring data normalization | Missed events across sources | Use normalized fields: `src_ip`, `dest_ip`, `user` |
| Not saving/sharing queries | Repeated work | Save as dashboard, detection rule, or shared query |
| Single monolithic query | Hard to debug | Break into steps with `let` statements |

---

## 23.11 Query Templates Library

### Template 1: Account Investigation
```kql
// Save as function: InvestigateAccount(accountName, hours=24)
let InvestigateAccount = (accountName:string, hours:long=24) {
    let startTime = ago(hours * 1h);
    // Auth activity
    let auth = SecurityEvent
        | where TimeGenerated > startTime
        | where Account == accountName
        | where EventID in (4624, 4625, 4634, 4647, 4672, 4720, 4728, 4732)
        | project TimeGenerated, EventID, Computer, IpAddress, LogonType, TargetAccount;
    // Process activity
    let process = DeviceProcessEvents
        | where Timestamp > startTime
        | where AccountName == accountName
        | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName;
    // Network activity
    let network = DeviceNetworkEvents
        | where Timestamp > startTime
        | where AccountName == accountName
        | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName;
    // Return combined
    union auth, process, network
    | sort by TimeGenerated asc
};
// Usage: InvestigateAccount("j.smith", 24)
```

### Template 2: Host Investigation
```kql
// Save as function: InvestigateHost(hostname, hours=24)
let InvestigateHost = (hostname:string, hours:long=24) {
    let startTime = ago(hours * 1h);
    // All security events
    let events = SecurityEvent
        | where TimeGenerated > startTime
        | where Computer == hostname
        | project TimeGenerated, EventID, Account, IpAddress, LogonType;
    // EDR process events
    let process = DeviceProcessEvents
        | where Timestamp > startTime
        | where DeviceName == hostname
        | project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256;
    // EDR network events
    let network = DeviceNetworkEvents
        | where Timestamp > startTime
        | where DeviceName == hostname
        | project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, ConnectionDirection;
    // File events
    let file = DeviceFileEvents
        | where Timestamp > startTime
        | where DeviceName == hostname
        | project Timestamp, FileName, FolderPath, ActionType, SHA256, InitiatingProcessFileName;
    union events, process, network, file
    | sort by TimeGenerated asc
};
```

### Template 3: IOC Search Across All Sources
```kql
// Save as function: SearchIOC(iocValue, hours=72)
let SearchIOC = (iocValue:string, hours:long=72) {
    let startTime = ago(hours * 1h);
    // Search across normalized fields
    union 
        (SecurityEvent | where TimeGenerated > startTime | where IpAddress == iocValue or Account == iocValue | project TimeGenerated, Source = "SecurityEvent", Computer, Account, IpAddress),
        (DeviceProcessEvents | where Timestamp > startTime | where SHA256 == iocValue or InitiatingProcessSHA256 == iocValue | project Timestamp, Source = "EDR_Process", DeviceName, SHA256, FileName),
        (DeviceNetworkEvents | where Timestamp > startTime | where RemoteIP == iocValue | project Timestamp, Source = "EDR_Network", DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName),
        (DeviceFileEvents | where Timestamp > startTime | where SHA256 == iocValue | project Timestamp, Source = "EDR_File", DeviceName, FileName, FolderPath, SHA256),
        (DnsEvents | where Timestamp > startTime | where QueryName == iocValue | project Timestamp, Source = "DNS", DeviceName, QueryName),
        (UrlEvents | where Timestamp > startTime | where Url contains iocValue | project Timestamp, Source = "Proxy", DeviceName, Url)
    | sort by Timestamp asc
};
```

---

## 23.12 Summary: What L1 Must Know

- [ ] Core query operations: filter, search, regex, time range, project, aggregate, sort, limit, join
- [ ] KQL syntax for Microsoft Sentinel/Defender (most common in MXDR)
- [ ] SPL syntax for Splunk environments
- [ ] Basic SQL for data lake queries
- [ ] Field extraction: base64, regex parsing, URL/DNS parsing
- [ ] Time handling: relative time, timezones, bucketing
- [ ] Query optimization: filter early, project early, summarize before join
- [ ] Investigation methodology: pivot on entities → timeline → hypothesis testing
- [ ] Reusable query templates for account/host/IOC investigation
- [ ] Common mistakes and how to avoid them