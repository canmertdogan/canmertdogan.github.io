# Module 20: Web Security

**Priority: P1 — Web apps = major attack surface. L1 investigates WAF/proxy alerts daily.**

---

## 20.1 Web Application Architecture

### Typical 3-Tier Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────►│   Web/App   │────►│  Database   │
│  (Browser)  │     │   Server    │     │  (SQL/NoSQL)│
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  WAF/Proxy  │     │  App Logs   │     │  DB Audit   │
│  (Layer 7)  │     │  (App-level)│     │  Logs       │
└─────────────┘     └─────────────┘     └─────────────┘
```

### Key Components L1 Monitors
| Component | Logs | Detection Value |
|-----------|------|-----------------|
| **WAF (Web Application Firewall)** | Blocked/Allowed requests, Rule IDs, Attack signatures | **Primary** — SQLi, XSS, RCE, Scanners |
| **Load Balancer / Reverse Proxy** | Client IP, Headers, Latency, Status codes | DDoS, Anomalous traffic, Geo |
| **Web Server (IIS/Apache/Nginx)** | Access logs, Error logs, Module logs | 404 enumeration, 500 errors (exploits) |
| **Application (Custom)** | Business logic logs, Audit trails, API logs | BOLA, IDOR, Auth bypass, Fraud |
| **Database** | Audit logs, Query logs, Failed logins | SQLi, Data exfil, Privilege escalation |
| **CDN** | Edge logs, Cache hit/miss, Geo | DDoS, Geo anomalies, Cache poisoning |

---

## 20.2 OWASP Top 10 (2021) — L1 Detection Focus

| Rank | Category | ID | L1 Detection |
|------|----------|----|--------------|
| 1 | **Broken Access Control** | A01 | BOLA/IDOR, Privilege escalation, Path traversal |
| 2 | **Cryptographic Failures** | A02 | Weak TLS, Sensitive data in logs/URLs, Missing HSTS |
| 3 | **Injection** | A03 | **SQLi, NoSQLi, Command Injection, LDAPi, XPATHi** |
| 4 | **Insecure Design** | A04 | Missing rate limits, Business logic flaws (hard to detect) |
| 5 | **Security Misconfiguration** | A05 | Default creds, Debug enabled, Directory listing, Exposed .git |
| 6 | **Vulnerable/Outdated Components** | A06 | CVE matching, Library version in headers, SBOM |
| 7 | **Identification & Authentication Failures** | A07 | Brute force, Credential stuffing, Weak MFA, Session fixation |
| 8 | **Software & Data Integrity Failures** | A08 | Unsigned updates, CI/CD compromise, Deserialization |
| 9 | **Security Logging & Monitoring Failures** | A09 | **Missing logs, No alerts on anomalies** (meta-detection) |
| 10 | **Server-Side Request Forgery (SSRF)** | A10 | **Internal metadata access, Cloud metadata, Port scanning** |

---

## 20.3 Injection Attacks — Deep Dive

### 1. SQL Injection (SQLi)
**Mechanism**: User input concatenated into SQL query without parameterization.
```sql
-- Vulnerable
query = "SELECT * FROM users WHERE username = '" + input + "'";
-- Attack: ' OR '1'='1
-- Result: SELECT * FROM users WHERE username = '' OR '1'='1'
```

**Types**:
| Type | Technique | Detection |
|------|-----------|-----------|
| **In-band (Error-based)** | Provoke DB errors → extract info | WAF: Error patterns (ORA-, MySQL, Syntax error) |
| **In-band (Union-based)** | UNION SELECT to extract data | WAF: UNION SELECT patterns |
| **Blind (Boolean)** | True/False inference (no errors) | WAF: ' OR 1=1, ' AND 1=2 patterns |
| **Blind (Time-based)** | SLEEP/WAITFOR DELAY → timing | WAF: SLEEP(5), WAITFOR DELAY '0:0:5' |
| **Out-of-band (OOB)** | DNS/HTTP exfil (xp_cmdshell, LOAD_FILE) | DNS logs, Proxy (internal → external) |
| **Second-order** | Stored payload → triggered later | App logs (delayed execution) |

**Detection (WAF/Proxy)**:
```kql
// Common SQLi patterns
WebLogs
| where cs_uri_query has_any ("'", "\"", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "OR 1=1", "'--", "';--", "xp_cmdshell", "sp_executesql")
| or cs_uri_query matches regex @"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E|%53%45%4C%45%43%54)"
| where cs_method in ("GET", "POST")
| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
| where Count > 5
```

### 2. NoSQL Injection
**Mechanism**: MongoDB/DocumentDB operators in JSON input.
```javascript
// Vulnerable
db.users.find({ username: req.body.user, password: req.body.pass });
// Attack: { "username": "admin", "password": { "$gt": "" } }
// Result: Bypass auth
```
**Operators**: `$gt`, `$ne`, `$regex`, `$where`, `$exists`, `$nin`, `$in`
**Detection**: JSON payloads with MongoDB operators in API calls.

### 3. Command Injection (OS Command)
**Mechanism**: User input passed to system shell.
```python
# Vulnerable
os.system("ping " + user_input)
# Attack: 8.8.8.8; cat /etc/passwd
# Result: Ping + password file
```
**Payloads**: `;`, `&&`, `||`, `|`, `` `cmd` ``, `$(cmd)`, `\n`, `\r`
**Detection**: Shell metacharacters in input fields, WAF rules, EDR on web server.

### 4. LDAP Injection
**Mechanism**: User input in LDAP filter.
```java
// Vulnerable
String filter = "(uid=" + userInput + ")";
// Attack: *)(userPassword=*)
// Result: (uid=*)(userPassword=*)
```
**Detection**: LDAP metacharacters `(`, `)`, `*`, `&`, `|`, `!`, `=`, `~` in auth/search params.

### 5. XPath Injection
**Mechanism**: User input in XPath query.
```xml
// Vulnerable
/users/user[username='input' and password='input']
// Attack: ' or '1'='1
// Result: Bypass auth
```
**Detection**: XPath syntax (`'`, `"`, `or`, `and`, `//`, `/*`) in XML API params.

---

## 20.4 Cross-Site Scripting (XSS)

### Types
| Type | Mechanism | Impact | Detection |
|------|-----------|--------|-----------|
| **Reflected** | Payload in URL/param → reflected in response | Victim clicks malicious link | WAF: `<script>`, `javascript:`, `onerror=` in URL/query |
| **Stored** | Payload saved in DB → served to all viewers | Persistent, all visitors | App logs: Stored payload in DB fields (comments, profiles) |
| **DOM-based** | Client-side JS modifies DOM unsafely | No server interaction | Hard for WAF; CSP, CSP report-uri |
| **Mutated** | Browser mutates payload (encoding bypass) | Bypass filters | Hard; Browser behavior analysis |

### Common Payloads
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

### Detection (WAF/Proxy)
```kql
WebLogs
| where cs_uri_query has_any ("<script>", "javascript:", "onerror=", "onload=", "alert(", "document.cookie", "eval(", "onfocus=", "ontoggle=", "onmouseover=")
| or cs_uri_query matches regex @"(%3Cscript%3E|javascript%3A|onerror%3D|onload%3D|alert%28)"
| where cs_method in ("GET", "POST")
| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
| where Count > 5
```

---

## 20.5 Broken Access Control — BOLA / IDOR

### BOLA (Broken Object Level Authorization)
**Mechanism**: User accesses object they don't own via direct reference.
```
GET /api/orders/12345  → Returns order 12345 (attacker's)
GET /api/orders/12346  → Returns order 12346 (victim's!) — No authz check
```

### IDOR (Insecure Direct Object Reference)
**Mechanism**: Predictable identifiers (sequential IDs, UUIDs) without authorization.
```
/api/users/1001/profile
/api/users/1002/profile  → Other user's data
/api/documents/inv-2024-001.pdf
/api/documents/inv-2024-002.pdf  → Other invoice
```

### Detection
```kql
// Unusual access patterns: One user accessing many object IDs
ApiLogs
| where cs_uri_stem matches regex @"/api/.*/\d+"
| extend ObjectId = extract(@"/api/.*/(\d+)", 1, cs_uri_stem)
| summarize UniqueObjects=dcount(ObjectId), Requests=count() by c_ip, cs_username, cs_uri_stem, bin(TimeGenerated, 1h)
| where UniqueObjects > 20  // One user accessing many objects
```

---

## 20.6 Server-Side Request Forgery (SSRF)

### Mechanism
Server makes requests to attacker-controlled or internal destinations.
```python
# Vulnerable: User-supplied URL fetched by server
response = requests.get(user_supplied_url)
```

### Targets
| Target | URL | Impact |
|--------|-----|--------|
| **Cloud Metadata** | `http://169.254.169.254/latest/meta-data/` (AWS) | IAM credentials, Instance info |
| | `http://metadata.google.internal/computeMetadata/v1/` (GCP) | Service account tokens |
| | `http://169.254.169.254/metadata/instance` (Azure) | Managed identity tokens |
| **Internal Services** | `http://localhost:8080/admin` | Admin panels, Debug endpoints |
| | `http://internal-db:5432` | Database access |
| **Port Scanning** | `http://10.0.0.1:22`, `http://10.0.0.1:3306` | Internal reconnaissance |
| **File Protocol** | `file:///etc/passwd` | Local file read |

### Detection
```kql
// Outbound from web server to internal/metadata
WebLogs
| where cs_host in (web_server_ips)
| where cs_uri_query has_any ("169.254.169.254", "metadata.google.internal", "metadata.azure.com", "127.0.0.1", "localhost", "file://")
| or cs_referer has_any ("169.254.169.254", "metadata.", "127.0.0.1", "localhost")
| project TimeGenerated, c_ip, cs_host, cs_method, cs_uri_stem, cs_uri_query, cs_referer, sc_status
```

---

## 20.7 Deserialization / RCE

### Java (Apache Commons, Spring, etc.)
```java
// Vulnerable: ObjectInputStream.readObject()
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Gadget chain → RCE
```
**Gadget Chains**: CommonsCollections, Spring, JRE, JSON libraries (Jackson, Gson).

### .NET (BinaryFormatter, Json.NET, etc.)
```csharp
// Vulnerable
BinaryFormatter formatter = new BinaryFormatter();
Object obj = formatter.Deserialize(stream);  // TypeConfuseDelegate, etc.
```

### PHP (unserialize)
```php
// Vulnerable
unserialize($_COOKIE['data']);  // POP chains → RCE
```

### Python (pickle)
```python
# Vulnerable
pickle.loads(user_data)  # __reduce__ → RCE
```

### Detection
```kql
// Serialized payloads in traffic
WebLogs
| where cs_request_body has_any ("ACED0005", "rO0", "sr ", "java.lang", "System.Object", "pickle", "O:8:\"stdClass\"")
| or cs_uri_query has_any ("ACED0005", "rO0", "pickle")
| project TimeGenerated, c_ip, cs_host, cs_method, cs_uri_stem, cs_request_body
```

---

## 20.8 Authentication & Session Attacks

| Attack | Mechanism | Detection |
|--------|-----------|-----------|
| **Brute Force** | Many login attempts | 401/403 spikes, WAF rate limit |
| **Credential Stuffing** | Breached creds tried | High volume, many IPs, known breach lists |
| **Session Fixation** | Attacker sets victim's session ID | Same session ID before/after login |
| **Session Hijacking** | Steal session cookie (XSS, MITM) | Same session from different IP/UA |
| **JWT Attacks** | `alg: none`, Weak secret, Key confusion | JWT parsing errors, Invalid signatures |
| **OAuth/SSO Abuse** | Redirect URI manipulation, Token replay | Auth server logs, State parameter missing |

---

## 20.9 Web Security Headers — L1 Checklist

| Header | Purpose | Secure Value |
|--------|---------|--------------|
| **Content-Security-Policy (CSP)** | Prevent XSS/injection | `default-src 'self'; script-src 'self' 'nonce-xxx'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |
| **Strict-Transport-Security (HSTS)** | Force HTTPS | `max-age=31536000; includeSubDomains; preload` |
| **X-Frame-Options** | Prevent clickjacking | `DENY` |
| **X-Content-Type-Options** | Prevent MIME sniffing | `nosniff` |
| **Referrer-Policy** | Control referer leakage | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | Control browser features | `geolocation=(), microphone=(), camera=()` |
| **Cross-Origin-Opener-Policy (COOP)** | Isolate browsing context | `same-origin` |
| **Cross-Origin-Resource-Policy (CORP)** | Control resource loading | `same-origin` |
| **X-XSS-Protection** | Legacy XSS filter | `1; mode=block` (deprecated, use CSP) |

---

## 20.10 Web Security Logging — What L1 Needs

| Log Source | Key Fields | Retention |
|------------|------------|-----------|
| **WAF** | Timestamp, Client IP, Rule ID, Action (Block/Allow/Monitor), Attack Type, Payload, Request/Response | 90 days+ |
| **Proxy/Load Balancer** | Client IP, Host, Method, URL, Status, Bytes, Latency, User-Agent, TLS info | 90 days+ |
| **Web Server (IIS/Nginx/Apache)** | Client IP, Method, URL, Status, Referer, User-Agent, Server IP, Latency | 30-90 days |
| **Application** | User ID, Action, Object ID, Result, Business Context, IP, Session ID | 1 year+ |
| **Database Audit** | User, Query, Table, Rows Affected, Duration, Error | 1 year+ |
| **CDN** | Edge IP, Client IP, Cache Status, Status, Bytes, Latency, Country | 30 days |

---

## 20.11 Interview Questions for This Module

1. **What is the OWASP Top 10 and which are most relevant for L1 detection?**
   - A01 Broken Access Control, A03 Injection, A07 Auth Failures, A10 SSRF — detectable via WAF/Proxy/App logs.

2. **Explain the difference between Reflected, Stored, and DOM-based XSS.**
   - Reflected: Payload in request → reflected in response. Stored: Payload saved in DB → served later. DOM-based: Client-side JS modifies DOM unsafely.

3. **What is SQL Injection and how do you detect it in WAF/proxy logs?**
   - User input concatenated into SQL query. Detect: `'`, `UNION`, `SELECT`, `OR 1=1`, `xp_cmdshell`, `--` in query params/body.

4. **What is SSRF and what are the high-value targets?**
   - Server makes requests to attacker-controlled/internal targets. Targets: Cloud metadata (169.254.169.254), Internal services, Port scanning, File protocol.

5. **What is BOLA/IDOR and how do you detect it?**
   - Accessing objects without authorization via direct reference. Detect: One user accessing many object IDs sequentially.

6. **What are the critical security headers every web app should have?**
   - CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.

7. **How do you detect deserialization attacks in web traffic?**
   - Serialized payload signatures: Java (`ACED0005`/`rO0`), .NET (BinaryFormatter), PHP (`O:8`), Python (`pickle`) in request body/params.

8. **What is the difference between In-band and Blind SQL Injection?**
   - In-band: Results/errors returned in response (Error-based, Union-based). Blind: No direct output; Boolean (true/false) or Time-based (SLEEP).

9. **What logs should you collect for web security and what are key fields?**
   - WAF (Rule ID, Action, Payload), Proxy (Client IP, Host, Method, URL, Status, UA), App (User ID, Action, Object, Business Context), DB (User, Query, Table).

10. **How does JWT authentication work and what attacks exist?**
    - Header.Payload.Signature. Attacks: `alg: none`, Weak secret (brute force), Key confusion (RS256→HS256), Token replay, Missing expiration.

---

## 20.12 Study Checklist for Module 20

- [ ] List OWASP Top 10 2021 with detection relevance
- [ ] Explain 5 SQLi types (Error, Union, Boolean Blind, Time Blind, OOB)
- [ ] Detect NoSQLi, Command Injection, LDAPi, XPath Injection patterns
- [ ] Distinguish Reflected, Stored, DOM, Mutated XSS with payloads
- [ ] Explain BOLA vs IDOR with detection query
- [ ] List 8 SSRF targets (Cloud metadata, Internal services, Port scan, File protocol)
- [ ] Identify deserialization payloads (Java, .NET, PHP, Python)
- [ ] List 6 Auth/Session attacks with detection
- [ ] Recite 9 critical security headers with secure values
- [ ] Define web log sources with key fields and retention
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 21 — Linux Security*