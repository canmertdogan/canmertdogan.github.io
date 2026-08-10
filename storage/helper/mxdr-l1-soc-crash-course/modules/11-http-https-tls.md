# Module 11: HTTP/HTTPS/TLS

**Priority: P1 — Web traffic = majority of alerts. L1 must read proxy logs, understand TLS.**

---

## 11.1 HTTP Fundamentals

### HTTP Request/Response Model
```
Client                                    Server
   │                                          │
   ├─ REQUEST ──────────────────────────────►│
   │  GET /api/users HTTP/1.1                 │
   │  Host: api.example.com                   │
   │  User-Agent: Mozilla/5.0...              │
   │  Authorization: Bearer <token>           │
   │  Cookie: session=abc123                  │
   │  Content-Type: application/json          │
   │                                          │
   │◄─ RESPONSE ─────────────────────────────┤
   │  HTTP/1.1 200 OK                         │
   │  Content-Type: application/json          │
   │  Set-Cookie: session=xyz789; Secure      │
   │  X-Frame-Options: DENY                   │
   │                                          │
   │  {"users": [...]}                        │
```

### HTTP Methods (Verbs)
| Method | Purpose | Idempotent | Body Allowed | SOC Relevance |
|--------|---------|------------|--------------|---------------|
| **GET** | Retrieve resource | Yes | No | **Recon, data exfil (params in URL)** |
| **POST** | Submit data / Create | No | Yes | **Login, upload, C2, web shells** |
| **PUT** | Replace resource | Yes | Yes | File upload, config change |
| **DELETE** | Remove resource | Yes | No | Data destruction |
| **HEAD** | Headers only | Yes | No | Recon, scanning |
| **OPTIONS** | Allowed methods | Yes | No | CORS preflight, recon |
| **PATCH** | Partial update | No | Yes | API abuse |
| **CONNECT** | Tunnel (HTTPS proxy) | No | No | **Proxy tunneling, C2** |
| **TRACE** | Echo request | Yes | No | **XST (Cross-Site Tracing)** |

### HTTP Status Codes
| Code | Category | Meaning | SOC Relevance |
|------|----------|---------|---------------|
| **1xx** | Informational | Continue, Switching Protocols | Upgrade attacks |
| **200** | Success | OK | Normal |
| **201** | Success | Created | Upload success |
| **204** | Success | No Content | API, C2 heartbeat |
| **301** | Redirect | Moved Permanently | Phishing, SEO poisoning |
| **302** | Redirect | Found (Temporary) | **Phishing, open redirect** |
| **304** | Redirect | Not Modified | Caching |
| **307/308** | Redirect | Temporary/Permanent (preserve method) | |
| **400** | Client Error | Bad Request | Malformed, fuzzing |
| **401** | Client Error | **Unauthorized** (auth required) | **Brute force, credential stuffing** |
| **403** | Client Error | **Forbidden** (auth known, no perms) | **Access control testing, WAF block** |
| **404** | Client Error | Not Found | **Recon, directory traversal, scanning** |
| **405** | Client Error | Method Not Allowed | API abuse |
| **429** | Client Error | Too Many Requests | **Rate limiting, DoS** |
| **500** | Server Error | Internal Server Error | **Exploit crash, WAF bypass** |
| **502** | Server Error | Bad Gateway | Proxy issues |
| **503** | Server Error | Service Unavailable | **DoS, maintenance** |
| **504** | Server Error | Gateway Timeout | |

### HTTP Headers — Security Critical
| Header | Direction | Purpose | SOC Relevance |
|--------|-----------|---------|---------------|
| **Host** | Request | Target domain (virtual hosting) | **Host header injection** |
| **User-Agent** | Request | Client identifier | **Anomalous UA, scanner signatures** |
| **Referer** | Request | Previous page | **CSRF, tracking, leak** |
| **Origin** | Request | CORS origin | **CORS misconfig** |
| **Authorization** | Request | Credentials (Basic, Bearer, etc.) | **Token leakage, credential theft** |
| **Cookie** | Request | Session/state | **Session hijacking, fixation** |
| **Set-Cookie** | Response | Set client cookie | **Secure/HttpOnly/SameSite flags** |
| **Content-Type** | Both | MIME type | **Upload validation, XSS** |
| **Content-Length** | Both | Body size | **Smuggling, truncation** |
| **Transfer-Encoding** | Both | Chunked, gzip | **Request smuggling** |
| **X-Forwarded-For** | Request | Original client IP (proxy) | **IP spoofing, geo bypass** |
| **X-Forwarded-Proto** | Request | Original protocol | **SSL stripping detection** |
| **Server** | Response | Server software/version | **Recon, version disclosure** |
| **X-Powered-By** | Response | Framework | **Recon** |
| **Location** | Response | Redirect target | **Open redirect, phishing** |

### Security Headers (Response)
| Header | Purpose | Secure Value |
|--------|---------|--------------|
| **Strict-Transport-Security (HSTS)** | Force HTTPS | `max-age=31536000; includeSubDomains; preload` |
| **Content-Security-Policy (CSP)** | Prevent XSS/injection | `default-src 'self'; script-src 'self'...` |
| **X-Frame-Options** | Prevent clickjacking | `DENY` or `SAMEORIGIN` |
| **X-Content-Type-Options** | Prevent MIME sniffing | `nosniff` |
| **Referrer-Policy** | Control referer leakage | `strict-origin-when-cross-origin` |
| **Permissions-Policy** | Control browser features | `geolocation=(), microphone=()` |
| **Cross-Origin-Opener-Policy (COOP)** | Isolate browsing context | `same-origin` |
| **Cross-Origin-Resource-Policy (CORP)** | Control resource loading | `same-origin` |

---

## 11.2 HTTPS & TLS — Encryption in Transit

### TLS Handshake (TLS 1.2)
```
Client                                    Server
   │                                          │
   ├─ ClientHello ──────────────────────────►│
   │  • Version (TLS 1.2)                     │
   │  • Random (32 bytes)                     │
   │  • Session ID                            │
   │  • Cipher Suites (priority order)        │
   │  • Compression Methods                   │
   │  • Extensions: SNI, ALPN, etc.           │
   │                                          │
   │◄─ ServerHello ──────────────────────────┤
   │  • Version                               │
   │  • Random                                │
   │  • Session ID                            │
   │  • **Cipher Suite** (selected)           │
   │  • Compression                           │
   │  • Extensions                            │
   │                                          │
   │◄─ Certificate ──────────────────────────┤
   │  • X.509 Certificate Chain               │
   │                                          │
   │◄─ ServerKeyExchange (if DHE/ECDHE) ─────┤
   │  • DH Parameters + Signature             │
   │                                          │
   │◄─ CertificateRequest (optional) ────────┤
   │  • Client cert types, CAs                │
   │                                          │
   │◄─ ServerHelloDone ──────────────────────┤
   │                                          │
   ├─ ClientKeyExchange ────────────────────►│
   │  • Pre-Master Secret (encrypted)         │
   │                                          │
   ├─ CertificateVerify (if client cert) ────►│
   │                                          │
   ├─ ChangeCipherSpec ─────────────────────►│
   ├─ Finished (encrypted) ─────────────────►│
   │                                          │
   │◄─ ChangeCipherSpec ─────────────────────┤
   │◄─ Finished (encrypted) ─────────────────┤
   │                                          │
   │         ENCRYPTED APPLICATION DATA       │
```

### TLS 1.3 Handshake (Simplified, Faster)
```
Client                                    Server
   │                                          │
   ├─ ClientHello ──────────────────────────►│
   │  • Version (TLS 1.3)                     │
   │  • Random                                │
   │  • Cipher Suites (AEAD only)             │
   │  • Key Shares (ECDHE)                    │
   │  • Supported Versions                    │
   │  • **SNI** (encrypted in 1.3!)           │
   │                                          │
   │◄─ ServerHello ──────────────────────────┤
   │  • Key Share                             │
   │  • Certificate (encrypted!)              │
   │  • CertificateVerify                     │
   │  • Finished                              │
   │                                          │
   ├─ Finished ─────────────────────────────►│
   │                                          │
   │         ENCRYPTED APPLICATION DATA       │
```

**Key TLS 1.3 Changes**: 
- 1-RTT handshake (vs 2-RTT in 1.2)
- Encrypted Server Certificate (privacy)
- Removed weak ciphers (RSA key exchange, CBC, RC4, SHA1)
- Only AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- 0-RTT resumption (replay risk)

### Cipher Suite Naming
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
│       │      │       │        │      │
│       │      │       │        │      └── PRF (HMAC-SHA384)
│       │      │       │        └──────── Auth Encryption (AES-256-GCM)
│       │      │       └──────────────── Bulk Encryption
│       │      └──────────────────────── Auth (RSA cert)
│       └────────────────────────────── Key Exchange (ECDHE)
└───────────────────────────────────── Protocol
```

**Preferred (TLS 1.2+)**:
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030)
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F)
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C)

**Deprecated/Weak**:
- `TLS_RSA_WITH_AES_256_CBC_SHA` (no forward secrecy)
- `TLS_RSA_WITH_RC4_128_SHA` (RC4 broken)
- `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (3DES sweet32)
- Any with `CBC` (Lucky13, POODLE)
- Any with `SHA` (not SHA256/384)

---

## 11.3 TLS Certificates — X.509

### Certificate Fields
| Field | Description |
|-------|-------------|
| **Version** | v3 (supports extensions) |
| **Serial Number** | Unique per CA |
| **Signature Algorithm** | e.g., `sha256WithRSAEncryption` |
| **Issuer** | CA DN (CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US) |
| **Validity** | Not Before / Not After |
| **Subject** | Entity DN (CN=example.com, O=Example Inc, L=City, C=US) |
| **Subject Public Key Info** | Algorithm + Public Key |
| **Extensions** | **Critical for security** |

### Critical Extensions
| Extension | Purpose | SOC Check |
|-----------|---------|-----------|
| **Subject Alternative Name (SAN)** | Additional DNS names/IPs | **Validates hostname** |
| **Key Usage** | Key purpose | Digital Signature, Key Encipherment |
| **Extended Key Usage (EKU)** | Specific uses | Server Auth (1.3.6.1.5.5.7.3.1), Client Auth |
| **Basic Constraints** | CA or End-Entity | `CA:FALSE` for leaf certs |
| **CRL Distribution Points** | Revocation check URL | |
| **Authority Information Access (AIA)** | OCSP responder, CA issuer | |
| **Certificate Transparency (SCT)** | CT log proof | **Required for public certs** |

### Certificate Validation (Client Side)
1. **Trust Chain**: Leaf → Intermediate(s) → Root (in OS/Browser trust store)
2. **Signature Verification**: Each cert signed by parent's private key
3. **Validity Period**: Now between NotBefore and NotAfter
4. **Revocation**: CRL / OCSP (soft-fail common)
5. **Hostname Match**: SNI/URL hostname in Subject CN or SAN
6. **Key Usage**: Server Auth EKU present
7. **Basic Constraints**: Not a CA (unless pathlen allows)

### Certificate Types
| Type | Validation | Use Case |
|------|------------|----------|
| **DV (Domain Validated)** | Email/DNS/HTTP challenge | Most websites, automation (Let's Encrypt) |
| **OV (Organization Validated)** | Business identity verified | Corporate sites |
| **EV (Extended Validation)** | Rigorous legal verification | Banks, high-value (green bar deprecated) |
| **Wildcard** | `*.example.com` | Subdomains |
| **Multi-Domain (SAN)** | Multiple names in one cert | Microservices, CDN |
| **Self-Signed** | No CA | Internal, dev, **malware C2** |
| **Code Signing** | Sign executables | Software distribution |

---

## 11.4 TLS Visibility for SOC

### The Encryption Problem
```
Without Decryption:                    With Decryption (SSL Inspection):
┌─────────────────────┐                ┌─────────────────────┐
│ Client ──────────► Server             │ Client ───► Proxy ───► Server
│       TLS 1.2                        │       TLS 1.2   TLS 1.2
│       🔒 Encrypted                   │       🔓 Decrypt  🔓 Decrypt
│       ❌ No payload                  │       ✅ Full HTTP  ✅ Full HTTP
│       ✅ JA3, SNI, Cert              │       ✅ JA3, SNI   ✅ JA3, SNI
└─────────────────────┘                └─────────────────────┘
```

### What You CAN See Without Decryption
| Metadata | Source | Value |
|----------|--------|-------|
| **SNI (Server Name Indication)** | ClientHello | Target domain (plaintext in 1.2, encrypted in 1.3 ECH) |
| **JA3 / JA3S Fingerprint** | ClientHello / ServerHello | **Client/Server TLS fingerprint** (identify tools, malware) |
| **Certificate** | Server Certificate | Subject, Issuer, SAN, Validity, Public Key, Extensions |
| **Cipher Suite** | ServerHello | Negotiated encryption (weak/strong) |
| **TLS Version** | ClientHello/ServerHello | 1.0/1.1/1.2/1.3 |
| **ALPN** | ClientHello | Application protocol (h2, http/1.1) |
| **Flow Metadata** | NetFlow/Zeek | Volume, duration, timing, direction |

### JA3 / JA3S — TLS Fingerprinting
**JA3 (Client)**: MD5 of concatenated ClientHello fields:
```
TLS Version, Cipher Suites, Extensions, Elliptic Curves, Elliptic Curve Formats
Example: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-255,0-11-10-35-16-5-13-18-51-45-43-27-21,29-23-24,0
→ JA3: ae4edc6faf64d08308082ad26be60767  (Chrome)
```

**JA3S (Server)**: Same for ServerHello.

**Use Cases**:
- Identify malware (Cobalt Strike, Meterpreter, custom tools)
- Detect anomalous clients (scripts, scanners)
- Cluster C2 infrastructure
- Bypass User-Agent spoofing

---

## 11.5 Proxy Logs — SOC Gold Mine

### Common Proxy Log Format (Squid/BlueCoat/Zscaler)
```
timestamp  client_ip  username  auth_method  request_method  request_url  response_code  response_size  mime_type  referer  user_agent  category  action  threat_score
```

### Key Fields for Investigation
| Field | Value |
|-------|-------|
| **timestamp** | UTC, microsecond precision |
| **client_ip** | Source (pre-NAT or post-NAT) |
| **username** | Authenticated user (AD/SAML) |
| **request_method** | GET, POST, CONNECT, etc. |
| **request_url** | Full URL (path + query) |
| **response_code** | HTTP status |
| **response_size** | Bytes returned |
| **mime_type** | Content-Type |
| **referer** | Previous page |
| **user_agent** | Client software |
| **category** | URL categorization (Malware, Phishing, Social Media, etc.) |
| **action** | ALLOW, BLOCK, MONITOR, SCAN |
| **threat_score** | Vendor risk score (0-100) |
| **dlp_trigger** | Data loss prevention match |
| **sandbox_verdict** | File sandbox result |

---

## 11.6 HTTP/HTTPS Attack Patterns — Detection

### 1. Web Shell Detection
```kql
ProxyLogs
| where cs_method in ("POST", "PUT")
| where cs_uri_stem has_any (".php", ".jsp", ".asp", ".aspx", ".cfm", ".pl", ".py")
| where cs_uri_query has_any ("cmd=", "exec=", "shell=", "system=", "passthru=", "eval(", "assert(")
| summarize Count=count(), Commands=make_set(cs_uri_query) by c_ip, cs_host, cs_uri_stem, bin(TimeGenerated, 1h)
| where Count > 5
```

### 2. SQL Injection in URL/Body
```kql
ProxyLogs
| where cs_uri_query has_any ("'", "\"", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "OR 1=1", "'--", "';--")
| or cs_uri_query matches regex @"(%27|%22|%3B|%2D%2D|%55%4E%49%4F%4E)"
| summarize Count=count(), Payloads=make_set(cs_uri_query) by c_ip, cs_host, bin(TimeGenerated, 1h)
```

### 3. C2 over HTTP/HTTPS
```kql
ProxyLogs
| where cs_method in ("GET", "POST")
| where cs_useragent has_any ("python-requests", "curl", "Wget", "Go-http-client", "axios", "okhttp")
| where cs_uri_stem matches regex @"(/api/|/v1/|/v2/|/cmd|/task|/beacon|/heartbeat)"
| summarize Count=count(), UAs=make_set(cs_useragent), URIs=make_set(cs_uri_stem) by c_ip, cs_host, bin(TimeGenerated, 1h)
| where Count > 20
```

### 4. Data Exfiltration (Large Uploads)
```kql
ProxyLogs
| where cs_method in ("POST", "PUT")
| where sc_bytes > 10485760  // > 10MB response (download)
| or cs_bytes > 10485760     // > 10MB request (upload)
| where cs_host !in ("known-cdn.com", "office365.com", "googleapis.com")
| summarize TotalUp=sum(cs_bytes), TotalDown=sum(sc_bytes), Count=count() by c_ip, cs_host, username, bin(TimeGenerated, 1h)
| where TotalUp > 52428800  // > 50MB uploaded in hour
```

### 5. Credential Phishing / Stuffing
```kql
ProxyLogs
| where cs_uri_stem has_any ("/login", "/signin", "/auth", "/wp-login", "/admin")
| where cs_method == "POST"
| where sc_status in (200, 302, 401, 403)
| summarize Attempts=count(), Success=countif(sc_status in (200, 302)), Failures=countif(sc_status in (401, 403)) 
  by c_ip, cs_host, username, bin(TimeGenerated, 5m)
| where Attempts > 20 or (Failures > 10 and Success == 0)
```

---

## 11.7 Interview Questions for This Module

1. **What are the common HTTP methods and which are idempotent?**
   - GET, HEAD, OPTIONS, PUT, DELETE are idempotent. POST, PATCH are not.

2. **Explain the difference between 301, 302, 307, 308 redirects.**
   - 301: Permanent (cache). 302: Temporary (may change method to GET). 307: Temporary (preserve method). 308: Permanent (preserve method).

3. **What is the TLS 1.2 handshake flow?**
   - ClientHello → ServerHello + Certificate + ServerKeyExchange + ServerHelloDone → ClientKeyExchange + ChangeCipherSpec + Finished → ChangeCipherSpec + Finished.

4. **What are the key differences between TLS 1.2 and TLS 1.3?**
   - 1.3: 1-RTT handshake, encrypted cert, only AEAD ciphers, removed RSA key exchange/CBC/RC4/SHA1, 0-RTT resumption, SNI encryption (ECH).

5. **What is JA3 and how is it used in SOC?**
   - TLS client fingerprint (MD5 of ClientHello parameters). Identifies tools (Cobalt Strike, browsers, scripts) regardless of User-Agent.

6. **What certificate extensions are critical for validation?**
   - SAN (hostname), Key Usage (Digital Signature, Key Encipherment), EKU (Server Auth), Basic Constraints (CA:FALSE), CRL/OCSP (AIA), CT (SCT).

7. **What can you see in encrypted HTTPS traffic without decryption?**
   - SNI (1.2), JA3/JA3S, Certificate (Subject, Issuer, SAN, Validity), Cipher Suite, TLS Version, ALPN, Flow metadata (volume, timing).

7. **What headers indicate a potential web shell?**
   - POST to script extensions (.php, .jsp, .asp) with query params like `cmd=`, `exec=`, `shell=`, or suspicious User-Agents (python, curl, Go).

8. **How do you detect credential stuffing in proxy logs?**
   - High volume POSTs to login endpoints from single IP, mix of 401/403 failures with occasional 200/302 success, anomalous User-Agents.

9. **What is the CONNECT method used for?**
   - HTTPS proxy tunneling. Establishes TCP tunnel through proxy for encrypted traffic.

10. **What security headers should be present in HTTP responses?**
    - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP.

---

## 11.8 Study Checklist for Module 11

- [ ] List HTTP methods, idempotency, body allowance
- [ ] Recite status codes by category (1xx-5xx) with SOC relevance
- [ ] Identify critical request/response headers
- [ ] Draw TLS 1.2 and 1.3 handshake flows
- [ ] Parse cipher suite names
- [ ] Explain X.509 certificate fields and extensions
- [ ] Describe certificate validation chain
- [ ] List visible TLS metadata without decryption
- [ ] Calculate/interpret JA3 fingerprints
- [ ] Write KQL for: Web shell, SQLi, C2, Exfil, Credential stuffing
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 12 — Network Traffic Analysis*