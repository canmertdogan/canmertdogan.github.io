# Module 16: Phishing and Email Security

**Priority: P0 — #1 initial access vector. L1 investigates phishing daily.**

---

## 16.1 Phishing Taxonomy

| Type | Target | Method | Sophistication |
|------|--------|--------|----------------|
| **Bulk Phishing** | Mass (millions) | Generic lure (invoice, package, password reset) | Low |
| **Spear Phishing** | Specific individual/org | Personalized (name, role, project, recent event) | Medium-High |
| **Whaling** | C-suite / VIP | Highly tailored, business context | Very High |
| **Business Email Compromise (BEC)** | Finance/HR/Exec | Impersonation, no malware, social engineering | High |
| **Clone Phishing** | Previous legitimate email recipient | Clone legit email, swap link/attachment | Medium |
| **Vishing (Voice)** | Phone | Caller ID spoof, urgency, authority impersonation | Medium |
| **Smishing (SMS)** | Mobile | Short links, urgency, 2FA codes | Medium |
| **QR Phishing (Quishing)** | Mobile | QR code in email/physical → phishing site | Emerging |
| **Consent Phishing** | OAuth/App consent | Malicious app requests permissions (Graph, Gmail) | High |

---

## 16.2 Email Anatomy — Headers & Body

### Critical Headers for Investigation
| Header | Purpose | Phishing Indicator |
|--------|---------|-------------------|
| **From** | Displayed sender | Spoofed display name, mismatched address |
| **Return-Path** | Bounce address (SMTP MAIL FROM) | **True sender domain** (check SPF) |
| **Reply-To** | Where replies go | Different from From (reply hijack) |
| **Received** | Hop-by-hop path (bottom = origin) | **Trace source IP, hops, delays** |
| **Authentication-Results** | SPF/DKIM/DMARC verdict | `spf=fail`, `dkim=fail`, `dmarc=fail` |
| **DKIM-Signature** | Cryptographic signature | `d=domain`, `s=selector`, `bh=hash`, `b=sig` |
| **ARC-Authentication-Results** | Forwarding chain auth | Preserves auth through forwards |
| **X-Originating-IP** | Client IP (some providers) | Geo mismatch, known bad |
| **X-Mailer / User-Agent** | Sending software | Bulk mailers, scripts, unusual |
| **Message-ID** | Unique identifier | Pattern analysis, tracking |
| **Date** | Timestamp | Timezone mismatch, future/past |
| **Subject** | Social engineering hook | Urgency, fear, curiosity, reward |
| **List-Unsubscribe** | Mailing list header | Often absent in phishing |

### Received Header Parsing (Bottom-Up)
```
Received: from mail.example.com (mail.example.com [192.0.2.1])
    by mx.recipient.com (Postfix) with ESMTPS id ABC123
    for <victim@recipient.com>; Mon, 15 Jan 2024 10:30:00 +0000 (UTC)
    (version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256)
```
- **Bottom-most** = Original sender's mail server
- **Each hop** adds a Received header
- **Analyze**: Source IP, HELO/EHLO name, TLS version/cipher, delay between hops

---

## 16.3 Email Authentication — SPF, DKIM, DMARC

### SPF (Sender Policy Framework) — RFC 7208
| Mechanism | Meaning |
|-----------|---------|
| `v=spf1` | Version |
| `ip4:192.0.2.0/24` | Allowed IPv4 range |
| `ip6:2001:db8::/32` | Allowed IPv6 range |
| `include:_spf.google.com` | Include another domain's SPF |
| `a` / `mx` | Domain's A/MX records |
| `~all` | **SoftFail** (accept but mark) |
| `-all` | **HardFail** (reject) |
| `?all` | Neutral |
| `+all` | **Pass all (DANGEROUS)** |

**SPF Failure**: Sending IP not in authorized list → `spf=fail` (hardfail) or `spf=softfail`.

### DKIM (DomainKeys Identified Mail) — RFC 6376
| Tag | Meaning |
|-----|---------|
| `v=1` | Version |
| `a=rsa-sha256` | Algorithm |
| `d=example.com` | **Signing domain** |
| `s=selector1` | **Selector** (DNS: `selector1._domainkey.example.com`) |
| `h=from:to:subject:date` | **Signed headers** |
| `bh=base64hash` | Body hash |
| `b=base64signature` | Signature |

**DKIM Verification**: Retrieve public key from DNS → Verify signature matches body + signed headers.

### DMARC (Domain-based Message Authentication, Reporting, Conformance) — RFC 7489
| Tag | Meaning |
|-----|---------|
| `v=DMARC1` | Version |
| `p=none` / `quarantine` / `reject` | **Policy** (monitor / spam / reject) |
| `sp=quarantine` | Subdomain policy |
| `pct=100` | Percentage to apply |
| `rua=mailto:dmarc@example.com` | Aggregate reports (XML) |
| `ruf=mailto:dmarc-forensic@example.com` | Forensic reports (eml) |
| `adkim=r` / `s` | DKIM alignment (relaxed/strict) |
| `aspf=r` / `s` | SPF alignment (relaxed/strict) |

**DMARC Pass**: (SPF Pass + SPF Aligned) OR (DKIM Pass + DKIM Aligned).
**Alignment**: `From` domain == `Return-Path` domain (SPF) OR `From` domain == `d=` domain (DKIM).

---

## 16.4 Phishing Email Analysis Workflow

### Alert: "Phishing Email Delivered - Credential Harvesting"
```
1. EXTRACT EMAIL (EML/MSG) FROM GATEWAY / USER REPORT / SANDBOX
   - Gateway: Proofpoint, Mimecast, Cisco ESA, Microsoft Defender, Google
   - User Report: Phish alert button, forward to security@
   - Sandbox: Detonation results (URL clicks, attachment behavior)

2. PARSE HEADERS (Use: msgparser, emlx, Outlook, online tools)
   - From: "IT Support" <it-support@company-services.xyz>
   - Return-Path: <bounce@attacker-domain.com>
   - Reply-To: <credential-harvest@evil.com>
   - Received chain: 
     1. mx.recipient.com ← mail.attacker-domain.com [203.0.113.45]
     2. mail.attacker-domain.com ← localhost [127.0.0.1]
   - Authentication-Results: spf=fail (domain=attacker-domain.com), dkim=fail, dmarc=fail
   - X-Mailer: PHP/8.1.12 (not corporate mailer)

3. ANALYZE SENDER INFRASTRUCTURE
   - Source IP: 203.0.113.45
     - VT: 15/92 (phishing, bulk mailer)
     - AbuseIPDB: 89% confidence
     - ASN: AS12345 (Bulletproof Hosting)
     - Geo: Russia (corporate HQ in US)
   - Domain: attacker-domain.com
     - Registered: 2024-01-10 (5 days ago)
     - Registrar: Namecheap
     - NS: ns1.bulletproof-hosting.net
     - MX: mail.attacker-domain.com
   - Return-Path domain: attacker-domain.com (matches)

4. ANALYZE CONTENT
   - Subject: "URGENT: Password Expires Today - Action Required"
   - Body: HTML with corporate logo, "Click here to reset"
   - Links: 
     - `https://company-services.xyz/reset?token=xyz` → Redirects to `https://evil-phish-site.com/credential-harvest`
     - Link text: "Reset Password" (hover shows different URL)
   - Attachments: None (credential phishing)
   - Language: Urgency, threat of account loss, poor grammar

5. CHECK RECIPIENTS & SCOPE
   - To: 47 recipients (Finance, HR, IT)
   - CC/BCC: None
   - Delivery: 44 delivered, 3 blocked by gateway
   - Clicks: 12 users clicked (gateway URL rewrite logs)
   - Credentials Entered: 5 users (gateway sandbox / credential monitoring)

6. THREAT INTEL ENRICHMENT
   - Campaign: "Operation FinancePhish" (tracking since 2023)
   - Actor: FIN7 / Carbanak (financially motivated)
   - Infrastructure: Reused IPs/domains from previous campaigns
   - TTPs: Credential phishing → VPN access → Lateral → Ransomware

7. CLASSIFY & RESPOND
   - TRUE POSITIVE: Credential Phishing (T1566.002)
   - SEVERITY: P2 (credentials entered, VPN risk)
   - ACTIONS:
     - Block sender domain/IP at gateway/firewall/DNS
     - Reset passwords for 5 compromised users
     - Revoke sessions / MFA re-enroll
     - Search for VPN logins from compromised users (last 24h)
     - Notify affected users + managers
     - Update blocklists / TI platform
     - Escalate to L2 for VPN log review
```

---

## 16.5 Malicious Attachments — Analysis

| Type | Execution Vector | Detection |
|------|------------------|-----------|
| **Office Macro (.docm, .xlsm, .pptm)** | VBA / Excel 4.0 / XLM macros | EDR (Office → Script), AMSI, 4104, Gateway sandbox |
| **PDF** | JavaScript, Embedded exploit, Launch action | Gateway sandbox, PDF parser (pdfid, peepdf) |
| **Archive (.zip, .rar, .7z, .iso, .img)** | Bypass gateway (password-protected, nested) | Gateway (recursive extraction), EDR on extract |
| **HTML/HTM** | Redirect, credential form, local execution | Gateway (URL analysis), Browser isolation |
| **LNK/URL** | Shortcut to remote payload (WebDAV, SMB) | EDR (LNK parse), Sysmon EID 11/1 |
| **Executable (.exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .wsf, .msi)** | Direct execution | Gateway (block), EDR (hash, behavior) |
| **RTF** | CVE-2017-11882 (EQNEDT32), OLE objects | Gateway sandbox, EDR |

### Attachment Analysis Steps
```
1. HASH (SHA256) → VT, Internal, MalwareBazaar
2. FILE TYPE → `file` command, TrID (not extension!)
3. STRINGS → URLs, IPs, commands, registry, mutex
4. OFFICE → `olevba`, `oleid`, `msoffcrypto-tool` (VBA, XLM, encryption)
5. PDF → `pdfid`, `pdf-parser`, `peepdf` (JS, /Launch, /EmbeddedFiles)
6. ARCHIVE → Recursive extract → Repeat above
7. SANDBOX → Hybrid Analysis, Any.Run, Joe Sandbox, Cape, internal
   - Process tree, network, file drops, registry, MITRE tags
8. YARA → Custom rules (phishing kit, specific actors)
```

---

## 16.6 Malicious URLs — Analysis

### URL Structure Analysis
```
https://subdomain.evil-domain.com:8443/path/to/page?param=value#fragment
│       │                │           │    │                    │
│       │                │           │    │                    └── Fragment (client-side)
│       │                │           │    └── Query (data exfil, tracking)
│       │                │           └── Path (phishing kit directory)
│       │                └── Port (non-standard = suspicious)
│       └── Domain (registration, reputation, hosting)
└── Scheme (https = TLS, http = cleartext)
```

### URL Investigation
| Check | Tool/Method |
|-------|-------------|
| **Domain Age** | WHOIS (`whois`, `domaintools`, `securitytrails`) |
| **Registrar** | WHOIS (Namecheap, Porkbun, Njalla = bulletproof indicators) |
| **Name Servers** | `dig NS`, passive DNS (bulletproof hosting NS) |
| **IP / Hosting** | `dig A`, `whois IP`, ASN, VT, Shodan, Censys |
| **SSL Certificate** | `openssl s_client`, crt.sh, Censys (issuer, SAN, validity, self-signed) |
| **Redirect Chain** | `curl -L -v`, browser dev tools, URLScan.io |
| **Page Content** | `curl`, `wget`, URLScan.io screenshot, DOM analysis |
| **Phishing Kit** | Known kit signatures (filename patterns, directory structure, POST endpoint) |
| **Reputation** | VT, URLhaus, PhishTank, Google Safe Browsing, Cisco Talos, internal |

---

## 16.7 Business Email Compromise (BEC) — Special Handling

### BEC Types
| Type | Scenario | Key Indicator |
|------|----------|---------------|
| **CEO Fraud** | "Urgent wire transfer" from CEO to Finance | Spoofed display name, free email (Gmail), urgency |
| **Invoice Fraud** | "Updated bank details" from vendor | Legitimate vendor domain compromised or lookalike |
| **Payroll Diversion** | "Change my direct deposit" from employee | HR target, personal email reply-to |
| **Attorney Impersonation** | "Confidential legal matter" | Legal language, urgency, confidentiality |
| **Account Compromise** | Real internal account hacked → sends BEC | Auth logs (impossible travel), sent items |

### BEC Investigation Differences
- **No malware, no links, no attachments** — Pure social engineering
- **Focus**: Header analysis (Return-Path, Reply-To, SPF/DKIM/DMARC), sender verification
- **Action**: Call sender (out-of-band), verify with finance/vendor, check auth logs for account compromise
- **Escalation**: Immediate — Financial loss risk, legal/regulatory implications

---

## 16.8 Email Gateway & Security Stack

| Layer | Technology | Function |
|-------|------------|----------|
| **MX / Perimeter** | Proofpoint, Mimecast, Cisco ESA, Microsoft Defender, Google, Barracuda | Spam, malware, phishing, DLP, encryption |
| **Post-Delivery** | Microsoft Defender for Office 365, Gmail Security, Avanan, GreatHorn | Click-time protection, mailbox intelligence, auto-remediation |
| **User Reporting** | Phish Alert Button (KnowBe4, Cofense, Hoxhunt, Microsoft) | Human sensor, rapid triage |
| **Sandbox** | Hybrid Analysis, Any.Run, Joe Sandbox, Cape, Internal (Cuckoo, CAPE) | Attachment/URL detonation |
| **URL Rewrite / Click-Time** | Gateway rewrites URLs → Proxy → Reputation check at click | Blocks delayed weaponization |
| **DMARC Enforcement** | `p=reject` / `quarantine` + Aggregate/Forensic reports | Domain protection, visibility |
| **Brand Indicators (BIMI)** | Verified logo in inbox (requires DMARC enforcement) | User trust, anti-spoof |

---

## 16.9 Interview Questions for This Module

1. **What are the three email authentication protocols and what does each verify?**
   - SPF: Sending IP authorized for domain (Return-Path). DKIM: Cryptographic signature of headers/body (d= domain). DMARC: Policy + alignment (From vs Return-Path/d=) + reporting.

2. **How do you identify the true sending IP from email headers?**
   - Read Received headers bottom-up. The bottom-most Received header from your mail server shows the connecting IP (source of the email).

3. **What is the difference between SPF SoftFail (`~all`) and HardFail (`-all`)?**
   - SoftFail: Accept but mark suspicious (spam folder). HardFail: Reject outright. DMARC treats both as "fail" for alignment.

4. **A phishing email has `From: CEO <ceo@company.com>` but `Return-Path: <bounce@attacker.com>` and `Reply-To: <hr@evil.com>`. What does this indicate?**
   - Display name spoofing (CEO), true sender is attacker.com (Return-Path), replies go to attacker (Reply-To). SPF/DKIM/DMARC will likely fail.

5. **What tools do you use to analyze a malicious Office document?**
   - `olevba` (VBA macros), `oleid` (OLE info), `msoffcrypto-tool` (decrypt), `oletools` suite, sandbox (Hybrid Analysis, Any.Run), AMSI/4104 logs.

6. **How do you investigate a malicious URL without clicking it?**
   - `curl -L -v` for redirect chain, `openssl s_client` for cert, `whois`/`dig` for domain/IP, VT/URLhaus/URLScan.io for reputation/screenshot, passive DNS.

7. **What makes BEC different from typical phishing and how do you investigate it?**
   - No malware/links/attachments. Pure social engineering. Investigate headers (Return-Path, Reply-To, auth results), verify sender out-of-band, check auth logs for account compromise.

8. **What is DMARC alignment and why does it matter?**
   - SPF Alignment: From domain == Return-Path domain. DKIM Alignment: From domain == d= domain. DMARC passes if either aligns + passes. Prevents spoofing where auth passes but From is forged.

8. **What is "URL Rewriting" in email gateways and why is it effective?**
   - Gateway rewrites all URLs to point through its proxy. At click time, proxy checks reputation. Catches delayed weaponization (clean at delivery, malicious later).

9. **What is a "Consent Phishing" attack?**
   - Malicious OAuth app requests permissions (Graph API: Mail.Read, Files.ReadWrite). User consents → attacker gets token → accesses data without credentials.

10. **What are the key indicators of a QR code phishing (Quishing) attack?**
    - QR code in email body (image), no visible URL, directs to phishing site when scanned. Mobile users bypass gateway URL scanning. Analyze: extract QR (zbarimg), check URL.

---

## 16.10 Study Checklist for Module 16

- [ ] Classify 9 phishing types with target/method/sophistication
- [ ] Parse email headers: From, Return-Path, Reply-To, Received chain, Authentication-Results, DKIM-Signature
- [ ] Explain SPF, DKIM, DMARC mechanisms, tags, and alignment
- [ ] Execute phishing analysis workflow (headers → infrastructure → content → recipients → TI → classify)
- [ ] Analyze 7 malicious attachment types with tools (olevba, pdfid, strings, sandbox)
- [ ] Investigate URLs: domain age, registrar, NS, IP/hosting, cert, redirect chain, content, reputation
- [ ] Differentiate BEC types and investigation approach (no malware, verify out-of-band)
- [ ] Map email security stack layers (MX, Post-delivery, User reporting, Sandbox, URL rewrite, DMARC, BIMI)
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 17 — Threat Intelligence*