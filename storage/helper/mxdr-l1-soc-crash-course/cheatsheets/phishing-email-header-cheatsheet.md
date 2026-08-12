# Phishing & Email Header Analysis Cheat Sheet for SOC Analysts

**Priority: P1 — Phishing is the #1 initial access vector; the headers are your fastest way to prove spoofing, trace the real sender, and stop the incident before payload detonation.**

---

## Where to Find Raw Headers

The goal is to get the **full raw header block** — not the friendly display. Copy it into a header analyzer (MXToolbox, Google Admin Toolbox Messageheader, Kaiten, or a local `msgparser`).

| Client | How to View Headers |
|--------|---------------------|
| **Outlook (Windows)** | Double-click email → **File → Properties** → `Internet headers:` box |
| **Outlook (Web / OWA)** | Click email → `...` (More actions) → **View → View message details** |
| **Gmail (Web)** | Open email → `...` (three dots) → **Show original** → copy the text |
| **M365 / Exchange (EAC)** | Mail flow → Message trace → view details → copy header, or `Get-MessageTrace` / `Get-MessageTraceDetail` in EXO PowerShell |
| **Thunderbird** | Open email → `View → Message Source` (Ctrl+U) |

**L1 Rule**: Always copy the header **and** save the original `.eml`/`.msg` into the ticket. Header analyzers re-render hop-by-hop and often compute SPF/DKIM/DMARC on the spot — but read the raw `Authentication-Results` yourself too.

---

## Header Anatomy — What Each Line Tells You

| Header | What It Is | Phishing Indicator |
|--------|------------|--------------------|
| **Return-Path** | Bounce address (SMTP `MAIL FROM` / envelope sender) | **True sender domain** — SPF is checked against this, not `From` |
| **Received** (chain) | Hop-by-hop path; **read bottom-up** | Trace source IP, hops, time delays |
| **Message-ID** | Unique message identifier | Pattern analysis, tracking, reused IDs |
| **From** | Displayed sender | Spoofed display name, mismatched address |
| **Sender** | Actual mailbox of the sender (mailing lists) | Different from `From` = list/impersonation |
| **Reply-To** | Where replies go | Different from `From` = **reply hijack** |
| **To / Cc / Bcc** | Recipients | Unusual bulk distribution lists |
| **Date** | Timestamp | Timezone mismatch, future/past dates |
| **Subject** | Social-engineering hook | Urgency, fear, reward, credential language |
| **X-Originating-IP** | Client IP (some providers) | Geo mismatch, known-bad IP |
| **X-Mailer / User-Agent** | Sending software | Scripts, PHP, bulk mailers instead of corporate clients |
| **MIME-Version / Content-Type / Content-Transfer-Encoding** | Body structure | `multipart/mixed` with attachments, HTML-only body |
| **DKIM-Signature** | Crypto signature | `d=` domain, `s=` selector, `bh=` body hash, `b=` signature |
| **List-Unsubscribe** | Mailing-list header | Usually absent in phishing |
| **ARC-Authentication-Results** | Forwarding-chain auth | Preserves auth through forwards — read it when SPF/DKIM/DMARC look odd after forwarding |

### Reading the Received Chain (Bottom-Up)

The **bottom-most** Received line is written by the first server that touched the mail — it shows the true origin. Each relay adds its own line on top.

```diff
+Received: from mx.recipient.com (mx.recipient.com [192.0.2.10])
+    by mail.recipient.com (Postfix) with ESMTPS id ABC123
+    for <victim@recipient.com>; Mon, 15 Jan 2024 10:30:05 +0000 (UTC)

+Received: from mail.attacker-domain.com (mail.attacker-domain.com [203.0.113.45])
+    by mx.recipient.com (Postfix) with ESMTPS id XYZ789
+    for <victim@recipient.com>; Mon, 15 Jan 2024 10:30:00 +0000 (UTC)
+    (version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256)

-Return-Path: <bounce@attacker-domain.com>
-From: "IT Support" <it-support@company-services.xyz>
-Reply-To: <credential-harvest@evil.com>
-Subject: URGENT: Password Expires Today - Action Required
```

- **Bottom = origin**: `mail.attacker-domain.com [203.0.113.45]` is the true sending server.
- **Look at**: HELO/EHLO name vs. resolved IP, TLS version/cipher, and **delay between hops** (large gaps = relaying/queueing abuse).
- **If the `From` domain and the bottom Received IP do not match the real corporate infrastructure — treat as spoofed.**

---

## SPF — Sender Policy Framework (RFC 7208)

SPF verifies that the **envelope sender / Return-Path domain** authorizes the connecting IP to send its mail. Check the `Received-SPF:` header.

| Result | Meaning | Action |
|--------|---------|--------|
| `spf=pass` | IP is authorized for the Return-Path domain | Normal |
| `spf=fail` | IP not authorized (**HardFail**, `-all`) | **Malicious / spoofed** |
| `spf=softfail` | IP not authorized but `~all` (accept but mark) | **Suspicious** — DMARC treats as fail |
| `spf=neutral` | `?all` — no verdict | Inconclusive |
| `spf=permerror` | SPF record malformed / lookup limit exceeded | Misconfiguration — not a spoof |
| `spf=temperror` | Temporary DNS failure | Re-check |

**L1 Trap**: SPF checks the **Return-Path**, not the visible `From`. An attacker can make `From: ceo@company.com` while `Return-Path: bounce@attacker.com` — SPF "passes" for attacker.com. That is why **DMARC alignment** matters.

---

## DKIM — DomainKeys Identified Mail (RFC 6376)

DKIM cryptographically signs the body plus selected headers (`h=`) with a private key; verifiers pull the public key from DNS at `<selector>._domainkey.<d-domain>`. Verdicts appear in `Authentication-Results:` and sometimes `DKIM-Status:`.

| Result | Meaning |
|--------|---------|
| `dkim=pass` | Signature cryptographically valid for the `d=` domain |
| `dkim=fail` | Signature invalid — headers/body altered or wrong key |
| `dkim=neutral` | No usable key / key not found / ambiguous |
| `dkim=permfail` | Permanent failure (bad key, unsupported algorithm) |

**Read the tags**: `d=example.com` (signing domain) + `s=selector1` (look up `selector1._domainkey.example.com`). If `d=` is **not** the `From` domain, or the signature fails — **spoofing**. A missing `b=` (signature) or `bh=` (body hash) means nothing was actually signed.

---

## DMARC — Policy, Alignment & the Big Picture (RFC 7489)

DMARC is the policy layer: it tells receivers what to do when SPF/DKIM fail and defines **alignment** so the envelope cannot be forged.

**DMARC passes if**: `(SPF pass AND SPF-aligned) OR (DKIM pass AND DKIM-aligned)`.

| DMARC Policy | Meaning | Result for failing mail |
|--------------|---------|-------------------------|
| `p=none` | Monitor only | Delivered, aggregate reports to `rua=` |
| `p=quarantine` | Mark suspicious | Goes to spam/quarantine |
| `p=reject` | Hard reject | Bounced / not delivered |
| `pct=100` | Apply policy to 100% of mail | Partial enforcement if lower |
| `adkim=r/s` | DKIM alignment relaxed/strict | Relaxed = subdomain of `From` ok; strict = exact match |
| `aspf=r/s` | SPF alignment relaxed/strict | Relaxed = subdomain of `From` ok; strict = exact match |

**Alignment**: SPF-aligned means `From` domain == `Return-Path` domain. DKIM-aligned means `From` domain == `d=` domain.

**L1 Trap — "auth passed but it's still phishing"**: If SPF and DKIM both pass **but are not aligned** to the `From` domain, DMARC fails. The attacker registered attacker.com, got real SPF/DKIM for it, then put your CEO's name/domain in `From`. **Check `dmarc=fail` regardless of `spf=pass` + `dkim=pass`.**

---

## Reading Authentication-Results — Master Table

One field carries all three verdicts. Parse it left to right:

```text
Authentication-Results: mx.recipient.com;
    dkim=pass header.i=@mail.attacker-domain.com header.s=selector1 header.b=AbC123;
    spf=pass smtp.mailfrom=attacker-domain.com;
    dmarc=fail (p=reject dis=none) header.from=company.com
```

| Verdict Line | What It Proves | Normal / Phishing |
|--------------|----------------|-------------------|
| `spf=pass smtp.mailfrom=attacker-domain.com` | attacker-domain.com authorized the sending IP | **Normal for attacker's domain — NOT proof of the `From`** |
| `dkim=pass header.i=@attacker-domain.com` | Signature valid for attacker's domain | Same trap as above |
| `dmarc=fail header.from=company.com` | `From` domain not aligned | **Spoofed `From` — phishing** |

**Decision table (L1):**

| spf | dkim | dmarc | Read |
|-----|------|-------|------|
| pass | pass | pass | Legit (or forwarded via ARC) |
| fail | fail | fail | **Spoofed — likely phishing** |
| pass | pass | fail | **Misaligned — display-name/domain spoof, still phishing** |
| fail | pass | pass | DKIM aligned, sender infra odd — verify |
| neutral | neutral | neutral | No records — check content, geo, links |

---

## Red Flags — Rapid Visual Triage

Run these before any deep-dive:

| Red Flag | Example | Why It Matters |
|----------|---------|----------------|
| **Spoofed display name** | `From: "IT Support" <it-support@evil.xyz>` | Legit-looking name, wrong domain |
| **Lookalike / punycode domain** | `xn--company-4na.com`, `arnazon.com` | IDN homograph / typosquatting |
| **Mismatched Reply-To** | `From: ceo@company.com`, `Reply-To: hr@evil.com` | Replies hijacked to attacker |
| **Return-Path vs From mismatch** | `Return-Path: @attacker.com` ≠ `From: @company.com` | Envelope spoofing — SPF checks Return-Path |
| **Urgent / credential language** | "Password expires today", "Verify now or account locked" | Pressure overrides judgment |
| **Unusual sender IP / geo** | `X-Originating-IP: 203.0.113.45` (RU) vs. HQ (US) | Impossible-travel for a "colleague" |
| **Header inconsistency** | `Message-ID` from free mailer, `X-Mailer: PHP/8.1.12` | Not corporate infrastructure |
| **No List-Unsubscribe / no signature** | Marketing-style but zero list headers | Spoofed bulk mail |
| **Future / past Date or timezone jump** | Date in 2025 while today is 2026 | Forged header |

---

## Payload Hunting — Attachments

### Attachment Type Table

| Type | Execution Vector | Detection |
|------|------------------|-----------|
| **Office Macro (.docm/.xlsm/.pptm)** | VBA / Excel 4.0 (XLM) macros | `olevba`, `oleid`, gateway sandbox, EDR Office→Script |
| **PDF** | JavaScript, embedded exploit, `/Launch` action | `pdfid`, `pdf-parser`, sandbox |
| **Archive (.zip/.rar/.7z/.iso/.img)** | Bypass gateway (nested, password-protected) | Recursive extraction, EDR on extract |
| **HTML (.html/.htm)** | Redirect, credential form | URL analysis, browser isolation |
| **LNK / URL** | Shortcut to remote payload (WebDAV, SMB) | Sysmon EID 11/1, LNK parser |
| **Executable (.exe/.scr/.bat/.ps1/.vbs/.js/.wsf/.msi)** | Direct execution | Gateway block, EDR hash+behavior |

### Attachment Analysis Steps

```text
1. HASH (SHA256) -> VT, MalwareBazaar, internal TI
2. FILE TYPE -> `file` command / TrID (never trust the extension)
3. STRINGS -> URLs, IPs, commands, registry, mutexes
4. OFFICE -> olevba, oleid, msoffcrypto-tool (VBA, XLM, encryption)
5. PDF -> pdfid, pdf-parser, peepdf (/JS, /Launch, /EmbeddedFiles)
6. ARCHIVE -> recursive extract, then repeat 1-5
7. SANDBOX -> Hybrid Analysis, Any.Run, Joe Sandbox, CAPE (process tree, net, drops)
8. YARA -> custom rules (phishing kits, known actors)
```

**Macro payload**: Office docs with macros carry the **mark-of-the-web (`Zone.Identifier` → `Isolated`)** when downloaded — EDR/Sysmon flags the Office → PowerShell → network chain (T1566.001 → T1059.001 → T1105).

### Suspicious Links (Without Clicking)

- **Hover** the link and compare the visible text to the real URL (link text "Reset Password" → URL `evil-phish-site.com`).
- **URL-decode** encoded links (quishing loves shortened + encoded URLs).
- **CLI look-up** with `curl -I` to see the redirect target and headers:

```bash
curl -I -s "https://company-services.xyz/reset?token=xyz" | head -20
curl -L -s -o /dev/null -w "%{url_effective}\n" "https://company-services.xyz/reset"
dig +short evil-phish-site.com A
whois evil-phish-site.com | rg -i "created|registrar|name server"
```

- Check domain age (recently registered = **High risk**), registrar (Namecheap/Porkbun/bulletproof = flag), ASN/hosting, SSL cert (crt.sh, self-signed), and reputation (VT, URLhaus, PhishTank, URLScan.io).
- **QR-code phishing (quishing)**: QR in the body/image hides the URL from user and gateway. Extract with `zbarimg`, then run the same checks. Mobile users bypass URL scanning — always enrich the QR's destination.

---

## Malicious Indicators to Record in the Ticket

Collect these — they are your incident's IOC set and feed blocklists/SOAR.

| Category | Example | Source |
|----------|---------|--------|
| **Sender IP** | `203.0.113.45` | Bottom Received / X-Originating-IP |
| **Source ASN** | `AS12345 (bulletproof hosting)` | `whois IP`, Shodan, Censys |
| **Envelope / Reply-To domain** | `attacker-domain.com`, `credential-harvest@evil.com` | Return-Path, Reply-To |
| **Spoofed From** | `it-support@company-services.xyz` | From header |
| **Malicious domains/URLs** | `https://company-services.xyz/reset` → redirect target | Body, hover, `curl -I` |
| **Attachment SHA256** | `a1b2c3...` (64 hex) | `sha256sum` on the `.eml` attachment |
| **Message-ID / selector** | `ABC123@attacker.com`, `selector1` | Message-ID, DKIM-Signature |
| **MITRE mapping** | **T1566 Phishing** (T1566.001/002), **T1195.002** (compromised supply chain), T1598 | ATT&CK — report in ticket, don't attribute |

> **L1 Note**: Record the IOCs and map the MITRE techniques; attribution comes from threat intel feeds, not you.

---

## L1 Triage Workflow — 60-Second Sequence

```text
1. EXTRACT: save .eml/.msg, copy full raw header into analyzer
2. PARSE: Return-Path, From, Reply-To, bottom Received IP, Authentication-Results
3. VERDICT: spf / dkim / dmarc — align to From domain
4. FLAGS: display name, lookalike domain, urgency, geo, mailer
5. PAYLOAD: attachment type+hash, link hover/curl, QR decode
6. SCOPE: recipients, delivered vs blocked, clicks, credentials entered
7. RECORD: IOCs above + MITRE T1566.x, severity, ticket notes
8. RESPOND: block domain/IP, quarantine mail, reset credentials if clicked, escalate BEC to L2
```

**BEC special case**: no malware, no links, no attachments — pure impersonation. Verify the sender **out-of-band** (call the CEO/finance/vendor) and check auth logs for a real account compromise before concluding.

---

## Summary — L1 Must Know

- [ ] Locate raw headers in Outlook, OWA, Gmail, M365 message trace, and Thunderbird; always save the `.eml`
- [ ] Read the Received chain **bottom-up** to identify the true sending server and IP
- [ ] Distinguish `Return-Path` (envelope, SPF checks this) from `From` (displayed) and `Reply-To` (reply hijack)
- [ ] Interpret `Received-SPF: pass | fail | softfail | neutral | permerror` against the Return-Path domain
- [ ] Verify DKIM `d=`/`s=` tags and that the signing domain matches `From`
- [ ] Apply DMARC pass logic: `(SPF pass + aligned) OR (DKIM pass + aligned)`; recognize pass/fail misalignment as spoofing
- [ ] Parse a full `Authentication-Results` line and decide spoofed vs. legitimate
- [ ] Spot red flags: spoofed display name, punycode/typosquat domains, mismatched Reply-To, urgency, geo mismatch
- [ ] Hunt payloads: hash+type attachments, macros/`Isolated` mark-of-the-web, hover/curl-URL-decode links, decode QR codes
- [ ] Record IOCs: sender IP, ASN, domains/URLs, attachment SHA256, Reply-To domain, and MITRE mapping (T1566.x, T1195.002)
- [ ] Classify and respond: TP/FP, severity, block/quarantine, credential reset, BEC out-of-band verification
