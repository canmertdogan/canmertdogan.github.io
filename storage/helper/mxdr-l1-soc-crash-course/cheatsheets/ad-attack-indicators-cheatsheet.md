# Active Directory Attack Indicators Cheat Sheet for SOC Analysts

**Priority: P1 — AD is the identity backplane: one missed AD attack indicator is a domain-wide compromise.**

---

## Why AD Attacks Matter to an L1

Attackers follow a repeatable path against AD: **enumerate** the domain, **steal or crack credentials**, **escalate privilege**, **move laterally**, then **own the domain** (DCSync, golden ticket). Every step leaves a trace in Windows event logs on Domain Controllers and endpoints. L1's job is to recognize the *pattern* in event IDs, correlate it to a source host and account, and escalate before the attacker finishes.

The three pillars of detection:
- **Who** (SubjectUserName / TargetUserName), **from where** (IpAddress, Workstation), **when** (time window, odd hours).
- **Logon type** on every 4624/4625 (Type 3 = network/lateral movement, Type 10 = RDP, Type 2 = interactive).
- **What changed** in AD objects (5136, 4728, 4670) and whether a **1102 log clear** or **4719 audit policy change** follows.

---

## Enumeration & Recon

### What Attackers Do
Map the domain with BloodHound/SharpHound over **LDAP**, enumerate SMB shares, and harvest usernames before attacking. Heavy recon is usually the first signal you will see.

| Event ID | Channel | What It Shows | Suspicious Signal |
|----------|---------|---------------|-------------------|
| **4662** | Security (DS Access) | Directory object access via LDAP | One account reading a broad sweep of objects; access to **Replicating Directory Changes** GUIDs = DCSync (see below) |
| **5140** | Security | Network share object accessed | Access to **ADMIN$ / C$** or unusual shares from a non-admin host |
| **5145** | Security | Detailed file share access | High-volume listing/naming of share contents = share enumeration |
| **4768** | Security | Kerberos TGT request (AS-REQ) | **AS-REQs for many distinct users from one source host** = user enumeration |

**Recon signals to escalate:** 5140/5145 floods from one host, a spike of 4768 for dozens of `TargetUserName` values from one IP, and LDAP query volume from a workstation account (normal LDAP comes from service accounts and DCs).

```kql
SecurityEvent
| where EventID == 4768
| where IpAddress == "<suspected-host>"
| summarize Users = dcount(TargetUserName) by bin(TimeGenerated, 15m)
| where Users > 20
```

---

## Password Spraying & Brute Force

### What Attackers Do
**Spray** = one password against many users (stays under lockout threshold). **Brute force** = many passwords against one user. Both generate failures, then a tell-tale success: **many failed → one success**.

| Event ID | What It Shows | Attack Signal |
|----------|---------------|---------------|
| **4625** | Failed logon | Flood from one IP; SubStatus **0xC000006A** (bad password), **0xC0000234** (locked out) |
| **4740** | Account locked out | **Multiple distinct accounts locked from one source** |
| **4776** | NTLM credential validation (DC) | Failures (Status not 0) for many users from one Workstation |
| **4648** | Explicit credentials logon (RunAs) | Type 2/Type 8 logon from unusual host, immediately followed by remote action |

**Escalation pattern:** `4625` spike for user X from IP A, then a `4624` **Logon Type 3** success for X from IP A — the attacker found the right password. Sprays often target service accounts (no 4740) and use 1–3 attempts per user, so judge by *total volume across users*, not per-user counts.

```kql
SecurityEvent
| where EventID == 4625 and Status == "0xc000006a"
| summarize Failed = count() by IpAddress, bin(TimeGenerated, 1h)
| where Failed > 20
```

---

## Kerberoasting

### What Attackers Do
Any authenticated domain user requests a **service ticket (TGS)** for a **service account SPN**. The ticket is encrypted with the service account's key — if the request is **RC4 (etype 23, 0x17)**, the offline crack is trivial.

| Event ID | Key Field | Signal |
|----------|-----------|--------|
| **4769** | **TicketEncryptionType** | **0x17 (RC4)** on service ticket requests |
| **4769** | **ServiceName** | SPN format (`HTTP/web01`, `MSSQLSvc/sql01:1433`), unusual SPN set |
| **4769** | **TargetUserName** | **One user requesting many SPNs** in a short window |

**Why it matters:** a single RC4 TGS request to a valid SPN can look legitimate. The anomaly is *volume and context*: one user requesting tickets for many SPNs, or RC4 requests for accounts that normally use AES (`msDS-SupportedEncryptionTypes` = 24).

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == 23  // RC4
| where ServiceName has "@"
| summarize Count = count(), SPNs = make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where Count >= 10
```

---

## AS-REP Roasting

### What Attackers Do
Accounts with **"Do not require Kerberos pre-authentication"** (`userAccountControl` DONT_REQUIRE_PREAUTH = **0x400000**) let an attacker request a TGT without proving the password. The **AS-REP** reply is encrypted with the user key, enabling offline crack.

| Event ID | Key Field | Signal |
|----------|-----------|--------|
| **4768** | **PreAuthType** | **0 (no pre-auth)** for accounts that should pre-authenticate |
| **4771** | **FailureCode** | **0x18** (bad password) for the same user — attacker cracking offline |
| **4768** | **TargetUserName** | Burst of AS-REQs for multiple pre-auth-disabled accounts |

**Signal:** a 4768 with `PreAuthType == 0` from a source host that is not the user's normal workstation, or several such requests in one burst. Cross-reference with AD for accounts flagged **DONT_REQUIRE_PREAUTH** — that misconfiguration is the vulnerability.

```kql
SecurityEvent
| where EventID == 4768
| where PreAuthType == 0  // No pre-auth
| summarize Count = count() by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where Count > 3
```

---

## Golden & Silver Tickets

### What Attackers Do
**Golden ticket:** forge a TGT using the **krbtgt hash** (any user, any group, lifetime of years). **Silver ticket:** forge a **service ticket** using a service account hash — no KDC interaction at all.

| Event ID | Signal |
|----------|--------|
| **4769** | RC4 (0x17) service ticket requests **after a user password change**, and tickets for services the user never touches |
| **4771** | FailureCode **KRB_AP_ERR_SKEW** (clock skew) — classic forged-ticket artifact |
| **4768** | TGT for a user from an **unusual source host** or with anomalous lifetime/flags |
| **1102** | **Security log cleared** nearby — evidence destruction before/after the attack |
| — | **Admin group membership anomaly** in the PAC (groups in ticket do not match AD) |

**Detection reality:** forged tickets are hard to prove from logs alone. **4769 after a password change** is your strongest DC-side indicator. Silver tickets leave **no matching 4769 from the KDC** — a service ticket used with no preceding TGS-REQ is a red flag. Correlate with **krbtgt password age > 180 days** and rely on EDR for ticket injection.

---

## DCSync & Domain Replication

### What Attackers Do
Abuse the **DS-Replication-Get-Changes** extended right (`Replicating Directory Changes All`) to replicate credential material — including the **krbtgt hash** — directly from the DC.

| Event ID | Key Field | Signal |
|----------|-----------|--------|
| **4662** | **AccessMask / Properties** | Operation on the **Replicating Directory Changes All** control access right (GUID `1131f6aa-9e07-11d0-991a-00aa005f12d6`) by a **non-DC principal** |

**Signals:** 4662 from a host that is not a DC, an account with no legitimate replication role (helpdesk user, workstation, service account), or repeated 4662 against replication-critical objects (krbtgt, Domain Admins). DCSync is the **fastest path to full domain compromise** — escalate P1 and isolate the source.

```kql
SecurityEvent
| where EventID == 4662
| where AccessMask == 0x100  // DS-Control-Access-Right
| where Properties has "1131f6aa-9e07-11d0-991a-00aa005f12d6"
| where Computer !has "-DC"  // source is not a DC
```

---

## Skeleton Key & Credential Dumping on DCs

### What Attackers Do
**Patch LSASS on a DC** so a single "master password" authenticates any account (skeleton key), or **dump credentials** from DC LSASS / NTDS.dit. Both are **domain compromise**.

| Event ID | Signal |
|----------|--------|
| **4624** | Success logons **without any preceding 4625** — skeleton-key master password accepted |
| **4776** | NTLM validations for many accounts at unusual times |
| **1102** | **Security log cleared on a DC** — anti-forensics after credential theft |
| **4648** | Explicit credentials logon by a suspicious process on the DC |

**Escalate immediately:** successful logons for accounts whose passwords were never tried, any 1102 on a DC, and EDR alerts for LSASS access (Sysmon Event 10 targeting `lsass.exe`) or `Backup Operators` reading NTDS.dit. Skeleton key can survive reboots if disk-patched — isolate the DC.

---

## GPO & AD Object Tampering

### What Attackers Do
Modify **GPOs** for persistence and mass malware deployment, retarget **AdminSDHolder** (template ACL for all privileged accounts), change **DACLs** to grant rights, or set **RBCD** attributes to impersonate anyone.

| Event ID | Key Field | Signal |
|----------|-----------|--------|
| **5136** | **AttributeLDAPDisplayName** | Changes to **memberOf, userAccountControl, unicodePwd, nTSecurityDescriptor, servicePrincipalName, msDS-AllowedToActOnBehalfOfOtherIdentity** |
| **5137/5139/5141** | ObjectDN | Create / move / undelete of high-value objects (GPO containers, AdminSDHolder) |
| **4741/4742** | Computer Object | Computer created or changed at odd hours; attribute changes on computer accounts |
| **4670** | ObjectName | **Permissions (DACL) changed** on an object — ACL tampering/persistence |

**Reading 5136:** `ObjectDN` tells you the target (`CN=AdminSDHolder,CN=System,DC=domain,DC=com`), `CallerProcessName` separates legitimate tools (`ldap.exe`, `mmc.exe`) from suspicious ones (`powershell.exe`), and `OperationType` shows Add/Delete/Replace. A 5136 on `nTSecurityDescriptor` or `memberOf` of a privileged account is **P1 privilege escalation**.

---

## Account Creation & Privilege Changes

### What Attackers Do
Plant **backdoor accounts**, add themselves to **privileged groups**, reset passwords, and disable or re-enable accounts to hide or recycle access.

| Event ID | What It Shows | Attack Signal |
|----------|---------------|---------------|
| **4720** | User account created | Created **at odd hours**; created by a non-admin subject; account immediately granted rights |
| **4728 / 4732 / 4756** | Member added to group | Addition to **Domain Admins, Enterprise Admins, Backup Operators, Account Operators** |
| **4725 / 4722** | User disabled / enabled | Disabling during exfiltration; re-enabling stale accounts |
| **4724** | Password reset | Admin resets an account then **logs on as it** shortly after |
| **4738** | User object changed | `userAccountControl`, password flags toggled on service accounts |

**Pattern to escalate:** 4720 (new user) followed by 4728/4732 (added to a privileged group) followed by a 4624 network logon — attacker-created admin in minutes. Group additions to high-value groups trigger a **P1** every time, even if the account name looks plausible.

---

## Investigation Flow — L1 Playbook

### Correlate
1. **Identify** the attack event from the tables above.
2. **Pull context**: source host/IP, account, time.
3. **Check logon types** in surrounding 4624/4625 (Type 3 = network, Type 10 = RDP, Type 2 = interactive, Type 9 = RunAs).
4. **Hunt lateral movement** after the indicator: 5140/5145 share access, 4624 Type 3 to new hosts.
5. **Check evasion**: 1102 log clears, 4719 audit policy changes, 4907 SACL changes.
6. **Triangulate with EDR**: LSASS access, process creation, command lines.

### MITRE Mapping
| Technique | ID | Key Events |
|-----------|-----|------------|
| Credential access — brute force / password spray | **T1110** | 4625, 4776, 4740 |
| Credential access — Kerberoasting | **T1558.003** | 4769 RC4, SPN requests |
| Credential access — AS-REP Roasting | **T1558.004** | 4768 PreAuthType 0 |
| Credential access — DCSync (NTDS.dit) | **T1003.006** | 4662 replication GUIDs |
| Defense evasion — valid accounts / backdoors | **T1078** | 4720, 4728, 4732, 4724 |
| Privilege escalation — domain/trust/GPO modification | **T1484** | 5136, 4742, 4670 |

### P1 Escalation Triggers
- **4662** DCSync replication rights (T1003.006)
- **4769** Kerberoasting burst with RC4 (T1558.003)
- **4728** add to Domain Admins / privileged group (T1078)
- **1102** security log clear, especially on a DC (T1070.001)
- **4768** with PreAuthType 0 for multiple accounts (T1558.004)
- Any **skeleton key** pattern: 4624 success with no 4625 (T1098)

---

## Summary — L1 Must Know
- [ ] Explain the AD kill chain: enumerate → credentials → escalate → lateral → domain compromise
- [ ] Name the recon events: 4662, 5140, 5145, and 4768 enumeration floods
- [ ] Recognize the "many failed → one success" password spray pattern in 4625/4776/4740
- [ ] Describe Kerberoasting: 4769 + TicketEncryptionType 0x17 (RC4) + SPN in ServiceName
- [ ] Describe AS-REP Roasting: 4768 with PreAuthType 0 for DONT_REQUIRE_PREAUTH accounts
- [ ] Recall golden/silver ticket indicators: 4769 after password change, KRB_AP_ERR_SKEW, log clear
- [ ] Identify DCSync: 4662 on Replicating Directory Changes All by a non-DC principal
- [ ] List the 5136 attributes that always matter: memberOf, userAccountControl, nTSecurityDescriptor, msDS-AllowedToActOnBehalfOfOtherIdentity
- [ ] Correlate source host, logon type, and time window across 4624/4625 when triaging
- [ ] Map key events to MITRE: T1110, T1558.003, T1558.004, T1003.006, T1078, T1484
