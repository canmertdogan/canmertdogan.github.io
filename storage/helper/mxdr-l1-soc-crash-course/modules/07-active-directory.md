# Module 7: Active Directory

**Priority: P0 — Identity is the new perimeter. AD compromise = domain compromise.**

---

## 7.1 Active Directory Fundamentals

### What is Active Directory?
**Directory service** for Windows domain networks. Stores objects (users, computers, groups, GPOs) in a hierarchical database. Provides authentication, authorization, and policy enforcement.

### Core Concepts
| Concept | Description |
|---------|-------------|
| **Forest** | Top-level container. One or more domains. Security boundary. |
| **Domain** | Logical partition. Replication boundary. Contains objects. |
| **Domain Controller (DC)** | Server running AD DS. Holds writable copy of domain partition. |
| **Global Catalog (GC)** | Partial replica of all objects in forest. Universal group membership. Port 3268/3269. |
| **FSMO Roles** | 5 single-master operations roles (Schema, Domain Naming, RID, PDC, Infrastructure). |
| **Trust** | Authentication path between domains/forests (transitive, non-transitive, forest, external). |

---

## 7.2 AD Objects — What L1 Needs to Know

### User Objects
| Attribute | SOC Relevance |
|-----------|---------------|
| `sAMAccountName` | Pre-Win2k logon name (DOMAIN\user) |
| `userPrincipalName` (UPN) | Modern logon (user@domain.com) |
| `objectSid` | Unique identifier (S-1-5-21-...-RID) |
| `primaryGroupID` | Default group (usually 513 = Domain Users) |
| `memberOf` | **Group memberships** (nested!) — privilege escalation path |
| `userAccountControl` | Flags: ACCOUNTDISABLE (0x2), PASSWD_NOTREQD (0x20), DONT_EXPIRE_PASSWORD (0x10000), TRUSTED_FOR_DELEGATION (0x80000) |
| `lastLogon` / `lastLogonTimestamp` | Last interactive logon (lastLogon not replicated!) |
| `pwdLastSet` | Password last changed (0 = must change) |
| `badPwdCount` / `badPasswordTime` | Failed logon tracking |
| `servicePrincipalName` (SPN) | **Kerberoasting target** — service accounts |
| `adminCount` | 1 = AdminSDHolder protected (Domain Admins, etc.) |
| `msDS-KeyCredentialLink` | WHfB / Certificate auth |

### Computer Objects
| Attribute | SOC Relevance |
|-----------|---------------|
| `dNSHostName` | FQDN |
| `operatingSystem` / `operatingSystemVersion` | Patch level, EOL detection |
| `lastLogonTimestamp` | Stale computer cleanup |
| `msDS-SupportedEncryptionTypes` | Kerberos encryption support (RC4 = weak) |
| `userAccountControl` | TRUSTED_FOR_DELEGATION, TRUSTED_TO_AUTH_FOR_DELEGATION |

### Group Objects
| Type | Scope | Use |
|------|-------|-----|
| **Security Group** | Domain Local, Global, Universal | Permissions, rights |
| **Distribution Group** | Email only | No security use |

**Critical Built-in Groups**:
| Group | SID Suffix | Privilege |
|-------|------------|-----------|
| Domain Admins | -512 | Full domain admin |
| Enterprise Admins | -519 | Full forest admin |
| Schema Admins | -518 | Schema modifications |
| Administrators (Builtin) | -544 | Local admin on DCs |
| Account Operators | -550 | User/group management |
| Server Operators | -549 | Server management |
| Print Operators | -550 | Printer management |
| Backup Operators | -551 | Backup/restore (can read NTDS.dit!) |
| Group Policy Creator Owners | -530 | Create GPOs |
| **Protected Users** | -525 | **Restricted auth** (no NTLM, no RC4, no delegation) |

---

## 7.3 Organizational Units (OUs) & Group Policy

### OU Structure (Typical)
```
domain.com
├── Domain Controllers (OU) → Default Domain Controllers Policy
├── Servers (OU)
│   ├── Tier 0 (PKI, PAM)
│   ├── Tier 1 (Apps, DB)
│   └── Tier 2 (File, Print)
├── Workstations (OU)
│   ├── Laptops
│   ├── Desktops
│   └── Kiosk
├── Users (OU)
│   ├── Admins
│   ├── Service Accounts
│   ├── Employees
│   └── Contractors
└── Groups (OU)
    ├── Security
    └── Distribution
```

### Group Policy Objects (GPOs)
- **Linked to**: Site, Domain, OU (LSDOU order)
- **Inheritance**: Child OUs inherit parent GPOs (Block Inheritance / Enforced)
- **Security Filtering**: Apply to specific groups
- **WMI Filtering**: Dynamic targeting

**Critical GPOs for SOC**:
| GPO | Purpose |
|-----|---------|
| Default Domain Policy | Password policy, account lockout, Kerberos |
| Default Domain Controllers Policy | Audit policy, user rights, security options |
| **Audit Policy GPO** | **Enable all Advanced Audit Policy subcategories** |
| **AppLocker / WDAC GPO** | Application control |
| **LAPS GPO** | Local admin password management |

---

## 7.4 Service Accounts — High-Value Targets

| Type | Description | Risk |
|------|-------------|------|
| **Domain User as Service** | Regular user with SPN, password never expires | **Kerberoasting**, password spray |
| **Group Managed Service Account (gMSA)** | Auto-rotated password, managed by DC | Low (no interactive logon) |
| **Standalone Managed Service Account (sMSA)** | Single server, auto-rotated | Low |
| **Virtual Account** | `NT SERVICE\ServiceName` | Local only |
| **SYSTEM / Network Service / Local Service** | Built-in | Local only |

**Service Account Hygiene Checks**:
- [ ] SPN set? (Kerberoasting target)
- [ ] Password last set > 1 year?
- [ ] Member of privileged groups?
- [ ] `userAccountControl`: DONT_EXPIRE_PASSWORD (0x10000)?
- [ ] `adminCount = 1` (AdminSDHolder)?
- [ ] Delegation configured? (Unconstrained = high risk)

---

## 7.5 Privileged Accounts & Tier Model

### Microsoft Tier Model (Security Best Practice)
```
TIER 0 — Identity Control Plane
├── Domain Controllers
├── AD FS / Azure AD Connect
├── PKI (CA)
├── PAM (Privileged Access Management)
└── Domain/Enterprise/Schema Admins
    → Dedicated Tier 0 admin accounts (no email, no web)
    → Tier 0 PAW (Privileged Access Workstation)

TIER 1 — Enterprise Applications
├── SQL, Exchange, SharePoint
├── Critical business apps
├── Application admins
    → Tier 1 admin accounts
    → Tier 1 PAW

TIER 2 — End-User Workloads
├── Workstations, Laptops
├── Helpdesk, standard users
├── Standard user accounts
    → Regular workstations

TIER 3 — (Optional) DMZ / Cloud / Untrusted
```

**Golden Rules**:
1. **Tier 0 admins NEVER log into Tier 1/2**
2. **Tier 1 admins NEVER log into Tier 2**
3. **Separate accounts per tier** (admin.t0, admin.t1, user.t2)
4. **PAW required** for Tier 0/1 admin work

### AdminSDHolder & SDProp
- **AdminSDHolder** (CN=AdminSDHolder,CN=System,DC=domain) — template ACL for privileged groups
- **SDProp** — runs every 60 min on PDC Emulator, reapplies AdminSDHolder ACL to all protected accounts (adminCount=1)
- **Effect**: Manual ACL changes on Domain Admins etc. **reverted within 60 min**

---

## 7.6 AD Authentication vs Authorization

| Concept | Description | AD Mechanism |
|---------|-------------|--------------|
| **Authentication** | *Who are you?* | Kerberos / NTLM → Ticket / Token |
| **Authorization** | *What can you do?* | Access Token (SIDs + Privileges) + ACL on Object (DACL/SACL) |

### Access Token (Created at Logon)
```
Token Contains:
├── User SID
├── Group SIDs (primary + all nested groups)
├── Privileges (SeDebugPrivilege, SeBackupPrivilege, etc.)
├── Integrity Level (System, High, Medium, Low)
├── Logon Session ID (LUID)
└── Claims (Dynamic Access Control)
```

**Authorization Check**:
```
Requestor Token → Object Security Descriptor (DACL)
    │
    ├── Owner SID → Owner ACEs
    ├── Primary Group SID → Group ACEs
    ├── Group SIDs (token) → Match ACEs (Allow/Deny)
    └── Everyone / Authenticated Users → Match ACEs
    │
    ▼
Result: Allow / Deny / Audit
```

---

## 7.7 AD Reconnaissance — What Attackers Enumerate

### BloodHound / SharpHound Data (What They Collect)
| Collection Method | Data |
|-------------------|------|
| LDAP | Users, Groups, Computers, GPOs, OUs, Trusts, ACLs |
| Remote Registry | Local admins (via `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes`) |
| WMI | Sessions, Logged-on users, Shares, Services |
| DCOM | Session info |

### Key Attack Paths (BloodHound Edge Types)
| Edge | Meaning | Abuse |
|------|---------|-------|
| `MemberOf` | User/Computer in Group | Nested group privilege escalation |
| `HasSession` | User logged on Computer | Credential theft (LSASS) |
| `AdminTo` | User/Group has admin rights on Computer | Lateral movement |
| `AllExtendedRights` | User/Group has extended rights on Object | Password reset, write SPN, DCSync |
| `ForceChangePassword` | Can reset password | Takeover |
| `AddMember` | Can add members to Group | Privilege escalation |
| `GenericAll` / `GenericWrite` / `WriteDacl` / `WriteOwner` | Full/Write ACL control | Object takeover |
| `DCSync` | Domain replication rights (DS-Replication-Get-Changes) | **Domain compromise** |
| `AllowedToDelegate` / `TrustedToAuth` | Kerberos delegation | **Privilege escalation** |

---

## 7.8 AD Security Monitoring — Key Events

### Critical Event IDs (From Module 4 + AD Specific)
| Event ID | Channel | What |
|----------|---------|------|
| **4720** | Security | User Created |
| **4722/4725** | Security | User Enabled/Disabled |
| **4723/4724** | Security | Password Change/Reset |
| **4728/4732/4756** | Security | User Added to Group (Global/Domain Local/Universal) |
| **4729/4733/4757** | Security | User Removed from Group |
| **4738** | Security | User Changed (attrs) |
| **4740** | Security | User Locked Out |
| **4741/4743** | Security | Computer Created/Changed |
| **4768/4769/4770** | Security | Kerberos TGT/TGS (see Module 8) |
| **4771** | Security | Kerberos Pre-Auth Failed |
| **4776** | Security | NTLM Auth (on DC) |
| **5136** | Directory Service | **LDAP Modify** (attribute changes) — **Critical for AD changes** |
| **5137** | Directory Service | LDAP Create |
| **5138** | Directory Service | LDAP Delete |
| **5139** | Directory Service | LDAP Move |
| **5141** | Directory Service | LDAP Undelete |

### 5136 — The AD Change Detective
```
Key Fields:
├── ObjectDN:           CN=AdminUser,OU=Admins,DC=domain,DC=com
├── AttributeLDAPDisplayName:  memberOf / userAccountControl / unicodePwd / nTSecurityDescriptor
├── AttributeSyntaxOID:  2.5.5.x (syntax type)
├── AttributeValue:     New value (or <value not logged> for sensitive)
├── OperationType:      Add / Delete / Replace
├── SubjectUserName:    Who made change
├── SubjectDomainName:
└── CallerProcessName:  Process (ldap.exe, powershell.exe, mmc.exe)
```

**Monitor These Attribute Changes**:
| Attribute | Why |
|-----------|-----|
| `memberOf` (Group changes) | Privilege escalation |
| `userAccountControl` | Delegation, password not required, disabled |
| `unicodePwd` / `ntPwdHistory` | Password changes (DCSync) |
| `nTSecurityDescriptor` | ACL changes (persistence) |
| `servicePrincipalName` | Kerberoasting setup |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | **Resource-based Constrained Delegation (RBCD)** |
| `userParameters` | Dial-in, callback (legacy) |

---

## 7.9 Azure AD / Entra ID — Cloud Identity

### Key Differences from On-Prem AD
| On-Prem AD | Entra ID |
|------------|----------|
| Kerberos / NTLM | OAuth 2.0 / OpenID Connect / SAML / WS-Fed |
| Domain/Forest | Tenant (single flat namespace) |
| OU/GPO | Administrative Units / Device Configuration Profiles |
| Domain Controller | Managed by Microsoft (no DC access) |
| Trust | B2B (Guest), B2C, Cross-tenant sync |
| Password Hash Sync / PTA / Federation | Auth methods |

### Entra ID Logs (Critical for L1 in Hybrid)
| Log | What |
|-----|------|
| **Sign-in Logs** | Interactive, non-interactive, service principal, managed identity |
| **Audit Logs** | Directory changes (user, group, app, role, policy) |
| **Provisioning Logs** | SCIM/HR-driven provisioning |
| **Risk Detections** | Risky sign-ins (impossible travel, anonymous IP, atypical, leaked creds) |

### Hybrid Identity Attacks
| Attack | Description |
|--------|-------------|
| **Password Hash Sync (PHS) Abuse** | Compromise on-prem → sync to cloud |
| **Seamless SSO / PTA Abuse** | Compromise PTA agent → bypass MFA |
| **AD Connect Sync Account** | `MSOL_...` / `AAD_...` account — high privilege |
| **Cloud-only Admin** | Global Admin in Entra ID ≠ Domain Admin on-prem |
| **Device Registration** | Join personal device → access corporate resources |
| **App Registration / Service Principal** | Credentials (cert/secret) → app impersonation |

---

## 7.10 AD Hardening Basics (What L1 Should Recognize)

| Control | Purpose |
|---------|---------|
| **Protected Users Group** | Blocks NTLM, RC4, delegation, caches |
| **LAPS** | Unique local admin passwords per machine |
| **Tiered Administration** | Separate accounts/PAWs per tier |
| **PAW (Privileged Access Workstation)** | Hardened admin workstation |
| **Time-based Access (PIM/PAM)** | Just-in-time privileged access |
| **Authentication Silos** | Restrict authN policies per tier |
| **DC Hardening** | No internet, no agents (or minimal), restricted RDP |
| **Audit Policy** | Advanced Audit Policy (Module 4) |
| **AdminSDHolder Review** | Verify ACL template |
| **Delegation Review** | Unconstrained → Constrained / None |
| **SPN Review** | Remove unused SPNs (Kerberoasting reduction) |
| **KRBTGT Rotation** | Rotate twice (Golden Ticket mitigation) |
| **DFL/FFL** | Domain/Forest Functional Level (2016+ for features) |

---

## 7.11 Interview Questions for This Module

1. **What is the difference between a Domain, Forest, and OU?**
   - Domain: Replication/auth boundary. Forest: Security boundary (multiple domains). OU: Administrative container for GPO linking/delegation.

2. **What are the 5 FSMO roles and which is most critical for password changes?**
   - Schema Master, Domain Naming Master, RID Master, PDC Emulator, Infrastructure Master. **PDC Emulator** — password changes, account lockouts, time sync, GPO default.

3. **What is AdminSDHolder and SDProp?**
   - AdminSDHolder: Template ACL for privileged accounts (adminCount=1). SDProp: Process on PDC that reapplies template every 60 min.

4. **What is the Tier Model and why does it matter?**
   - Tier 0 (Identity/DC), Tier 1 (Apps), Tier 2 (Workstations). Prevents credential theft via lateral movement. Admins use dedicated accounts per tier + PAW.

5. **What attributes on a user object indicate Kerberoasting risk?**
   - `servicePrincipalName` (SPN) set, `userAccountControl` has DONT_EXPIRE_PASSWORD (0x10000), password old, not in Protected Users.

6. **What is the difference between Authentication and Authorization in AD?**
   - AuthN: Kerberos/NTLM → Ticket/Token (who). AuthZ: Token SIDs+Privs + Object DACL → Allow/Deny (what).

7. **What does Event ID 5136 tell you and what attributes should you monitor?**
   - LDAP Modify. Monitor: `memberOf`, `userAccountControl`, `unicodePwd`, `nTSecurityDescriptor`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity`.

8. **What is a gMSA and why is it more secure than a regular service account?**
   - Group Managed Service Account: Auto-rotated complex password (120+ chars), managed by DC, no interactive logon, single/multi-server.

9. **How does Entra ID (Azure AD) authentication differ from on-prem AD?**
   - OAuth/OIDC/SAML vs Kerberos/NTLM. Tenant vs Domain/Forest. Managed identity, conditional access, risk-based auth.

10. **What is Resource-Based Constrained Delegation (RBCD) and what attribute controls it?**
    - Delegation where *resource* controls who can delegate to it. Attribute: `msDS-AllowedToActOnBehalfOfOtherIdentity` on resource computer/user.

---

## 7.12 Study Checklist for Module 7

- [ ] Define Forest, Domain, DC, GC, FSMO, Trust
- [ ] List critical user/computer/group attributes and SOC relevance
- [ ] Explain OU/GPO structure and LSDOU processing
- [ ] Classify service account types and risk levels
- [ ] Diagram Tier Model (0/1/2/3) with accounts/PAWs
- [ ] Explain AdminSDHolder + SDProp mechanism
- [ ] Distinguish Authentication vs Authorization (Token + DACL)
- [ ] List BloodHound edge types and attack paths
- [ ] Identify critical AD Event IDs (4720-4769, 5136-5141)
- [ ] Explain 5136 monitoring for `memberOf`, `userAccountControl`, `nTSecurityDescriptor`, RBCD
- [ ] Compare On-prem AD vs Entra ID auth/models
- [ ] List 10 AD hardening controls
- [ ] Answer all 10 interview questions without notes

---

*Next: Module 8 — Kerberos and NTLM*