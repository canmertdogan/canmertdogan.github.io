# Cloud Security Cheat Sheet for SOC Analysts

**Priority: P1 — Identity is the new perimeter; L1 will triage cloud alerts (impossible travel, crypto mining, exposed storage) from week one**

---

## Cloud vs On-Prem — What Changes for the SOC

Cloud breaks most on-prem assumptions — attacks move through **identities** and **APIs**, not network perimeters.

| Aspect | On-Prem | Cloud |
|--------|---------|-------|
| **Security boundary** | Network perimeter (firewall, DMZ) | **Identity** — who can call which API |
| **Where data lives** | Fixed servers you control | Ephemeral resources (VMs, containers, buckets) spun up on demand |
| **Primary attack surface** | Hosts, network, malware | **Compromised credentials**, misconfigured APIs, exposed storage |
| **Logs** | Syslog, Windows Event Log, firewall | **Audit APIs**: CloudTrail (AWS), Activity/Sign-in Logs (Azure) |
| **Visibility** | One network you own | Multi-account / multi-tenant, cross-cloud |
| **Incident tempo** | Slow, persistent | **Fast and ephemeral** — attacker may create/delete resources in minutes |

**Key mental shift:** an attacker rarely "breaks in" — they steal a valid credential and use it like a legitimate user, which is why most cloud alerts are **identity events**, not malware events.

---

## The Shared Responsibility Model

**The provider secures *of* the cloud; the customer secures *in* the cloud.** You must know where the line falls for every alert you triage.

| Cloud Provider (AWS / Azure) | Customer (Your Org) |
|------------------------------|---------------------|
| Physical security, data centers, network infrastructure | Identity and access management (IAM) |
| Hypervisor / host operating system | Data encryption (at rest and in transit) |
| Managed services (S3, RDS, Azure SQL) | Application and OS config (EC2, AKS, VMs) |
| Global infrastructure, compliance certifications | Network config (VPC, security groups, NSGs) |
| | **Logging and monitoring configuration** |

**L1 impact:** when logs are missing, it is usually a customer-side configuration gap (data events not enabled, export not configured). Flag it — but keep investigating.

---

## Cloud IAM Concepts

| Concept | AWS | Azure / Entra ID | L1 Relevance |
|---------|-----|------------------|--------------|
| **User** | IAM User (long-term password + access keys) | Entra ID User (cloud or AD-synced) | Compromised user = full access; watch sign-in risk |
| **Role** | Role assumed temporarily via **STS AssumeRole** | Role assignment (Owner/Contributor/Reader + scope) | Temporary credentials; abuse shows as unusual `AssumeRole` |
| **Service principal** | N/A (AWS services assume roles) | **App identity** (client_id + secret/cert) | App compromise = silent **SP abuse** |
| **Managed identity** | N/A (instance profile) | System/user-assigned, no stored secret | Preferred over SP — nothing to steal |
| **Access keys** | `AKIA...` long-term keys — **high risk if leaked** | Client secrets / certificates | Check for newly created or unusually used keys |
| **Conditional Access** | N/A (use policies + MFA) | Policies: require MFA, block locations, device compliance | **Bypass = risk**; always verify CA status |
| **Privileged access** | N/A (use policies) | **PIM** — just-in-time elevation with approval | Standing admin access = risk |

**Identity vs workload identity:** a **human identity** (user) signs in to a portal; a **workload identity** (SP, managed identity, EC2 role) makes API calls as a machine. Compromising either gives the attacker the same API power.

---

## Azure / Microsoft 365 Log Sources in Sentinel

All of these flow into Sentinel via **data connectors** (Entra ID, Activity Log, Office 365). Know which log answers which question.

| Log | What It Records | L1 Use |
|-----|-----------------|--------|
| **SigninLogs** | Interactive and non-interactive user sign-ins: UPN, IP, location, auth method, **riskLevel**, **conditionalAccessStatus** | Impossible travel, unfamiliar location, MFA failures |
| **AuditLogs** | Changes inside tenants/apps: user/group changes, **mailbox rules**, consent grants, app registration | Persistence, mailbox backdoors, consent grant abuse |
| **AzureActivity** | **Control plane** (ARM) operations on resources: `operationName`, `caller`, `resourceId`, `result` | Role assignment changes, resource creation/deletion |
| **MicrosoftGraphActivityLogs** | API calls to Microsoft Graph (who accessed which tenant data via Graph) | OAuth/Graph abuse, token reuse |
| **AADSignInEventsBeta** | Richer, normalized sign-in telemetry (user, device, risk, app) | Fast pre-parsed sign-in hunting |
| **SecurityEvent** | Windows security events from on-prem/VM agents | Correlate on-prem compromise with cloud sign-ins |

**Investigation pattern:** alert → identify the log that proves it (SigninLogs for "who signed in", AuditLogs for "what changed", AzureActivity for "what resource").

---

## AWS Log Sources

| Log | What It Records | L1 Use |
|-----|-----------------|--------|
| **CloudTrail (management events)** | Every control-plane API call: `eventName`, `userIdentity`, `sourceIPAddress`, `userAgent`, `errorCode` | `ConsoleLogin`, `AssumeRole`, IAM and security group changes |
| **CloudTrail (data events)** | Data-plane access: S3 `GetObject`, Lambda `Invoke`, DynamoDB `PutItem` | **Exfiltration** and object-level access (opt-in, often missing) |
| **CloudWatch VPC Flow Logs** | Network metadata for VPC traffic | Mining pool connections, data transfer, lateral movement |
| **GuardDuty** | ML/rule-based findings: `CredentialCompromise`, `CryptoCurrency`, `S3 Bucket Deletion` | Pre-correlated findings — treat as high-signal |
| **S3 access logs** | Object-level HTTP requests to buckets | Who read what, from where, over time |
| **CloudWatch Logs (Lambda)** | Function execution logs | Function abuse, crypto-mining code, `stratum` strings |

**CloudTrail key fields to always project:** `eventTime`, `eventSource`, `eventName`, `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `errorCode`. A burst of `AccessDenied` errors = **reconnaissance**.

---

## Azure Key Events — Recognize & React

| Event | Log Source | Suspicious If | L1 Action |
|-------|------------|---------------|-----------|
| **Impossible travel** | SigninLogs | Two sign-ins from far-apart locations within minutes | Check risk, MFA satisfaction, device registration, VPN |
| **Sign-in from unfamiliar location / high risk** | SigninLogs (`riskLevel`) | New country/IP for that user | Verify CA applied, confirm with user, **disable user if confirmed** |
| **MFA failures** | SigninLogs | Repeated failed MFA attempts (MFA fatigue) | Check for MFA-bomb pattern; block app push |
| **Conditional Access failure** | SigninLogs (`conditionalAccessStatus`) | Policy blocks unusual access then it succeeds | Investigate the allowed sign-in — possible bypass |
| **New service principal** | AuditLogs | Created by unknown actor, granted broad roles | Verify requestor; **suspend SP if unauthorized** |
| **Privileged role activation (PIM)** | AuditLogs | Activation outside approval, unusual time, then destructive actions | Review activation + subsequent role usage |
| **Unusual AAD app consent** | AuditLogs (`ConsentGrant`) | App requests high Graph permission (Mail.Read, Files.ReadWrite) | Check app publisher, requested scopes, grantor |
| **Mailbox rule created** | AuditLogs (`New-InboxRule`) | Rule forwards/deletes mail to external address | **Known exfiltration technique** — delete rule, reset creds |
| **OAuth app grants** | AuditLogs / MicrosoftGraphActivityLogs | App granted token access to tenant data | Revoke grant, block app, check token use |

```kql
// Sentinel: suspicious or risky sign-ins in the last 24h
SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevel != "none" or ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationMethod, ConditionalAccessStatus,
          RiskLevel, RiskState, DeviceDetail
| sort by TimeGenerated desc
```

---

## AWS Key Events — Recognize & React

| Event | Log Source | Suspicious If | L1 Action |
|-------|------------|---------------|-----------|
| **ConsoleLogin without MFA** | CloudTrail | `additionalEventData.MFAUsed` = false for admin/user with MFA policy | Check user agent, IP, prior sign-in pattern; **disable access keys** |
| **Unusual root account activity** | CloudTrail (`userIdentity.type: Root`) | Root login from new IP, `CreateAccessKey` under root | Root for billing is normal — API/console actions are not; escalate |
| **CreateAccessKey / UpdateAccessKey** | CloudTrail | New key, old key rotated by unknown actor | Persistence — verify requestor, deactivate key |
| **AssumeRole with external account** | CloudTrail | Cross-account role assumption from unknown account | Check `requestParameters.roleArn`, session issuer, source IP |
| **Security group changes** | CloudTrail (`AuthorizeSecurityGroupIngress`) | Inbound open to `0.0.0.0/0` on SSH/RDP/DB ports | Exposure — confirm intent, restrict CIDR |
| **S3 bucket policy → public access** | CloudTrail (`PutBucketPolicy`) | Policy grants `*` principal / `GetObject` to all | Enable **Block Public Access**, evaluate data exposure |
| **EC2 with UserData tampering** | CloudTrail (`RunInstances`) | Custom UserData containing `wget`/`curl`/mining binary | New host possibly launched for mining/backdoor |
| **GuardDuty findings** | GuardDuty | `CredentialCompromise`, `CryptoCurrency`, `S3 Bucket Deletion` | Treat as high-signal; pivot to CloudTrail + Flow Logs |

```kql
// Sentinel: AWS console logins with MFA status
CloudTrail
| where eventName == "ConsoleLogin"
| where eventTime > ago(24h)
| project eventTime, userIdentity.arn, sourceIPAddress, userAgent,
          additionalEventData.MFAUsed, errorCode
```

---

## Cloud Attack Patterns

| Pattern | Cloud Example | Indicator | Attacker Goal |
|---------|---------------|-----------|---------------|
| **Credential theft** | Phishing steals Microsoft 365 creds | Risky sign-in, impossible travel, mailbox rule created | Access mail/cloud data; pivot to VPN/on-prem |
| **Consent grant abuse** | Malicious OAuth app requests high Graph scopes | New app consent, Graph API calls by unknown SP | Read/send mail without user password |
| **Service principal backdoor** | Attacker creates SP, adds it to a privileged role | New SP + role assignment in AzureActivity/AuditLogs | Persistent API-level access after creds rotated |
| **Misconfigured storage** | Public S3 bucket / blob container | `PutBucketPolicy` grant-all, Block Public Access off | **Data theft** via `GetObject` / blob download |
| **Crypto mining** | Compromised EC2/VM/container runs miner | **High CPU**, outbound `stratum` connections, billing anomaly | Resource hijacking — they burn your compute |
| **Data exfiltration via sync/export** | `aws s3 sync`, storage account export, DB dump | Large `GetObject`/`ListObjects` volume, new destination bucket | Steal data at scale before detection |

**Crypto mining confirmation chain:** instance/container → process list (EDR/CWPP: `xmrig`, `cpuminer`, `stratum`) → network (mining pool IPs) → CloudTrail `RunInstances` (who launched) → IAM (compromised keys?).

---

## Event → Suspicious → Investigation

Turn a single field into a hypothesis. The same event is benign or malicious depending on context.

| Event | Suspicious | Investigation Step |
|-------|-----------|--------------------|
| `AssumeRole` from `185.x.x.x` | IP is not in your ranges, userAgent is `aws-cli` | Check session issuer, role policy, subsequent API calls |
| `New-InboxRule` forwarding to `gmail.com` | Rule created by admin-adjacent account | Read the rule details, check sign-in context first |
| `PutBucketPolicy` on finance bucket | No change ticket exists | Compare with change management, scan objects |
| MFA prompt burst at 3 AM | Target is CFO-level account | Check tenant risk detections, block device, reset creds |
| High CPU + `stratum+tcp` outbound | No miner should run in prod | Isolate instance, capture memory/process list |

**L1 judgment:** context beats the raw event — always pair the **who**, **where** (IP, location, userAgent), and **when** before deciding.

---

## Cloud Alert Investigation Flow

```
CLOUD ALERT RECEIVED
        │
        ▼
1. VERIFY SIGN-IN CONTEXT
   - Azure: SigninLogs (risk, MFA, CA status, device)
   - AWS:   CloudTrail ConsoleLogin (MFAUsed, IP, userAgent)
        │
        ▼
2. CHECK CONDITIONAL ACCESS / MFA
   - Policy applied? Satisfied? Bypassed?
        │
        ▼
3. CHECK DOWNSTREAM ACTIVITY
   - Mailbox: rules, OWA, forwarding (AuditLogs)
   - Files:   OneDrive/SharePoint/S3 access (AuditLogs, data events)
   - Azure:   AzureActivity resource changes
        │
        ▼
4. CORRELATE
   - Same identity/IP across accounts? Endpoint/network alerts?
   - Recent permission or role changes?
        │
        ▼
5. DETERMINE & ESCALATE
   - TP / FP / Benign / Inconclusive — document evidence
   - Contain if pre-approved (disable key, revoke session, block SG)
   - Escalate confirmed compromise with cloud + identity + host context
```

---

## MITRE ATT&CK Cloud Mapping

| Technique | ID | Cloud Example | Detection |
|-----------|-----|---------------|-----------|
| **Valid Accounts** | T1078 | Logon with stolen IAM user / Entra ID credentials | SigninLogs risk, CloudTrail ConsoleLogin, GuardDuty `CredentialCompromise` |
| **Application Access Token** | T1550.001 | OAuth token / AAD app consent reuse | MicrosoftGraphActivityLogs, AuditLogs consent events |
| **Additional Cloud Credentials** | T1098.001 | Create new IAM user, access key, or SP | CloudTrail `CreateAccessKey`/`CreateUser`, AuditLogs SP creation |
| **Data from Cloud Storage** | T1530 | `aws s3 sync`, blob download from public bucket | CloudTrail data events, S3 access logs |
| **Account Manipulation** | T1578 | Modify IAM policy, attach `AdministratorAccess`, change role assignment | CloudTrail IAM events, AzureActivity `roleAssignment` |
| **Resource Hijacking** | T1496 | Crypto mining on EC2/VM/container | CPU monitoring, Flow Logs to mining pools, GuardDuty `CryptoCurrency` |

---

## Summary — L1 Must Know

- [ ] Cloud is **identity-centric**: most attacks abuse valid credentials, not network breaks
- [ ] Shared Responsibility: provider secures *of* cloud, customer secures *in* cloud
- [ ] Azure sources: SigninLogs (who signed in), AuditLogs (what changed), AzureActivity (resource control plane)
- [ ] AWS source: CloudTrail — check `eventName`, `userIdentity.arn`, `sourceIPAddress`, `userAgent`, `errorCode`
- [ ] Recognize Azure events: impossible travel, MFA failures, new SP, PIM activation, consent grants, mailbox rules
- [ ] Recognize AWS events: ConsoleLogin without MFA, root activity, key creation, cross-account AssumeRole, SG/S3 changes
- [ ] GuardDuty finding types: `CredentialCompromise`, `CryptoCurrency`, `S3 Bucket Deletion` = high-signal
- [ ] Attack patterns: credential theft, consent grant abuse, SP backdoor, public storage, crypto mining, data exfiltration
- [ ] Investigation flow: verify sign-in context → check CA/MFA → downstream activity → correlate → escalate
- [ ] Cloud MITRE: T1078, T1550.001, T1098.001, T1530, T1578, T1496
- [ ] Containment: disable access keys, revoke sessions, block SGs/NSGs, enable Block Public Access
- [ ] Common mistakes: IP-centric thinking, ignoring data-plane logs, missing failed calls (recon), no cloud-on-prem correlation
