# Module 27: Cloud Security Basics for L1 SOC Analysts

**Priority: P1 — Important for first months on the job**

> **Scope**: AWS, Azure, GCP fundamentals — focus on identity, logs, and common alerts L1 will see in MXDR

---

## 27.1 Why Cloud Security for L1?

### Reality Check
- **>90% of orgs** use cloud (multi-cloud common)
- **Identity is the new perimeter** — no more network boundary
- **Shared Responsibility Model**: Cloud provider secures *of* cloud; customer secures *in* cloud
- **L1 will see**: CloudTrail/Activity Log alerts, impossible travel, suspicious roles, crypto miners, exposed storage

### Shared Responsibility Model
```
┌─────────────────────────────────────────────────────────────────────────────┐
                         SHARED RESPONSIBILITY MODEL
└─────────────────────────────────────────────────────────────────────────────┘

CLOUD PROVIDER (AWS/Azure/GCP)          CUSTOMER (YOU)
─────────────────────────────────       ─────────────────────
Physical Security                       Identity & Access Mgmt
Network Infrastructure                  Data Encryption (at rest/transit)
Hypervisor / Host OS                    Application Security
Managed Services (RDS, S3, etc.)        OS/Container Config (EC2, AKS)
Global Infrastructure                   Network Config (VPC, SG, NSG)
Compliance Certifications               Client-side Data Protection
                                        Logging & Monitoring Config
```

---

## 27.2 Cloud Identity — The Critical Layer

### AWS IAM
| Concept | Description | L1 Relevance |
|---------|-------------|--------------|
| **User** | Human identity, long-term credentials (access keys, password) | Compromised keys = full access |
| **Group** | Collection of users | Permission inheritance |
| **Role** | Temporary credentials assumed by users/services (EC2, Lambda, cross-account) | **Most common** — STS AssumeRole |
| **Policy** | JSON document: Effect (Allow/Deny), Action, Resource, Condition | Over-permissive policies = risk |
| **Permission Boundary** | Max permissions an entity can have | Guardrail |
| **Access Keys** | `AKIA...` (long-term) — **High risk if leaked** | Check for unused/old keys |
| **Session Tokens** | Temporary (STS), include `SessionToken` | Normal for roles |

### Azure Entra ID (formerly Azure AD)
| Concept | Description | L1 Relevance |
|---------|-------------|--------------|
| **User** | Human identity (cloud-only or synced from AD) | Sign-in logs, risk detection |
| **Service Principal** | App identity (client_id + secret/cert) | App compromise = SP abuse |
| **Managed Identity** | System/User-assigned, no secrets managed by Azure | Preferred over SP |
| **Role Assignment** | Role (Owner, Contributor, Reader, Custom) + Scope (Sub/RG/Resource) | Over-privileged assignments |
| **Conditional Access** | Policies: require MFA, block locations, device compliance | Bypass = risk |
| **PIM (Privileged Identity Management)** | Just-in-time elevation, approval workflows | Standing access = risk |

### GCP IAM
| Concept | Description |
|---------|-------------|
| **Member** | User, Service Account, Group, Domain |
| **Role** | Primitive (Owner/Editor/Viewer), Predefined, Custom |
| **Policy** | Bindings: Role + Members + Conditions |
| **Service Account** | Non-human identity, keys (JSON), can be impersonated |

---

## 27.3 Cloud Audit Logs — L1 Primary Data Source

### AWS CloudTrail
| Aspect | Details |
|--------|---------|
| **What It Logs** | **Every API call** in AWS account (management + data events) |
| **Log Types** | Management events (control plane): CreateBucket, RunInstances, AttachRolePolicy<br>Data events (data plane): S3 GetObject, Lambda Invoke, DynamoDB PutItem |
| **Key Fields** | `eventTime`, `eventSource` (service), `eventName` (API), `userIdentity` (type, principalId, arn, accessKeyId, sessionContext), `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`, `errorCode`, `errorMessage`, `requestID`, `eventID`, `readOnly`, `eventType`, `managementEvent`, `eventCategory` |
| **userIdentity Types** | `IAMUser`, `AssumedRole`, `Root`, `AWSService`, `FederatedUser`, `DirectoryUser` |
| **L1 Investigation Fields** | `eventName` (what happened), `userIdentity.arn` (who), `sourceIPAddress` (where from), `userAgent` (console/cli/sdk), `errorCode` (denied = reconnaissance) |

### Azure Activity Log
| Aspect | Details |
|--------|---------|
| **What It Logs** | Control plane operations on Azure resources (ARM) |
| **Key Fields** | `time`, `caller` (UPN/SPN), `operationName` (e.g., `Microsoft.Compute/virtualMachines/write`), `resourceId`, `resourceGroup`, `subscriptionId`, `category` (Administrative, Security, Policy, etc.), `result` (Succeeded/Failed), `httpRequest.clientIpAddress`, `properties` |
| **Sign-in Logs (Entra ID)** | Separate: `userPrincipalName`, `ipAddress`, `location`, `authenticationMethod`, `authenticationRequirement`, `conditionalAccessStatus`, `riskLevel`, `riskState`, `deviceDetail` |

### GCP Cloud Audit Logs
| Aspect | Details |
|--------|---------|
| **Log Types** | Admin Activity (always on), Data Access (opt-in), System Event, Policy Denied |
| **Key Fields** | `protoPayload` (methodName, resourceName, authenticationInfo, requestMetadata), `resource` (type, labels), `severity`, `logName` |

---

## 27.4 Common Cloud Alerts L1 Will Investigate

### 1. Impossible Travel / Anomalous Location
| Alert | Investigation |
|-------|---------------|
| **Entra ID**: "Sign-in from unfamiliar location" / "Impossible travel" | 1. Check sign-in logs: user, IP, location, time<br>2. Verify MFA status (satisfied? bypassed?)<br>3. Check device: known/registered?<br>4. Check Conditional Access: applied?<br>5. Correlate: VPN? Travel? Compromise? |
| **AWS**: "Console login from new country" | 1. CloudTrail: `ConsoleLogin` event<br>2. Check `sourceIPAddress`, `userAgent`<br>3. Check MFA: `additionalEventData.MFAUsed` |

### 2. Suspicious Role Assumption / Permission Escalation
| Alert | Investigation |
|-------|---------------|
| **AWS**: `AssumeRole` from unusual IP / user / time | 1. Who assumed? `userIdentity.sessionContext.sessionIssuer.arn`<br>2. What role? `requestParameters.roleArn`<br>3. Permissions of role? Check policy<br>4. Source IP reputation?<br>5. Session duration? Subsequent API calls? |
| **Azure**: "Role assignment created" (Owner/Contributor) | 1. Who assigned? `caller`<br>2. To whom? `properties.principalId`<br>3. What role? `properties.roleDefinitionId`<br>4. Scope? `resourceId` (subscription/RG/resource) |
| **GCP**: "Service account key created" / "IAM policy changed" | 1. Who created? `protoPayload.authenticationInfo.principalEmail`<br>2. For which SA? `protoPayload.resourceName`<br>3. Key type? (user-managed = risk) |

### 3. Resource Exposure / Misconfiguration
| Alert | Investigation |
|-------|---------------|
| **S3 Bucket Public** / **Storage Account Public Access** | 1. Which bucket/account?<br>2. How exposed? (ACL, bucket policy, block public access off)<br>3. Data sensitivity? (scan if possible)<br>4. Who changed? CloudTrail/Activity Log<br>5. Duration exposed? Access logs? |
| **Security Group / NSG Open to 0.0.0.0/0** (SSH, RDP, DB ports) | 1. Which SG/NSG? Which port?<br>2. Attached resources?<br>3. Who created/modified?<br>4. Legitimate? (bastion, LB) |
| **Unencrypted Storage / DB** | 1. Resource ID<br>2. Data classification<br>3. Compliance requirement |

### 4. Crypto Mining / Resource Hijacking
| Alert | Investigation |
|-------|---------------|
| **High CPU on EC2/VM/Container** + **Outbound to mining pools** | 1. Identify instance/container<br>2. Process list (EDR/CWPP): `xmrig`, `cpuminer`, `stratum`<br>3. Network: connections to known mining pool IPs/domains<br>4. CloudTrail: `RunInstances` with suspicious AMI/user-data<br>5. IAM: Who launched? Compromised keys? |
| **Lambda/Function Abuse** (high invocations, long duration) | 1. Which function?<br>2. Code review (malicious? crypto?)<br>3. Trigger source?<br>4. IAM role permissions? |

### 5. Data Exfiltration
| Alert | Investigation |
|-------|---------------|
| **Large S3 GetObject / Blob Download** / **DynamoDB Scan** | 1. Who? `userIdentity.arn` / `caller`<br>2. What data? Resource + object count/size<br>3. Destination? Source IP (corporate? personal? tor?)<br>4. User agent? (aws-cli, script, console)<br>5. Business justification? |

### 6. Persistence / Backdoor
| Alert | Investigation |
|-------|---------------|
| **New IAM User/Access Key/Role** / **New Service Principal** | 1. Who created?<br>2. Permissions granted?<br>3. Legitimate onboarding?<br>4. Key usage since creation? |
| **Lambda/Function URL / API Gateway Created** | 1. Who?<br>2. Public? Authenticated?<br>3. Code inspection |
| **Container Image Pushed to ECR/ACR/GAR** | 1. Image name, tags<br>2. Base image? Vulnerabilities?<br>3. Who pushed? |

---

## 27.5 Cloud Investigation Workflow for L1

```
CLOUD ALERT RECEIVED
        │
        ▼
┌─────────────────────────────────────────┐
│  1. IDENTIFY:                           │
│     - Cloud provider (AWS/Azure/GCP)    │
│     - Account / Subscription / Project  │
│     - Resource type & ID                │
│     - Identity involved (user/role/SA)  │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│  2. COLLECT CONTEXT (CloudTrail/Logs):  │
│     - What API calls? (eventName)       │
│     - When? (time window)               │
│     - From where? (sourceIP, userAgent) │
│     - By whom? (userIdentity.arn)       │
│     - Success/Failed? (errorCode)       │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│  3. ENRICH:                             │
│     - IP reputation (TI)                │
│     - User: normal locations, devices   │
│     - Resource: criticality, data class │
│     - Identity: permissions, last used  │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│  4. CORRELATE:                          │
│     - Other alerts same identity?       │
│     - Same IP across accounts?          │
│     - Endpoint/Network correlation?     │
│     - Recent permission changes?        │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│  5. DETERMINE & DOCUMENT:               │
│     - TP / FP / Benign / Inconclusive   │
│     - Evidence for conclusion           │
│     - Containment needed? (disable key, │
│       revoke session, modify SG)        │
│     - Escalation?                       │
└─────────────────────────────────────────┘
```

---

## 27.6 Cloud Containment Actions (L1 Authority)

| Action | When Pre-Approved | Requires Approval |
|--------|-------------------|-------------------|
| **Disable/Delete Access Key** (AWS) | Compromised key confirmed | Root key, break-glass key |
| **Revoke Session** (Entra ID / AWS STS) | Compromised user/role confirmed | Admin accounts |
| **Disable User/Service Principal** | Confirmed compromise | Break-glass, critical service accounts |
| **Modify Security Group / NSG** (block port/IP) | Known malicious IP, open SSH/RDP to world | Business-critical ports |
| **Enable S3 Block Public Access** / **Storage Account Public Access Off** | Public exposure confirmed | If business requires public (rare) |
| **Detach IAM Policy / Role Assignment** | Over-privileged role on compromised identity | Production service roles |
| **Quarantine VM/Container** (CWPP/EDR) | Active malware/crypto | Critical production workloads |

---

## 27.7 Key Cloud Security Concepts for Interviews

### Concepts to Explain Simply
| Concept | Simple Explanation |
|---------|-------------------|
| **Shared Responsibility** | "Cloud provider secures the building; you secure what's inside your apartment" |
| **IAM Role vs User** | "User = human with permanent keys. Role = temporary hat anyone can wear (services, users)" |
| **AssumeRole / STS** | "Trading your badge for a temporary visitor pass with specific permissions" |
| **CloudTrail / Activity Log** | "Security camera recording every API call — who, what, when, from where" |
| **Least Privilege** | "Give only the keys needed for the job, not the master key" |
| **Permission Boundary** | "Ceiling — even if you get more keys, you can't go above this floor" |
| **Conditional Access** | "Rules: 'Only enter if you have badge + MFA + approved device'" |
| **Managed Identity** | "App gets automatic badge from Azure — no password to steal" |
| **Data Plane vs Control Plane** | "Control = managing resources (create bucket). Data = using resources (upload file)" |

---

## 27.8 Cloud-Specific MITRE ATT&CK (Cloud Matrix)

| Tactic | Technique | Cloud Example |
|--------|-----------|---------------|
| **Initial Access** | T1078.004 Cloud Accounts | Compromised IAM user/access key |
| | T1190 Exploit Public-Facing App | Vulnerable web app on EC2/App Service |
| | T1195 Supply Chain Compromise | Malicious container image / Terraform module |
| **Persistence** | T1098.001 Additional Cloud Roles | Create new IAM role with admin access |
| | T1505.003 Web Shell | Deploy malicious Lambda/Function |
| | T1556.002 Password Filter | Not applicable (use: T1556.006 MFA fatigue) |
| **Privilege Escalation** | T1098 Account Manipulation | Attach AdministratorAccess policy to user |
| | T1548.002 Bypass User Account Control | Not applicable (use: T1548.003 Escalate via Role) |
| **Credential Access** | T1528 Steal Application Access Token | Steal Azure AD token / AWS session token |
| | T1555.003 Credentials in Registry | Not applicable (use: T1555.005 Cloud Instance Metadata API) |
| **Discovery** | T1580 Cloud Infrastructure Discovery | `aws iam list-users`, `az resource list` |
| | T1526 Cloud Service Discovery | Enumerate S3 buckets, storage accounts |
| **Lateral Movement** | T1021.007 Cloud Instance Metadata API | IMDSv1 to get IAM role credentials |
| | T1550.001 Pass the Hash | Not applicable (use: Pass the Token / Role) |
| **Collection** | T1530 Data from Cloud Storage | `aws s3 sync`, `az storage blob download` |
| **Exfiltration** | T1537 Transfer Data to Cloud Account | Copy to attacker-controlled bucket/account |
| **Impact** | T1496 Resource Hijacking | Crypto mining on EC2/VM/Container |

---

## 27.9 L1 Cloud Investigation Cheat Sheet

### AWS CloudTrail Query Patterns (KQL/SQL-style)
```kql
// All Console Logins
CloudTrail
| where eventName == "ConsoleLogin"
| where eventTime > ago(24h)
| project eventTime, userIdentity.arn, sourceIPAddress, userAgent, 
          additionalEventData.MFAUsed, errorCode

// AssumeRole Activity
CloudTrail
| where eventName == "AssumeRole"
| where eventTime > ago(24h)
| project eventTime, userIdentity.arn, requestParameters.roleArn, 
          sourceIPAddress, userAgent, responseElements.assumedRoleUser.arn

// S3 Data Events (Large Downloads)
CloudTrail
| where eventSource == "s3.amazonaws.com"
| where eventName in ("GetObject", "ListObjects", "GetObjectTagging")
| where eventTime > ago(24h)
| extend bytes = tolong(responseElements.bytesTransferred)
| where bytes > 100000000  // >100MB
| project eventTime, userIdentity.arn, requestParameters.bucketName, 
          requestParameters.key, sourceIPAddress, bytes

// IAM Changes
CloudTrail
| where eventSource == "iam.amazonaws.com"
| where eventName has "Create" or eventName has "Attach" or eventName has "Put"
| where eventTime > ago(7d)
| project eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress
```

### Azure Activity Log Patterns
```kql
// Role Assignments (Privilege Escalation)
AzureActivity
| where OperationName has "roleAssignment"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Caller, OperationName, 
          Properties.roleDefinitionId, Properties.principalId, 
          Properties.scope, Result, HttpRequest.clientIpAddress

// Suspicious Sign-ins (Entra ID)
SigninLogs
| where TimeGenerated > ago(24h)
| where RiskLevel != "none" or ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, 
          AppDisplayName, AuthenticationMethod, ConditionalAccessStatus, 
          RiskLevel, RiskState, DeviceDetail
```

---

## 27.10 Common L1 Mistakes with Cloud

| Mistake | Correction |
|---------|------------|
| Treating cloud like on-prem (IP-based) | Cloud is identity-based; IP changes constantly |
| Ignoring Data Plane logs (S3 data events, Lambda) | Control plane only shows *management*; data plane shows *access* |
| Not checking `userAgent` in CloudTrail | `aws-cli/2.x`, `console.amazonaws.com`, `terraform`, custom script — reveals actor |
| Assuming "Root" account alerts are always critical | Root usage for billing, support — context matters |
| Missing cross-account role assumptions | Attackers pivot across accounts via roles |
| Not correlating cloud with on-prem/endpoint | Compromised laptop → stolen AWS keys → cloud activity |
| Ignoring "Failed" API calls (`AccessDenied`) | Reconnaissance — attacker mapping permissions |

---

## 27.11 Summary: What L1 Must Know

- [ ] Shared Responsibility Model: provider vs customer
- [ ] Identity concepts: IAM User/Role (AWS), User/SP/Managed Identity (Azure), Service Account (GCP)
- [ ] Audit logs: CloudTrail (AWS), Activity Log + Sign-in Logs (Azure), Cloud Audit Logs (GCP)
- [ ] Key log fields: `eventName`/`operationName`, `userIdentity`/`caller`, `sourceIPAddress`, `userAgent`, `errorCode`
- [ ] Common alerts: impossible travel, suspicious role assumption, public exposure, crypto mining, data exfil, persistence
- [ ] Investigation workflow: Identify → Collect Context → Enrich → Correlate → Determine
- [ ] Containment actions: disable keys, revoke sessions, modify SGs/NSGs, block public access
- [ ] Cloud MITRE ATT&CK techniques (Initial Access, Persistence, Credential Access, Discovery, Exfiltration)
- [ ] Cross-correlation: cloud + endpoint + network + identity
- [ ] Common mistakes: IP-centric thinking, ignoring data plane, missing failed calls, no cross-correlation