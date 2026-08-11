# Intermediate Linux Commands Cheat Sheet for SOC Analysts

**Priority: P1 — The commands you'll type every shift, beyond the basics**

---

## Text Processing — The Core Toolkit

### grep (pattern matching)
```bash
grep "Failed password" /var/log/auth.log      # Basic search
grep -E "Accepted|Failed" /var/log/auth.log   # Extended regex (| = or)
grep -i "root" file                           # Case-insensitive
grep -v "localhost" file                      # Exclude lines
grep -c "Accepted" file                       # Count matches
grep -A3 -B2 "accepted" file                  # 3 lines after, 2 before
grep -oE "[0-9]{1,3}(\.[0-9]{1,3}){3}" file   # Print only matched IPs
grep -r "password" /etc/                       # Recursive
grep -l "suspicious" /var/log/*                # Only filenames that match
```

### sed (stream editing)
```bash
sed -n '10,20p' file                    # Print lines 10-20
sed 's/foo/bar/g' file                  # Replace all foo with bar
sed '/^#/d' file                        # Delete comment lines
sed -i 's/old/new/' file                # Edit in place (careful!)
sed -n '/Feb 15/,/Feb 16/p' file        # Range between two patterns
```

### awk (column extraction — the SOC workhorse)
```bash
awk '{print $1}' access.log              # First column (source IP)
awk '{print $1, $9}' access.log          # IP + status code
awk -F: '{print $1}' /etc/passwd         # Custom delimiter (:)
awk '$9 == 404' access.log               # Filter: only 404 lines
awk '{print $NF}' file                   # Last field on each line
awk '{count[$1]++} END {for (ip in count) print count[ip], ip}' access.log
```

### sort / uniq (frequency analysis)
```bash
sort file | uniq -c                      # Count unique lines
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head
#          IP                sort  count  numeric desc  top 10
```

### cut / head / tail / tr
```bash
cut -d: -f1 /etc/passwd                  # Split by colon, take field 1
head -50 file;  tail -50 file            # First / last lines
tail -f /var/log/auth.log                # Follow (real-time)
tr '\0' '\n' < /proc/1234/environ        # Replace null bytes with newlines
wc -l file                               # Count lines
```

---

## find — File & Forensics Search

```bash
find / -name "shell.sh" -mtime -7                # Name + modified last 7 days
find / -type f -mmin -30                         # Modified in last 30 minutes
find / -size +100M 2>/dev/null                   # Large files (staging)
find / -perm -4000 -type f                       # SUID binaries (privesc)
find / -name ".*" -type f                        # Hidden files
find /tmp /var/tmp /dev/shm -type f -mtime -1    # Staging dirs, recent files
find / -newer /etc/passwd -mtime -1              # Newer than a reference file
find / -user www-data -name "*.php" 2>/dev/null  # Web shell hunt
find / -type f -name "*.log" -size 0             # Zero-byte logs (tampering)
```

### find + exec (act on results)
```bash
find /home -name authorized_keys -exec cat {} \;       # Dump all SSH keys
find / -name "*.bak" -mtime -1 -exec ls -la {} \; 2>/dev/null
find /tmp -type f -exec sha256sum {} \; 2>/dev/null     # Hash suspicious files
find / -type f -exec grep -l "password" {} \; 2>/dev/null
```

---

## Process Investigation

```bash
ps aux --sort=-%cpu | head                  # Top CPU consumers
ps aux --sort=-%mem | head                  # Top memory consumers
ps -eo pid,ppid,user,cmd,etime,lstart | grep -i suspicious
pstree -p | grep -i nc                      # See parent/child chain
pgrep -a ssh                                # Find processes by name + cmdline
ls -la /proc/*/exe 2>/dev/null | grep deleted    # Deleted (fileless) binaries
cat /proc/<PID>/cmdline | tr '\0' ' '       # Full command line (spaces)
ls -l /proc/<PID>/cwd                       # Working directory (where it runs from)
```

### /proc deep-dive per process
```bash
/proc/<PID>/cmdline     # Command line (null-separated)
/proc/<PID>/environ     # Environment variables (may leak secrets)
/proc/<PID>/fd/         # Open file descriptors (files, sockets)
/proc/<PID>/exe         # Symlink to the executable (may show (deleted))
/proc/<PID>/status      # Creds: Uid, Gid, CapEff (capabilities)
/proc/<PID>/maps        # Memory mappings (injected libraries)
```

### Signals & control
```bash
kill <PID>          # Graceful (SIGTERM)
kill -9 <PID>       # Force (SIGKILL) — last resort
killall -9 nc       # Kill all named
```

---

## Network Tools

```bash
ss -tunap                           # ALL connections + PID (modern)
netstat -tunap                      # Same, legacy
ss -tlnp                            # Listening TCP + PID
ss -tnp state established           # Only established
tcpdump -i eth0 -n -c 50            # Capture 50 packets, no DNS
tcpdump -i any -n 'port 443'        # Filter by port
tcpdump -nn -w capture.pcap -i eth0 # Write to file (forensics)
tcpdump -r capture.pcap | head      # Read a pcap
nc -zv 10.0.0.5 445                 # Port scan one host (z = no data, v = verbose)
dig +short example.com              # Quick DNS answer
dig example.com A TXT MX            # Multiple record types
nslookup example.com                # Legacy DNS lookup
host example.com                    # Quick lookup
curl -sI https://example.com        # Headers only (S = silent)
curl -sv https://example.com        # Verbose (TLS handshake, cert)
lsof -i :8080                       # What's listening on 8080?
lsof -i -P -n | grep ESTABLISHED    # All connections
```

### DNS / web recon
```bash
curl -X POST -d "user=admin&pass=x" http://target/login  # Replay a request
curl --resolve host:443:10.0.0.5 https://host/          # Force IP for hostname
whois 45.155.205.10                                     # Abuse/registry info
```

---

## Users & Authentication

```bash
who                        # Currently logged in (with source)
w                          # Who + what they're doing
last -20                   # Last logins (reads /var/log/wtmp)
lastb -20                  # Failed logins (reads /var/log/btmp) — needs root
id                         # Current user UID/GID/groups
getent passwd backup       # Look up a user (LDAP/NIS aware)
grep bash /etc/passwd      # Users with login shells
passwd -S alice            # Password status (L = locked?)
chage -l alice             # Password expiry policy
usermod -aG docker alice   # Add user to group (privilege change)
sudo -l                    # What can I run with sudo?
faillock --user alice      # Failed-auth lockout state (RHEL)
```

### Spotting a backdoor account
```bash
awk -F: '$3 >= 1000 {print $1, $3, $6}' /etc/passwd   # Human users + home
grep -v '/usr/sbin/nologin\|/bin/false' /etc/passwd    # Users with real shells
lastlog | grep -v "Never logged in"                    # Accounts actually used
```

---

## Services & Packages

```bash
systemctl status sshd              # Is it running? Recent log lines
systemctl list-unit-files --state=enabled   # What starts at boot
systemctl cat suspicious.service   # Read the unit file (ExecStart?)
dpkg -l | grep -i tor              # Debian: is it installed?
dpkg -S /usr/bin/nc                # What package owns this file?
rpm -qa | grep -i nmap             # RHEL: is it installed?
journalctl -u sshd --since today   # Service logs
```

---

## Disk, Memory & Resources

```bash
df -h                          # Filesystem usage
du -sh /var/tmp                # Size of one dir
du -sh /* 2>/dev/null | sort -hr | head   # Biggest top-level dirs
free -h                        # RAM usage
vmstat 1 5                     # 5 samples, 1s apart (swap, IO, CPU)
lsof | grep deleted | head     # Deleted files still held (disk full cause)
```

---

## Log Analysis One-Liners (Memorize These)

```bash
# Top brute-force source IPs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Top usernames attacked
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr

# Successful login right after failures (spray hit?)
grep -B5 "Accepted password" /var/log/auth.log | grep "Failed password"

# Top web-scanning IPs
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

# Most-hit suspicious paths (404s)
awk '$9==404 {print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

# POST-only requests (credential stuffing / form abuse)
awk '$3=="POST" {print $1, $7}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head

# All sudo activity
grep "sudo:" /var/log/auth.log

# Who ran shells/summary tools via sudo (privesc hunting)
grep "sudo:" /var/log/auth.log | grep -E "(bash|sh|nc|ncat|python|perl|curl|wget)"

# New user accounts created
grep "new user" /var/log/auth.log
```

---

## Bash One-Liners for Everyday Shifts

```bash
# Tail multiple logs with timestamps
tail -f /var/log/auth.log /var/log/nginx/error.log | while read l; do echo "$(date +%T) $l"; done

# Re-run a check every 5 seconds (watch)
watch -n5 'ss -tunap | grep -v LISTEN | wc -l'

# Hash a suspicious file without touching it further
sha256sum /tmp/suspicious.bin | tee hash.txt

# Compare two config files (find what changed)
diff /etc/ssh/sshd_config /tmp/sshd_config.bak

# Search a pcap for cleartext creds
tcpdump -r capture.pcap -A | grep -i "password\|user="

# Firewall rules as root (what's allowed in?)
iptables -L -n -v | head -30
```

---

## Summary — L1 Must Know

- [ ] `grep -E`, `-A/-B`, `-v`, `-o` fluently
- [ ] Extract columns with `awk '{print $1}'` and count with `sort | uniq -c | sort -nr`
- [ ] `find` with `-mtime`, `-size`, `-perm -4000`, `-exec`
- [ ] Read `/proc/<PID>` (cmdline, environ, fd, exe) for process analysis
- [ ] `ss -tunap` / `ss -tlnp` for connections and listeners
- [ ] `tcpdump` basic capture + filter, `nc -zv` quick port checks
- [ ] `dig`, `nslookup`, `curl -sI` for DNS and web checks
- [ ] `last` / `lastb` / `who` for login review
- [ ] `systemctl` status/list-unit-files/cat for service analysis
- [ ] Log-analysis one-liners for brute force and web scans
- [ ] `lsof | grep deleted` and `df -h` for disk/tampering issues
