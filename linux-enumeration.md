# Linux Enumeration Playbook

> Linux post-compromise and external-service enumeration for authorized testing.
> Goal: identify privilege escalation paths, exposed services, credential leakage, weak configs, and pivot opportunities.

---

## 1. Host and Identity Baseline

```bash
id
whoami
hostname
uname -a
cat /etc/os-release
date
timedatectl
```

Key checks:
- Kernel version for local privilege escalation CVEs
- Whether current user is sudo-capable
- Host role clues from hostname and distro packages

---

## 2. Privilege and Access Controls

```bash
# Sudo capabilities
sudo -l

# Users and groups
cat /etc/passwd
cat /etc/group
getent passwd
lastlog

# Login-capable users
awk -F: '($7!~/nologin|false/){print $1":"$7}' /etc/passwd
```

Red flags:
- `NOPASSWD` sudo entries for dangerous binaries
- Service accounts with interactive shell
- Recently added privileged users

---

## 3. Process and Service Enumeration

```bash
ps aux --sort=-%cpu | head -40
systemctl list-units --type=service --state=running
systemctl list-timers --all
ss -tulpen
lsof -i -P -n | head -80
```

Hunt for:
- Root-owned services executing writable scripts
- Custom daemons in `/opt`, `/tmp`, `/var/tmp`
- Internal-only services binding on `0.0.0.0`

---

## 4. Filesystem and Sensitive Data Discovery

```bash
# World-writable files and dirs
find / -xdev -type d -perm -0002 2>/dev/null
find / -xdev -type f -perm -0002 2>/dev/null

# SUID/SGID binaries
find / -xdev -perm -4000 -type f 2>/dev/null
find / -xdev -perm -2000 -type f 2>/dev/null

# Quick secret hunt
grep -RInE 'password|passwd|token|secret|apikey|PRIVATE KEY' /etc /opt /var/www 2>/dev/null | head -200
```

High-value targets:
- SSH keys in user home and automation directories
- Web app config files (`.env`, `settings.py`, `wp-config.php`)
- Backup files and scripts with embedded credentials

---

## 5. Scheduled Tasks and Persistence Vectors

```bash
crontab -l
ls -la /etc/cron*
cat /etc/crontab
systemctl list-timers --all

# Startup scripts
ls -la /etc/init.d
ls -la /etc/rc*.d
```

Look for:
- Cron scripts writable by low-priv users
- Root timers launching non-root-owned binaries
- Execution from unsafe paths (`/tmp`, user-writable directories)

---

## 6. Network and Lateral Movement Context

```bash
ip a
ip route
arp -an
cat /etc/hosts
cat /etc/resolv.conf

# Internal service probing
for h in 10.10.10.1 10.10.10.2 10.10.10.3; do nc -zv -w1 "$h" 22 445 3306 5432 2>&1; done
```

Findings to capture:
- Reachable internal database/admin services
- Trust boundaries and pivot paths
- Misplaced management interfaces

---

## 7. Automated Linux Enumeration Utilities

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh

# LinEnum
git clone https://github.com/rebootuser/LinEnum.git
cd LinEnum && ./LinEnum.sh
```

Use output to validate:
- Kernel exploit candidates
- Misconfigured sudoers
- Writable service paths and escalation chains

---

## 8. Tool-Call Strategy (For Model-Oriented Workflows)

Recommended high-priority tool calls:
- `linux_privilege_map`: Parse sudo, SUID/SGID, and writable root paths into escalation graph
- `service_trust_audit`: Correlate running services with binary ownership and file permissions
- `secret_leak_scanner`: Structure credential findings by source and confidence
- `internal_reachability_probe`: Build reachable-service matrix for pivot planning

Decision sequence:
1. Confirm privilege context (`id`, `sudo -l`)
2. Build attack surface map (`ss`, `systemctl`, cron)
3. Validate escalation candidates (SUID, writable root paths)
4. Extract credentials/tokens safely
5. Prioritize mitigations (least privilege, hardening, segmentation)

---

## 9. Detection and Mitigation Guidance

Detection ideas:
- Alert on execution of recon-heavy command clusters in short windows (`id`, `sudo -l`, `find / -perm -4000`)
- Monitor reads of high-risk config locations (`/etc/shadow`, app secrets)
- Detect suspicious script execution from cron/timers

Mitigation actions:
- Remove unnecessary SUID/SGID bits and tighten sudoers
- Enforce file permission baselines for service binaries and cron jobs
- Store secrets in a vault, not flat files
- Restrict east-west network access from non-admin hosts
